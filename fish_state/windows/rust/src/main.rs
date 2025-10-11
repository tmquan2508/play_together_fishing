use std::error::Error;
use std::io::{self, Write};
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use memchr::memchr;
use sysinfo::System;
use winapi::shared::minwindef::{LPCVOID, LPVOID};
use winapi::um::handleapi::CloseHandle;
use winapi::um::memoryapi::{ReadProcessMemory, VirtualQueryEx};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::winnt::{
    HANDLE, MEMORY_BASIC_INFORMATION, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, MEM_COMMIT,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_READONLY,
    PAGE_READWRITE, PAGE_WRITECOPY,
};

const TARGET_PROCESS_NAME: &str = "PlayTogether.exe";
const AOB_SIGNATURE: &[u8] = b"\x20\x41\xCD\xCC\x4C\x3E\x2E\x2E\x2E\x2E\x2E\x2E\x00\x00";
const WILDCARD: u8 = 0x2E;

const BALO_OFFSET: usize = 214;
const CONFIRM_VALUE: i32 = 300;
const FISH_STATE_OFFSET: usize = 308;

const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4MB

fn is_readable(protect: u32) -> bool {
    (protect
        & (PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_WRITECOPY
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY))
        != 0
        && (protect & PAGE_GUARD == 0)
}

fn read_bytes(handle: HANDLE, address: usize, buffer: &mut [u8]) -> bool {
    let mut bytes_read: usize = 0;
    let ok = unsafe {
        ReadProcessMemory(
            handle,
            address as LPCVOID,
            buffer.as_mut_ptr() as LPVOID,
            buffer.len(),
            &mut bytes_read,
        )
    };
    ok != 0 && bytes_read == buffer.len()
}


fn read_i32(handle: HANDLE, address: usize) -> Option<i32> {
    let mut buffer = [0u8; 4];
    if read_bytes(handle, address, &mut buffer) {
        Some(i32::from_le_bytes(buffer))
    } else {
        None
    }
}


fn matches_with_wildcard(window: &[u8], signature: &[u8], wildcard: u8) -> bool {
    for (a, b) in window.iter().zip(signature.iter()) {
        if *b != wildcard && a != b {
            return false;
        }
    }
    true
}

fn scan_aob(handle: HANDLE, signature: &[u8], wildcard: u8) -> Vec<usize> {
    let mut results = Vec::new();
    let sig_len = signature.len();
    let overlap_len = sig_len - 1;

    let mut chunk_buffer = vec![0u8; CHUNK_SIZE];
    let mut scan_buffer = vec![0u8; CHUNK_SIZE + overlap_len];

    let mut addr = 0usize;
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };

    while unsafe {
        VirtualQueryEx(
            handle,
            addr as LPCVOID,
            &mut mbi,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    } != 0
    {
        let region_base = mbi.BaseAddress as usize;
        let region_size = mbi.RegionSize;

        if mbi.State == MEM_COMMIT && is_readable(mbi.Protect) {
            let mut region_offset = 0;
            while region_offset < region_size {
                let bytes_to_read = (region_size - region_offset).min(CHUNK_SIZE);
                let current_chunk = &mut chunk_buffer[..bytes_to_read];

                if read_bytes(handle, region_base + region_offset, current_chunk) {
                    scan_buffer[overlap_len..overlap_len + bytes_to_read].copy_from_slice(current_chunk);

                    let effective_scan_buffer = &scan_buffer[..overlap_len + bytes_to_read];

                    let mut search_offset = 0;
                    while let Some(index) = memchr(signature[0], &effective_scan_buffer[search_offset..]) {
                        let match_pos = search_offset + index;
                        if match_pos + sig_len > effective_scan_buffer.len() {
                            break;
                        }

                        if matches_with_wildcard(&effective_scan_buffer[match_pos..match_pos + sig_len], signature, wildcard) {
                            let absolute_addr = region_base + region_offset + match_pos - overlap_len;
                            if results.last() != Some(&absolute_addr) {
                                results.push(absolute_addr);
                            }
                        }
                        search_offset = match_pos + 1;
                    }

                    if bytes_to_read >= overlap_len {
                         scan_buffer[..overlap_len].copy_from_slice(&current_chunk[bytes_to_read - overlap_len..]);
                    }
                }
                region_offset += bytes_to_read;
            }
        }
        addr = region_base + region_size;
    }
    results
}


fn main() -> Result<(), Box<dyn Error>> {
    println!("Searching for process '{}'...", TARGET_PROCESS_NAME);
    let mut sys = System::new_all();
    sys.refresh_processes();

    let process_info = sys
        .processes_by_name(TARGET_PROCESS_NAME)
        .next()
        .ok_or(format!("Process not found: '{}'. Make sure the game is running.", TARGET_PROCESS_NAME))?;

    let pid = process_info.pid().as_u32();
    let handle: HANDLE = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
    if handle.is_null() {
        return Err("Could not open process handle. Try running as administrator.".into());
    }
    println!("Pymem attached to PID: {}", pid);

    println!("\n*** IMPORTANT ***");
    println!("Please OPEN YOUR INVENTORY/BAG in the game so the tool can find the correct address (confirm value = {}).", CONFIRM_VALUE);
    println!("The tool will start scanning in 5 seconds...");
    thread::sleep(Duration::from_secs(5));

    println!("\n--- Starting full memory scan ---");
    let start_time = Instant::now();
    println!("Step 1: Scanning for AOB signature across all memory regions...");
    let base_addresses = scan_aob(handle, AOB_SIGNATURE, WILDCARD);
    println!("==> AOB scan finished in: {:.4} seconds.", start_time.elapsed().as_secs_f64());

    if base_addresses.is_empty() {
        return Err("Scan failed: AOB signature not found.".into());
    }

    println!("Found {} addresses. Starting filter...", base_addresses.len());
    println!("Step 2: Applying offset ({}) and filtering with value ({}) while inventory is open...", BALO_OFFSET, CONFIRM_VALUE);


    let mut valid_balo_addresses = Vec::new();
    for &base in &base_addresses {
        let potential_balo_addr = base + BALO_OFFSET;
        if let Some(val) = read_i32(handle, potential_balo_addr) {
            if val == CONFIRM_VALUE {
                valid_balo_addresses.push(potential_balo_addr);
            }
        }
    }

    if valid_balo_addresses.len() != 1 {
        return Err(format!(
            "Filter failed: Found {} valid addresses instead of 1. Try restarting the game and the tool.",
            valid_balo_addresses.len()
        )
        .into());
    }

    let dynamic_balo_address = valid_balo_addresses[0];
    println!(
        "\nSUCCESS! Found unique inventory address: {:#X}",
        dynamic_balo_address
    );

    println!("\n--- Starting main tool loop ---");
    let fish_state_addr = dynamic_balo_address + FISH_STATE_OFFSET;

    println!("You can now close your inventory and start fishing.");
    println!("Tool is now monitoring the game state...");


    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
        println!("\n\nReceived exit command from user...");
    })
    .expect("Error setting Ctrl-C handler");

    while running.load(Ordering::SeqCst) {
        match read_i32(handle, fish_state_addr) {
            Some(state) => {
                print!(
                    "Reading fish state at {:#X} -> Value: {}          \r",
                    fish_state_addr, state
                );
                io::stdout().flush().unwrap();
            },
            None => {
                println!("\nError: Could not read memory. The game may have closed. Exiting...");
                break;
            }
        }
        thread::sleep(Duration::from_millis(500));
    }

    unsafe { CloseHandle(handle) };
    println!("\nTool has finished. Press Enter to exit.");
    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer)?;
    Ok(())
}