use std::io::{stdout, Write};
use std::mem::size_of;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use mach::kern_return::KERN_SUCCESS;
use mach::message::mach_msg_type_number_t;
use mach::port::mach_port_t;
use mach::traps::task_for_pid;
use mach::vm::{mach_vm_deallocate, mach_vm_remap};
use mach::vm_inherit::VM_INHERIT_NONE;
use mach::vm_prot::VM_PROT_READ;
use mach::vm_region::VM_REGION_BASIC_INFO_64;
use mach::vm_statistics::VM_FLAGS_ANYWHERE;
use mach::vm_types::{mach_vm_address_t, mach_vm_size_t};
use memchr::memchr;
use rayon::prelude::*;
use sysinfo::System;

const TARGET_PROCESS_NAME: &str = "PLAY TOGETHER";
const AOB_SIGNATURE: &[u8] = b"\x20\x41\xCD\xCC\x4C\x3E......\x00\x00";
const AOB_WILDCARD: u8 = b'.';

const BALO_OFFSET: u64 = 214;
const CONFIRM_VALUE: i32 = 300;
const FISH_STATE_OFFSET: u64 = 308;

fn matches_with_wildcard(window: &[u8], signature: &[u8], wildcard: u8) -> bool {
    window
        .iter()
        .zip(signature.iter())
        .all(|(a, b)| *b == wildcard || a == b)
}

fn scan_aob(
    task: mach_port_t,
    signature: &[u8],
    wildcard: u8,
) -> Result<Vec<mach_vm_address_t>> {
    let sig_len = signature.len();
    if sig_len == 0 {
        return Ok(Vec::new());
    }

    let mut address: mach_vm_address_t = 0;
    let mut regions: Vec<(mach_vm_address_t, mach_vm_size_t)> = Vec::new();
    loop {
        let mut size: mach_vm_size_t = 0;
        let mut info: mach::vm_region::vm_region_basic_info_64 = unsafe { std::mem::zeroed() };
        let mut object_name = 0;
        let mut info_size = (size_of::<mach::vm_region::vm_region_basic_info_64>()
            / size_of::<i32>()) as mach_msg_type_number_t;
        let kern_ret = unsafe {
            mach::vm::mach_vm_region(
                task,
                &mut address,
                &mut size,
                VM_REGION_BASIC_INFO_64,
                &mut info as *mut _ as mach::vm_region::vm_region_info_t,
                &mut info_size,
                &mut object_name,
            )
        };
        if kern_ret != KERN_SUCCESS {
            break;
        }
        if (info.protection & VM_PROT_READ) != 0 {
            if let Some(last_region) = regions.last_mut() {
                if last_region.0 + last_region.1 == address {
                    last_region.1 += size;
                } else {
                    regions.push((address, size));
                }
            } else {
                regions.push((address, size));
            }
        }
        address += size;
    }

    let all_results: Vec<Vec<mach_vm_address_t>> = regions
        .par_iter()
        .map(|&(region_base, region_size)| {
            let mut matches_in_region = Vec::new();
            let mut remapped_address: mach_vm_address_t = 0;
            let mut cur_protection = 0;
            let mut max_protection = 0;

            let kern_ret = unsafe {
                mach_vm_remap(
                    mach::traps::mach_task_self(),
                    &mut remapped_address,
                    region_size,
                    0,
                    VM_FLAGS_ANYWHERE,
                    task,
                    region_base,
                    0,
                    &mut cur_protection,
                    &mut max_protection,
                    VM_INHERIT_NONE,
                )
            };

            if kern_ret == KERN_SUCCESS {
                let data = unsafe {
                    std::slice::from_raw_parts(remapped_address as *const u8, region_size as usize)
                };

                let mut search_offset = 0;
                while let Some(index) = memchr(signature[0], &data[search_offset..]) {
                    let match_pos = search_offset + index;
                    if match_pos + sig_len > data.len() {
                        break;
                    }
                    if matches_with_wildcard(
                        &data[match_pos..match_pos + sig_len],
                        signature,
                        wildcard,
                    ) {
                        matches_in_region.push(region_base + match_pos as u64);
                    }
                    search_offset = match_pos + 1;
                }

                unsafe {
                    mach_vm_deallocate(mach::traps::mach_task_self(), remapped_address, region_size);
                }
            }
            matches_in_region
        })
        .collect();

    let mut final_results: Vec<mach_vm_address_t> = all_results.into_iter().flatten().collect();
    final_results.sort_unstable();
    final_results.dedup();

    Ok(final_results)
}

unsafe fn read_memory<T: Copy>(task: mach_port_t, address: mach_vm_address_t) -> Result<T> {
    let mut data_ptr: usize = 0;
    let mut data_count: mach_msg_type_number_t = 0;
    let size_to_read = size_of::<T>() as mach_vm_size_t;

    let kern_ret = mach::vm::mach_vm_read(
        task,
        address,
        size_to_read,
        &mut data_ptr,
        &mut data_count,
    );
    if kern_ret != KERN_SUCCESS {
        bail!(
            "Failed to mach_vm_read at address {:#X} (code: {})",
            address,
            kern_ret
        );
    }
    let value = ptr::read_unaligned(data_ptr as *const T);
    mach_vm_deallocate(
        mach::traps::mach_task_self(),
        data_ptr as mach_vm_address_t,
        data_count as mach_vm_size_t,
    );
    Ok(value)
}

fn run_logic() -> Result<()> {
    if std::env::consts::OS != "macos" {
        bail!("Error: This tool is designed to run on macOS only.");
    }
    if unsafe { libc::getuid() } != 0 {
        bail!("Error: Please run the tool with root privileges. Use: sudo ./your_executable_name");
    }

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
        println!("\nReceived exit command, cleaning up...");
    })?;

    println!("Searching for process '{}'...", TARGET_PROCESS_NAME);
    let mut sys = System::new_all();
    sys.refresh_processes();

    let process = sys
        .processes_by_name(TARGET_PROCESS_NAME)
        .next()
        .context(format!(
            "Could not find process: '{}'. Make sure the game is running.",
            TARGET_PROCESS_NAME
        ))?;

    println!("Found PID: {}", process.pid());

    let mut task: mach_port_t = 0;
    let kern_ret =
        unsafe { task_for_pid(mach::traps::mach_task_self(), process.pid().as_u32() as i32, &mut task) };
    if kern_ret != KERN_SUCCESS {
        bail!("Error with 'task_for_pid' (code: {}).\nPossible reasons:\n1. You did not run with 'sudo'.\n2. System Integrity Protection (SIP) may not be disabled.", kern_ret);
    }
    println!("Successfully attached to the process memory.");

    println!("\n*** IMPORTANT ***");
    println!(
        "Please OPEN YOUR INVENTORY/BAG in the game so the tool can find the correct address (confirmation value = {}).",
        CONFIRM_VALUE
    );
    println!("The tool will start scanning in 5 seconds...");
    thread::sleep(Duration::from_secs(5));

    println!("\n--- Starting full memory scan ---");
    let start_time = Instant::now();
    println!("Step 1: Scanning for signature (AOB)...");

    let base_addresses = scan_aob(task, AOB_SIGNATURE, AOB_WILDCARD)?;

    let duration = start_time.elapsed();
    println!(
        "==> AOB scan time: {:.4} seconds.",
        duration.as_secs_f64()
    );

    if base_addresses.is_empty() {
        bail!("Scan failed: Could not find the Array of Bytes (AOB) signature.");
    }

    println!("Found {} addresses. Starting to filter...", base_addresses.len());
    let mut candidate_addresses = Vec::new();
    for &addr in &base_addresses {
        let potential_balo_addr = addr + BALO_OFFSET;
        if let Ok(value) = unsafe { read_memory::<i32>(task, potential_balo_addr) } {
            if value == CONFIRM_VALUE {
                candidate_addresses.push(potential_balo_addr);
            }
        }
    }

    if candidate_addresses.len() != 1 {
        bail!(
            "Filter failed: Found {} valid addresses instead of 1. Try restarting the game and the tool.",
            candidate_addresses.len()
        );
    }

    let dynamic_balo_address = candidate_addresses[0];
    println!(
        "\nSUCCESS! Found unique Bag address: {:#X}",
        dynamic_balo_address
    );

    let fish_state_addr = dynamic_balo_address + FISH_STATE_OFFSET;
    println!("\n--- Starting main tool loop ---");
    println!("You can now close your bag and start fishing.");
    println!("Tool is now monitoring the fishing state (Press Ctrl+C to exit)...");

    while running.load(Ordering::SeqCst) {
        match unsafe { read_memory::<i32>(task, fish_state_addr) } {
            Ok(state) => {
                print!(
                    "Reading fishing state at {:#X} -> Value: {}          \r",
                    fish_state_addr, state
                );
                stdout().flush()?;
            }
            Err(_) => {
                println!("\nError: Could not read memory. The game might have been closed.");
                break;
            }
        }
        thread::sleep(Duration::from_millis(500));
    }
    Ok(())
}

fn main() {
    if let Err(e) = run_logic() {
        eprintln!("\nFatal error: {}", e);
    }
    println!("\nTool has finished.");
}