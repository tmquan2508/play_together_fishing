import ctypes
from ctypes import wintypes
import psutil
import time
import signal
import sys
import re

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

MEM_COMMIT = 0x1000
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100

kernel32 = ctypes.windll.kernel32

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

def is_readable(protect):
    readable_flags = (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
    return (protect & readable_flags) != 0 and (protect & PAGE_GUARD == 0)

def find_process_pid_by_name(name):
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == name:
            return proc.info['pid']
    return None

def open_process_readonly(pid):
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        raise OSError(f"OpenProcess failed for PID {pid}. Error: {kernel32.GetLastError()}")
    return handle

def close_handle(handle):
    kernel32.CloseHandle(handle)

def read_process_memory(handle, address, size_or_buffer):
    if isinstance(size_or_buffer, int):
        size = size_or_buffer
        buffer = (ctypes.c_byte * size)()
        bytes_read = ctypes.c_size_t(0)
        
        success = kernel32.ReadProcessMemory(
            handle, ctypes.c_void_p(address), buffer, size, ctypes.byref(bytes_read)
        )
        
        if not success or bytes_read.value != size:
            return None
        return bytearray(buffer)
    else:
        buffer = size_or_buffer
        bytes_read = ctypes.c_size_t(0)
        buffer_size = len(buffer)
        c_buffer = (ctypes.c_char * buffer_size).from_buffer(buffer)
        
        success = kernel32.ReadProcessMemory(
            handle, ctypes.c_void_p(address), c_buffer, buffer_size, ctypes.byref(bytes_read)
        )
        
        if not success:
            return 0
        return bytes_read.value

def read_i32(handle, address):
    data = read_process_memory(handle, address, 4)
    if data is None:
        return None
    return int.from_bytes(data, byteorder='little', signed=True)

def create_aob_pattern(signature, wildcard):
    pattern = b''
    for byte in signature:
        if byte == wildcard:
            pattern += b'.'
        else:
            pattern += re.escape(bytes([byte]))
    return pattern

def scan_aob(handle, signature, wildcard=0x2E, chunk_size=4 * 1024 * 1024):
    results = []
    sig_len = len(signature)
    if sig_len == 0:
        return results
    overlap_len = sig_len - 1

    aob_pattern = re.compile(create_aob_pattern(signature, wildcard), re.DOTALL)

    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()

    scan_buffer = bytearray(chunk_size + overlap_len)
    overlap_view = memoryview(scan_buffer)[:overlap_len]
    read_view = memoryview(scan_buffer)[overlap_len:]
    last_chunk_tail = bytearray(overlap_len)

    while True:
        result = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not result:
            break

        region_base = int(mbi.BaseAddress or 0)
        region_size = int(mbi.RegionSize or 0)
        
        next_addr = region_base + region_size
        if next_addr <= addr:
            addr += 1
        else:
            addr = next_addr

        if mbi.State == MEM_COMMIT and is_readable(mbi.Protect):
            overlap_view[:] = last_chunk_tail
            
            region_offset = 0
            while region_offset < region_size:
                bytes_to_read = min(region_size - region_offset, chunk_size)
                current_read_view = read_view[:bytes_to_read]
                
                bytes_read = read_process_memory(handle, region_base + region_offset, current_read_view)
                
                if bytes_read == 0:
                    region_offset += bytes_to_read
                    continue
                
                effective_scan_view = memoryview(scan_buffer)[:overlap_len + bytes_read]

                for match in aob_pattern.finditer(effective_scan_view):
                    match_start_index = match.start()
                    absolute_addr = region_base + region_offset + match_start_index - overlap_len
                    if not results or results[-1] != absolute_addr:
                        results.append(absolute_addr)
                
                if bytes_read >= overlap_len:
                    if overlap_len > 0:
                        last_chunk_tail[:] = effective_scan_view[-overlap_len:]
                else:
                    start_copy = overlap_len - bytes_read
                    last_chunk_tail[start_copy:] = effective_scan_view[:bytes_read]

                overlap_view[:] = last_chunk_tail
                region_offset += bytes_read
            
            last_chunk_tail = bytearray(overlap_len)

    return results

TARGET_PROCESS_NAME = "vmmem"
AOB_SIGNATURE = b"\x20\x41\xCD\xCC\x4C\x3E\x2E\x2E\x2E\x2E\x2E\x2E\x00\x00"
WILDCARD = 0x2E
BALO_OFFSET = 214
CONFIRM_VALUE = 300
FISH_STATE_OFFSET = 308

def main():
    print(f"Searching for process '{TARGET_PROCESS_NAME}'...")
    pid = find_process_pid_by_name(TARGET_PROCESS_NAME)
    if not pid:
        print("❌ Process not found.")
        return

    print(f"PID: {pid}. Opening read-only handle...")
    try:
        handle = open_process_readonly(pid)
    except OSError as e:
        print(f"❌ Error opening handle: {e}")
        return

    print("✅ Connected. Please OPEN YOUR INVENTORY/BAG.")
    print("Starting scan in 5 seconds...")
    time.sleep(5)

    print("🔍 Scanning AOB...")
    start = time.time()
    base_addrs = scan_aob(handle, AOB_SIGNATURE, WILDCARD)
    elapsed = time.time() - start
    print(f"==> Scan time: {elapsed:.4f} seconds. Found {len(base_addrs)} results.")

    if not base_addrs:
        print("❌ AOB not found.")
        close_handle(handle)
        return

    print(f"Filtering with value {CONFIRM_VALUE} at offset {BALO_OFFSET}...")

    valid_balo = []
    for base in base_addrs:
        balo_addr = base + BALO_OFFSET
        val = read_i32(handle, balo_addr)
        if val == CONFIRM_VALUE:
            valid_balo.append(balo_addr)

    if len(valid_balo) != 1:
        print(f"❌ Filter failed: {len(valid_balo)} valid addresses found (exactly 1 required).")
        close_handle(handle)
        return

    balo_addr = valid_balo[0]
    fish_addr = balo_addr + FISH_STATE_OFFSET
    print(f"\n✅ Success! Bag: 0x{balo_addr:08X} | Fish state: 0x{fish_addr:08X}")

    print("\n--- Monitoring state (Ctrl+C to exit) ---")

    running = True
    def signal_handler(sig, frame):
        nonlocal running
        running = False
        print("\nExit command received...")

    signal.signal(signal.SIGINT, signal_handler)

    while running:
        state = read_i32(handle, fish_addr)
        if state is not None:
            print(f"\rState: {state} (0x{fish_addr:08X})        ", end='', flush=True)
        else:
            print("\n❌ Memory read error. The process may have been closed.")
            break
        time.sleep(0.5)

    close_handle(handle)
    print("\n✅ Handle closed. Exiting.")

if __name__ == "__main__":
    main()