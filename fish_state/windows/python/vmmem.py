import ctypes
from ctypes import wintypes
import psutil
import time
import signal
import sys

# This python version may take a longer than other language.

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
    readable_flags = (
        PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    )
    return (protect & readable_flags) != 0 and (protect & PAGE_GUARD == 0)

def find_process_pid_by_name(name):
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == name:
            return proc.info['pid']
    return None

def open_process_readonly(pid):
    handle = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        False,
        pid
    )
    if not handle:
        raise OSError(f"OpenProcess failed for PID {pid}. Error: {kernel32.GetLastError()}")
    return handle

def close_handle(handle):
    kernel32.CloseHandle(handle)

def read_process_memory(handle, address, size):
    buffer = (ctypes.c_byte * size)()
    bytes_read = ctypes.c_size_t(0)
    success = kernel32.ReadProcessMemory(
        handle,
        ctypes.c_void_p(address),
        buffer,
        size,
        ctypes.byref(bytes_read)
    )
    if not success or bytes_read.value != size:
        return None
    return bytearray(buffer)

def read_i32(handle, address):
    data = read_process_memory(handle, address, 4)
    if data is None:
        return None
    return int.from_bytes(data, byteorder='little', signed=True)

def matches_with_wildcard(window, signature, wildcard=0x2E):
    if len(window) != len(signature):
        return False
    for a, b in zip(window, signature):
        if b != wildcard and a != b:
            return False
    return True

def scan_aob(handle, signature, wildcard=0x2E, chunk_size=4 * 1024 * 1024):
    results = []
    sig_len = len(signature)
    if sig_len == 0:
        return results
    overlap_len = sig_len - 1

    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()

    while True:
        result = kernel32.VirtualQueryEx(
            handle,
            ctypes.c_void_p(addr),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi)
        )
        if not result:
            break

        region_base = int(mbi.BaseAddress or 0)
        region_size = int(mbi.RegionSize or 0)

        if region_size == 0:
            addr = region_base + 1
            continue

        if mbi.State == MEM_COMMIT and is_readable(mbi.Protect):
            region_offset = 0
            overlap_buffer = b""

            while region_offset < region_size:
                bytes_to_read = min(region_size - region_offset, chunk_size)
                full_addr = region_base + region_offset

                raw_data = read_process_memory(handle, full_addr, bytes_to_read)
                if raw_data is None:
                    region_offset += bytes_to_read
                    continue

                scan_data = overlap_buffer + raw_data

                search_start = 0
                while search_start <= len(scan_data) - sig_len:
                    first_byte = signature[0]
                    try:
                        idx = scan_data.index(first_byte, search_start)
                    except ValueError:
                        break

                    if idx + sig_len > len(scan_data):
                        break

                    window = scan_data[idx:idx + sig_len]
                    if matches_with_wildcard(window, signature, wildcard):
                        absolute_addr = full_addr + idx - len(overlap_buffer)
                        if not results or results[-1] != absolute_addr:
                            results.append(absolute_addr)
                        search_start = idx + 1
                    else:
                        search_start = idx + 1

                if bytes_to_read >= overlap_len:
                    overlap_buffer = raw_data[-overlap_len:]
                else:
                    overlap_buffer = raw_data

                region_offset += bytes_to_read

        next_addr = region_base + region_size
        if next_addr <= addr:
            addr += 1
        else:
            addr = next_addr

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
    print("This may take 1-2 mins, wait patiently")
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