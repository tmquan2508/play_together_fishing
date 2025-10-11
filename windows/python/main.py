import pymem
import pymem.process
import psutil
import time

TARGET_PROCESS_NAME = "PlayTogether.exe"
AOB_SIGNATURE = b'\x5c\x78\x32\x30\x5c\x78\x34\x31\x5c\x78\x43\x44\x5c\x78\x43\x43\x5c\x78\x34\x43\x5c\x78\x33\x45\x2e\x2e\x2e\x2e\x2e\x2e\x5c\x78\x30\x30\x5c\x78\x30\x30'
BALO_OFFSET = 214
CONFIRM_VALUE = 300
FISH_STATE_OFFSET = 308
ROD_STATE_OFFSET = 509

def find_address_and_run():
    pm = None
    try:
        print(f"Searching for process '{TARGET_PROCESS_NAME}'...")
        process_info = next((p for p in psutil.process_iter(['pid', 'name']) if p.info['name'] == TARGET_PROCESS_NAME), None)
        if not process_info:
            raise Exception(f"Process not found: '{TARGET_PROCESS_NAME}'. Make sure the game is running.")
        
        pm = pymem.Pymem(process_info.pid)
        print(f"Pymem attached to PID: {process_info.pid}")

        print("\n*** IMPORTANT ***")
        print(f"Please OPEN YOUR INVENTORY/BAG in the game so the tool can find the correct address (confirm value = {CONFIRM_VALUE}).")
        print("The tool will start scanning in 5 seconds...")
        time.sleep(5)

        print("\n--- Starting full memory scan ---")
        start_time = time.time()
        
        print("Step 1: Scanning for AOB signature across all memory regions...")
        base_addresses = pymem.pattern.pattern_scan_all(pm.process_handle, AOB_SIGNATURE, return_multiple=True)
        end_time = time.time()
        print(f"==> AOB scan finished in: {end_time - start_time:.4f} seconds.")

        if not base_addresses:
            raise Exception("Scan failed: AOB signature not found.")
        
        print(f"Found {len(base_addresses)} addresses. Starting filter...")
        print(f"Step 2: Applying offset ({BALO_OFFSET}) and filtering with value ({CONFIRM_VALUE}) while inventory is open...")
        
        candidate_addresses = []
        for addr in base_addresses:
            try:
                potential_balo_addr = addr + BALO_OFFSET
                if pm.read_int(potential_balo_addr) == CONFIRM_VALUE:
                    candidate_addresses.append(potential_balo_addr)
            except Exception:
                continue

        if len(candidate_addresses) != 1:
            raise Exception(f"Filter failed: Found {len(candidate_addresses)} valid addresses instead of 1. Try restarting the game and the tool.")

        dynamic_balo_address = candidate_addresses[0]
        print(f"\nSUCCESS! Found unique inventory address: {hex(dynamic_balo_address)}")

        print("\n--- Starting main tool loop ---")
        fish_state_addr = dynamic_balo_address + FISH_STATE_OFFSET
        rod_state_addr = dynamic_balo_address + ROD_STATE_OFFSET

        print("You can now close your inventory and start fishing.")
        print("Tool is now monitoring the game state...")

        first_print = True

        while True:
            try:
                fish_state = pm.read_int(fish_state_addr)
                rod_state = pm.read_longlong(rod_state_addr)

                if not first_print:
                    print('\x1b[2A', end='')

                print(f"Reading fish state at {hex(fish_state_addr)} -> Value: {fish_state}\x1b[K")
                print(f"Reading rod state at {hex(rod_state_addr)}  -> Value: {rod_state}\x1b[K")

                first_print = False
                
                time.sleep(0.5)
            except pymem.exception.MemoryReadError:
                print("\nError: Could not read memory. The game may have closed. Exiting...")
                break
            except KeyboardInterrupt:
                print("\n\nReceived exit command from user...")
                break

    except Exception as e:
        print(f"\nFatal error: {e}")
    finally:
        print("\nTool has finished. Press Enter to exit.")
        input()

if __name__ == "__main__":
    find_address_and_run()