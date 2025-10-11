package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/sys/windows"
)

const (
	TARGET_PROCESS_NAME = "PlayTogether.exe"
	AOB_WILDCARD        = '.'
	BALO_OFFSET         = 214
	CONFIRM_VALUE       = int32(300)
	FISH_STATE_OFFSET   = 308
	CHUNK_SIZE          = 4 * 1024 * 1024
)

var AOB_SIGNATURE = []byte{0x20, 0x41, 0xCD, 0xCC, 0x4C, 0x3E, '.', '.', '.', '.', '.', '.', 0x00, 0x00}

func findProcessByName(name string) (uint32, error) {
	processes, err := process.Processes()
	if err != nil {
		return 0, err
	}
	for _, p := range processes {
		procName, err := p.Name()
		if err == nil && procName == name {
			return uint32(p.Pid), nil
		}
	}
	return 0, fmt.Errorf("process not found: '%s'", name)
}

func readMemory(handle windows.Handle, address uintptr, buffer []byte) (int, error) {
	var bytesRead uintptr
	size := len(buffer)
	err := windows.ReadProcessMemory(handle, address, &buffer[0], uintptr(size), &bytesRead)
	if err != nil {
		return 0, err
	}
	if bytesRead != uintptr(size) {
		return int(bytesRead), errors.New("mismatched number of bytes read")
	}
	return int(bytesRead), nil
}

func readInt32(handle windows.Handle, address uintptr) (int32, error) {
	data := make([]byte, 4)
	_, err := readMemory(handle, address, data)
	if err != nil {
		return 0, err
	}
	var value int32
	err = binary.Read(bytes.NewReader(data), binary.LittleEndian, &value)
	return value, err
}

func findPatternInChunk(chunk, signature []byte, wildcard byte) []int {
	var matches []int
	sigLen := len(signature)
	firstByte := signature[0]
	offset := 0
	for {
		index := bytes.IndexByte(chunk[offset:], firstByte)
		if index == -1 {
			break
		}
		offset += index
		if len(chunk)-offset < sigLen {
			break
		}
		found := true
		for j := 1; j < sigLen; j++ {
			if signature[j] != wildcard && signature[j] != chunk[offset+j] {
				found = false
				break
			}
		}
		if found {
			matches = append(matches, offset)
		}
		offset++
	}
	return matches
}

func scanAOB(handle windows.Handle, signature []byte, wildcard byte) ([]uintptr, error) {
	var matches []uintptr
	var memInfo windows.MemoryBasicInformation
	var currentAddr uintptr

	sigLen := len(signature)
	overlap_len := sigLen - 1

	chunkBuffer := make([]byte, CHUNK_SIZE)
	scanBuffer := make([]byte, CHUNK_SIZE+overlap_len)

	for {
		err := windows.VirtualQueryEx(handle, currentAddr, &memInfo, unsafe.Sizeof(memInfo))
		if err != nil {
			break
		}

		isReadable := (memInfo.State == windows.MEM_COMMIT) &&
			(memInfo.Protect == windows.PAGE_READONLY ||
				memInfo.Protect == windows.PAGE_READWRITE ||
				memInfo.Protect == windows.PAGE_EXECUTE_READ ||
				memInfo.Protect == windows.PAGE_EXECUTE_READWRITE)

		if isReadable {
			regionSize := memInfo.RegionSize
			regionBase := memInfo.BaseAddress
			var regionOffset uintptr
			for regionOffset < regionSize {
				bytesToRead := uintptr(CHUNK_SIZE)
				if regionOffset+bytesToRead > regionSize {
					bytesToRead = regionSize - regionOffset
				}

				currentChunk := chunkBuffer[:bytesToRead]
				_, err := readMemory(handle, regionBase+regionOffset, currentChunk)
				if err != nil {
					break
				}

				copy(scanBuffer, scanBuffer[CHUNK_SIZE:CHUNK_SIZE+overlap_len])
				copy(scanBuffer[overlap_len:], currentChunk)

				effectiveScanBuffer := scanBuffer[:overlap_len+int(bytesToRead)]

				relativeIndices := findPatternInChunk(effectiveScanBuffer, signature, wildcard)

				for _, index := range relativeIndices {
					absoluteAddr := regionBase + regionOffset + uintptr(index) - uintptr(overlap_len)
					matches = append(matches, absoluteAddr)
				}

				if int(bytesToRead) >= overlap_len {
					copy(scanBuffer[CHUNK_SIZE:], currentChunk[int(bytesToRead)-overlap_len:])
				}

				regionOffset += bytesToRead
			}
		}
		currentAddr = memInfo.BaseAddress + memInfo.RegionSize
	}
	return matches, nil
}

func runLogic() error {
	fmt.Printf("Searching for process '%s'...\n", TARGET_PROCESS_NAME)
	pid, err := findProcessByName(TARGET_PROCESS_NAME)
	if err != nil {
		return fmt.Errorf("%v. Please make sure the game is running", err)
	}
	fmt.Printf("Found process with PID: %d\n", pid)

	handle, err := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return errors.New("could not open process. Try running the tool with Administrator privileges")
	}
	defer windows.CloseHandle(handle)

	fmt.Println("\n*** IMPORTANT ***")
	fmt.Printf("Please OPEN THE INVENTORY/BAG in-game so the tool can find the correct address (confirm value = %d).\n", CONFIRM_VALUE)
	fmt.Println("The tool will start scanning in 5 seconds...")
	time.Sleep(5 * time.Second)

	fmt.Println("\n--- Starting full memory scan ---")
	startTime := time.Now()
	fmt.Println("Step 1: Scanning for signature (AOB)...")
	baseAddresses, err := scanAOB(handle, AOB_SIGNATURE, AOB_WILDCARD)
	if err != nil {
		return fmt.Errorf("AOB scan failed: %v", err)
	}
	duration := time.Since(startTime)
	fmt.Printf("==> AOB scan time: %.4f seconds.\n", duration.Seconds())

	if len(baseAddresses) == 0 {
		return errors.New("scan failed: Array of Bytes (AOB) signature not found")
	}

	fmt.Printf("Found %d addresses. Starting to filter...\n", len(baseAddresses))
	fmt.Printf("Step 2: Applying offset (%d) and filtering with value (%d) while the inventory is open...\n", BALO_OFFSET, CONFIRM_VALUE)

	var candidateAddresses []uintptr
	for _, addr := range baseAddresses {
		potentialBaloAddr := addr + BALO_OFFSET
		if val, err := readInt32(handle, potentialBaloAddr); err == nil && val == CONFIRM_VALUE {
			candidateAddresses = append(candidateAddresses, potentialBaloAddr)
		}
	}

	if len(candidateAddresses) != 1 {
		return fmt.Errorf("filter failed: found %d valid addresses instead of 1. Please try restarting the game and the tool", len(candidateAddresses))
	}

	dynamicBaloAddress := candidateAddresses[0]
	fmt.Printf("\nSUCCESS! Found unique Inventory address: %#X\n", dynamicBaloAddress)

	fishStateAddr := dynamicBaloAddress + FISH_STATE_OFFSET
	fmt.Println("\n--- Starting main tool loop ---")
	fmt.Println("You can now close the inventory and start fishing.")
	fmt.Println("The tool is monitoring the fishing state (Press Ctrl+C to exit)...")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case <-sigChan:
			fmt.Println("\nReceived exit command...")
			return nil
		default:
			state, err := readInt32(handle, fishStateAddr)
			if err != nil {
				fmt.Println("\nError: Could not read memory. The game may have been closed.")
				return err
			}
			fmt.Printf("Reading fishing state at %#X -> Value: %d          \r", fishStateAddr, state)
			time.Sleep(500 * time.Millisecond)
		}
	}
}

func main() {
	if err := runLogic(); err != nil {
		log.Fatalf("\nFatal error: %v", err)
	}
	fmt.Println("\nThe tool has finished. Press Enter to exit.")
	fmt.Scanln()
}