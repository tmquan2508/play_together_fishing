#include <iostream>
#include <vector>
#include <string>
#include <windows.h>
#include <tlhelp32.h>
#include <memory>
#include <chrono>  // for time measuring
#include <cstring> // for memchr and memcpy

const std::string TARGET_PROCESS_NAME = "PlayTogether.exe";
const BYTE AOB_SIGNATURE[] = { 0x20, 0x41, 0xCD, 0xCC, 0x4C, 0x3E, '?', '?', '?', '?', '?', '?', 0x00, 0x00 };
const BYTE AOB_WILDCARD = '?';
const size_t AOB_SIGNATURE_SIZE = sizeof(AOB_SIGNATURE);
const size_t BALO_OFFSET = 214;
const int CONFIRM_VALUE = 300;
const size_t FISH_STATE_OFFSET = 308;
const size_t CHUNK_SIZE = 4 * 1024 * 1024; // 4MB

DWORD GetProcessIdByName(const std::string& processName) {
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32First(snapshot, &processEntry)) {
        do {
            if (_stricmp(processEntry.szExeFile, processName.c_str()) == 0) {
                CloseHandle(snapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return 0;
}

template <typename T>
bool ReadMemory(HANDLE processHandle, uintptr_t address, T& buffer) {
    SIZE_T bytesRead = 0;
    BOOL result = ReadProcessMemory(processHandle, (LPCVOID)address, &buffer, sizeof(T), &bytesRead);
    return result && (bytesRead == sizeof(T));
}

std::vector<uintptr_t> ScanAobOptimized(HANDLE processHandle) {
    std::vector<uintptr_t> matches;
    const size_t sigSize = AOB_SIGNATURE_SIZE;
    const size_t overlap_len = sigSize - 1;

    auto chunkBuffer = std::make_unique<BYTE[]>(CHUNK_SIZE);
    auto scanBuffer = std::make_unique<BYTE[]>(CHUNK_SIZE + overlap_len);
    if (!chunkBuffer || !scanBuffer) {
        std::cerr << "Memory allocation error." << std::endl;
        return matches;
    }
    memset(scanBuffer.get() + CHUNK_SIZE, 0, overlap_len);

    uintptr_t currentAddress = 0;
    MEMORY_BASIC_INFORMATION memInfo;

    while (VirtualQueryEx(processHandle, (LPCVOID)currentAddress, &memInfo, sizeof(memInfo))) {
        bool isReadable = (memInfo.State == MEM_COMMIT) &&
                          (memInfo.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));
        
        if (isReadable) {
            uintptr_t regionOffset = 0;
            while (regionOffset < memInfo.RegionSize) {
                size_t bytesToRead = CHUNK_SIZE;
                if (regionOffset + bytesToRead > memInfo.RegionSize) {
                    bytesToRead = memInfo.RegionSize - regionOffset;
                }

                SIZE_T bytesRead;
                if (ReadProcessMemory(processHandle, (LPCVOID)((uintptr_t)memInfo.BaseAddress + regionOffset), chunkBuffer.get(), bytesToRead, &bytesRead)) {
                    memcpy(scanBuffer.get(), scanBuffer.get() + CHUNK_SIZE, overlap_len);
                    memcpy(scanBuffer.get() + overlap_len, chunkBuffer.get(), bytesRead);
                    
                    const size_t effectiveScanSize = overlap_len + bytesRead;

                    BYTE* currentScanPos = scanBuffer.get();
                    while (currentScanPos < scanBuffer.get() + effectiveScanSize) {
                        BYTE* potentialMatch = (BYTE*)memchr(currentScanPos, AOB_SIGNATURE[0], (scanBuffer.get() + effectiveScanSize) - currentScanPos);
                        if (potentialMatch == NULL) { break; }
                        if ((size_t)(potentialMatch - scanBuffer.get()) + sigSize > effectiveScanSize) { break; }

                        bool found = true;
                        for (size_t j = 1; j < sigSize; ++j) {
                            if (AOB_SIGNATURE[j] != AOB_WILDCARD && AOB_SIGNATURE[j] != potentialMatch[j]) {
                                found = false;
                                break;
                            }
                        }

                        if (found) {
                            uintptr_t baseAddressOfScan = (uintptr_t)memInfo.BaseAddress + regionOffset - overlap_len;
                            matches.push_back(baseAddressOfScan + (potentialMatch - scanBuffer.get()));
                        }
                        currentScanPos = potentialMatch + 1;
                    }
                    
                    if (bytesRead >= overlap_len) {
                        memcpy(scanBuffer.get() + CHUNK_SIZE, chunkBuffer.get() + bytesRead - overlap_len, overlap_len);
                    }
                }
                regionOffset += bytesToRead;
            }
        }
        currentAddress = (uintptr_t)memInfo.BaseAddress + memInfo.RegionSize;
    }
    return matches;
}


int main() {
    std::cout << "Searching for process '" << TARGET_PROCESS_NAME << "'..." << std::endl;
    DWORD pid = GetProcessIdByName(TARGET_PROCESS_NAME);
    if (pid == 0) {
        std::cerr << "Error: Process not found. Please make sure the game is running." << std::endl;
        std::cin.get(); return 1;
    }
    std::cout << "Found process with PID: " << pid << std::endl;

    HANDLE processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (processHandle == NULL) {
        std::cerr << "Error: Could not open process. Try running the tool with Administrator privileges." << std::endl;
        std::cin.get(); return 1;
    }

    auto processHandleGuard = std::unique_ptr<void, decltype(&::CloseHandle)>(processHandle, &::CloseHandle);

    std::cout << "\n*** IMPORTANT ***" << std::endl;
    std::cout << "Please OPEN YOUR INVENTORY/BAG in the game." << std::endl;
    std::cout << "The tool will start scanning in 5 seconds..." << std::endl;
    Sleep(5000);

    std::cout << "\n--- Starting full memory scan ---" << std::endl;

    auto startTime = std::chrono::high_resolution_clock::now();
    
    std::vector<uintptr_t> baseAddresses = ScanAobOptimized(processHandle);

    auto endTime = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsedTime = endTime - startTime;
    std::cout << "==> AOB scan time: " << std::fixed << elapsedTime.count() << " seconds." << std::endl;

    if (baseAddresses.empty()) {
        std::cerr << "Scan failed: Array of Bytes (AOB) signature not found." << std::endl;
        std::cin.get(); return 1;
    }
    std::cout << "Found " << baseAddresses.size() << " addresses. Starting filtering..." << std::endl;
    
    std::vector<uintptr_t> candidateAddresses;
    for (const auto& addr : baseAddresses) {
        uintptr_t potentialBaloAddr = addr + BALO_OFFSET;
        int value = 0;
        if (ReadMemory(processHandle, potentialBaloAddr, value) && value == CONFIRM_VALUE) {
            candidateAddresses.push_back(potentialBaloAddr);
        }
    }

    if (candidateAddresses.size() != 1) {
        std::cerr << "Filter failed: Found " << candidateAddresses.size() << " valid addresses instead of 1." << std::endl;
        std::cin.get(); return 1;
    }

    uintptr_t dynamicBaloAddress = candidateAddresses[0];
    std::cout << "\nSUCCESS! Found unique Bag address: 0x" << std::hex << dynamicBaloAddress << std::dec << std::endl;
    
    uintptr_t fishStateAddr = dynamicBaloAddress + FISH_STATE_OFFSET;
    std::cout << "Tool is monitoring the fishing state (Press Ctrl+C to exit)..." << std::endl;

    while (true) {
        int state = 0;
        if (ReadMemory(processHandle, fishStateAddr, state)) {
            std::cout << "Reading fishing state at 0x" << std::hex << fishStateAddr << std::dec << " -> Value: " << state << "          \r";
            std::cout.flush();
        } else {
            std::cout << "\nError: Could not read memory. The game might have been closed." << std::endl;
            break;
        }
        Sleep(500);
    }
    
    std::cout << "\nTool has finished. Press Enter to exit." << std::endl;
    std::cin.get();
    return 0;
}