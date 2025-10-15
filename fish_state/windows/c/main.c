#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <string.h> // for memchr, memcpy
#include <stdlib.h> // for malloc, realloc, free

#define TARGET_PROCESS_NAME "PlayTogether.exe"
const BYTE AOB_SIGNATURE[] = { 0x20, 0x41, 0xCD, 0xCC, 0x4C, 0x3E, '?', '?', '?', '?', '?', '?', 0x00, 0x00 };
const BYTE AOB_WILDCARD = '?';
const size_t AOB_SIGNATURE_SIZE = sizeof(AOB_SIGNATURE);
const size_t BALO_OFFSET = 214;
const int CONFIRM_VALUE = 300;
const size_t FISH_STATE_OFFSET = 308;
const size_t CHUNK_SIZE = 4 * 1024 * 1024; // 4MB

DWORD GetProcessIdByName(const char* processName) {
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    DWORD pid = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32First(snapshot, &processEntry)) {
        do {
            if (_stricmp(processEntry.szExeFile, processName) == 0) {
                pid = processEntry.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return pid;
}

uintptr_t* ScanAobOptimized(HANDLE processHandle, const BYTE* signature, size_t sigSize, BYTE wildcard, size_t* finalMatchCount) {
    const size_t overlap_len = sigSize - 1;

    BYTE* chunkBuffer = (BYTE*)malloc(CHUNK_SIZE);
    BYTE* scanBuffer = (BYTE*)malloc(CHUNK_SIZE + overlap_len);
    if (!chunkBuffer || !scanBuffer) {
        fprintf(stderr, "Memory allocation error.\n");
        if(chunkBuffer) free(chunkBuffer);
        if(scanBuffer) free(scanBuffer);
        *finalMatchCount = 0;
        return NULL;
    }
    memset(scanBuffer + CHUNK_SIZE, 0, overlap_len);

    size_t matchesCapacity = 1024;
    uintptr_t* matches = (uintptr_t*)malloc(matchesCapacity * sizeof(uintptr_t));
    if (!matches) {
        fprintf(stderr, "Memory allocation error for results.\n");
        free(chunkBuffer);
        free(scanBuffer);
        *finalMatchCount = 0;
        return NULL;
    }
    *finalMatchCount = 0;

    uintptr_t currentAddress = 0;
    MEMORY_BASIC_INFORMATION memInfo;

    while (VirtualQueryEx(processHandle, (LPCVOID)currentAddress, &memInfo, sizeof(memInfo))) {
        BOOL isReadable = (memInfo.State == MEM_COMMIT) &&
                          (memInfo.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));
        
        if (isReadable) {
            uintptr_t regionOffset = 0;
            while (regionOffset < memInfo.RegionSize) {
                size_t bytesToRead = CHUNK_SIZE;
                if (regionOffset + bytesToRead > memInfo.RegionSize) {
                    bytesToRead = memInfo.RegionSize - regionOffset;
                }

                SIZE_T bytesRead;
                if (ReadProcessMemory(processHandle, (LPCVOID)((uintptr_t)memInfo.BaseAddress + regionOffset), chunkBuffer, bytesToRead, &bytesRead)) {
                    memcpy(scanBuffer, scanBuffer + CHUNK_SIZE, overlap_len);
                    memcpy(scanBuffer + overlap_len, chunkBuffer, bytesRead);
                    
                    const size_t effectiveScanSize = overlap_len + bytesRead;

                    BYTE* currentScanPos = scanBuffer;
                    while (currentScanPos < scanBuffer + effectiveScanSize) {
                        BYTE* potentialMatch = (BYTE*)memchr(currentScanPos, signature[0], (scanBuffer + effectiveScanSize) - currentScanPos);
                        if (potentialMatch == NULL) {
                            break; 
                        }
                        if ((size_t)(potentialMatch - scanBuffer) + sigSize > effectiveScanSize) {
                            break;
                        }

                        BOOL found = TRUE;
                        for (size_t j = 1; j < sigSize; ++j) {
                            if (signature[j] != wildcard && signature[j] != potentialMatch[j]) {
                                found = FALSE;
                                break;
                            }
                        }

                        if (found) {
                            if (*finalMatchCount >= matchesCapacity) {
                                matchesCapacity *= 2;
                                uintptr_t* newMatches = (uintptr_t*)realloc(matches, matchesCapacity * sizeof(uintptr_t));
                                if (!newMatches) { 
                                    fprintf(stderr, "Memory reallocation error.\n");
                                    free(chunkBuffer);
                                    free(scanBuffer);
                                    free(matches);
                                    *finalMatchCount = 0;
                                    return NULL;
                                }
                                matches = newMatches;
                            }
                            uintptr_t baseAddressOfScan = (uintptr_t)memInfo.BaseAddress + regionOffset - overlap_len;
                            matches[*finalMatchCount] = baseAddressOfScan + (potentialMatch - scanBuffer);
                            (*finalMatchCount)++;
                        }
                        currentScanPos = potentialMatch + 1;
                    }

                    if (bytesRead >= overlap_len) {
                        memcpy(scanBuffer + CHUNK_SIZE, chunkBuffer + bytesRead - overlap_len, overlap_len);
                    }
                }
                regionOffset += bytesToRead;
            }
        }
        currentAddress = (uintptr_t)memInfo.BaseAddress + memInfo.RegionSize;
    }

    free(chunkBuffer);
    free(scanBuffer);
    return matches;
}

int main() {
    printf("Searching for process '%s'...\n", TARGET_PROCESS_NAME);
    DWORD pid = GetProcessIdByName(TARGET_PROCESS_NAME);
    if (pid == 0) {
        fprintf(stderr, "Error: Process not found. Please make sure the game is running.\n");
        getchar(); return 1;
    }
    printf("Process found with PID: %lu\n", pid);

    HANDLE processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (processHandle == NULL) {
        fprintf(stderr, "Error: Cannot open process. Try running the tool with Administrator privileges.\n");
        getchar(); return 1;
    }

    printf("\n*** IMPORTANT ***\n");
    printf("Please OPEN YOUR INVENTORY/BAG in the game.\n");
    printf("The tool will start scanning in 5 seconds...\n");
    Sleep(5000);

    printf("\n--- Starting full memory scan ---\n");
    
    LARGE_INTEGER frequency, start, end;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&start);

    size_t matchCount = 0;
    uintptr_t* baseAddresses = ScanAobOptimized(processHandle, AOB_SIGNATURE, AOB_SIGNATURE_SIZE, AOB_WILDCARD, &matchCount);
    
    QueryPerformanceCounter(&end);
    double elapsedTime = (double)(end.QuadPart - start.QuadPart) / frequency.QuadPart;
    printf("==> AOB scan time: %.4f seconds.\n", elapsedTime);

    if (baseAddresses == NULL || matchCount == 0) {
        fprintf(stderr, "Scan failed: Array of Bytes (AOB) signature not found.\n");
        if(baseAddresses) free(baseAddresses);
        CloseHandle(processHandle);
        getchar(); return 1;
    }
    printf("Found %zu addresses. Starting to filter...\n", matchCount);

    uintptr_t candidateAddress = 0;
    size_t candidateCount = 0;
    for (size_t i = 0; i < matchCount; ++i) {
        uintptr_t potentialBaloAddr = baseAddresses[i] + BALO_OFFSET;
        int value = 0;
        SIZE_T bytesRead;
        if (ReadProcessMemory(processHandle, (LPCVOID)potentialBaloAddr, &value, sizeof(value), &bytesRead) && bytesRead == sizeof(value)) {
            if (value == CONFIRM_VALUE) {
                candidateAddress = potentialBaloAddr;
                candidateCount++;
            }
        }
    }
    free(baseAddresses);

    if (candidateCount != 1) {
        fprintf(stderr, "Filter failed: Found %zu valid addresses instead of 1.\n", candidateCount);
        CloseHandle(processHandle);
        getchar(); return 1;
    }
    
    uintptr_t dynamicBaloAddress = candidateAddress;
    printf("\nSUCCESS! Found unique Inventory address: 0x%p\n", (void*)dynamicBaloAddress);

    uintptr_t fishStateAddr = dynamicBaloAddress + FISH_STATE_OFFSET;
    printf("The tool is now monitoring the fishing state (Press Ctrl+C to exit)...\n");

    while (TRUE) {
        int state = 0;
        SIZE_T bytesRead;
        if (ReadProcessMemory(processHandle, (LPCVOID)fishStateAddr, &state, sizeof(state), &bytesRead) && bytesRead == sizeof(state)) {
            printf("Reading fishing state at 0x%p -> Value: %d          \r", (void*)fishStateAddr, state);
        } else {
            printf("\nError: Could not read memory. The game might have been closed.\n");
            break;
        }
        Sleep(500);
    }

    CloseHandle(processHandle);
    printf("\nTool has finished. Press Enter to exit.\n");
    getchar();
    return 0;
}