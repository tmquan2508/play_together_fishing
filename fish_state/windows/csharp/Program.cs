using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Linq;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Numerics;

public unsafe class Program
{
    private const string TargetProcessName = "PlayTogether";
    private static readonly byte[] AobSignature = { 0x20, 0x41, 0xCD, 0xCC, 0x4C, 0x3E, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00 };
    private const byte AobWildcard = 0xFF;
    private const int BaloOffset = 214;
    private const int ConfirmValue = 300;
    private const int FishStateOffset = 308;
    private const int ChunkSize = 4 * 1024 * 1024;

    [Flags]
    public enum ProcessAccessFlags : uint { QueryInformation = 0x0400, VirtualMemoryRead = 0x0010 }

    [StructLayout(LayoutKind.Sequential)]
    public struct MemoryBasicInformation
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public nint RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MemoryBasicInformation lpBuffer, uint dwLength);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte* lpBuffer, nint dwSize, out nint lpNumberOfBytesRead);

    private static List<IntPtr> ScanAobOptimized(IntPtr processHandle)
    {
        var matches = new List<IntPtr>();
        int sigSize = AobSignature.Length;
        int overlapLen = sigSize - 1;

        byte* chunkBuffer = (byte*)NativeMemory.Alloc(ChunkSize);
        byte* scanBuffer = (byte*)NativeMemory.Alloc((nuint)(ChunkSize + overlapLen));
        
        try
        {
            IntPtr currentAddress = IntPtr.Zero;
            while (VirtualQueryEx(processHandle, currentAddress, out MemoryBasicInformation memInfo, (uint)sizeof(MemoryBasicInformation)) != 0)
            {
                bool isReadable = (memInfo.State == 0x1000) && (memInfo.Protect & 0xEE) != 0;
                
                if (isReadable && memInfo.RegionSize > 0)
                {
                    nint regionOffset = 0;
                    while (regionOffset < memInfo.RegionSize)
                    {
                        nint bytesToRead = Math.Min(ChunkSize, memInfo.RegionSize - regionOffset);
                        if (ReadProcessMemory(processHandle, memInfo.BaseAddress + regionOffset, chunkBuffer, bytesToRead, out _))
                        {
                            Buffer.MemoryCopy(scanBuffer + ChunkSize, scanBuffer, overlapLen, overlapLen);
                            Buffer.MemoryCopy(chunkBuffer, scanBuffer + overlapLen, bytesToRead, bytesToRead);

                            var scanSpan = new ReadOnlySpan<byte>(scanBuffer, overlapLen + (int)bytesToRead);

                            int searchOffset = 0;
                            while (searchOffset < scanSpan.Length)
                            {
                                int index = scanSpan.Slice(searchOffset).IndexOf(AobSignature[0]);
                                if (index == -1) break;

                                int matchPos = searchOffset + index;
                                if (matchPos + sigSize > scanSpan.Length) break;
                                
                                if (SequenceMatch(scanSpan.Slice(matchPos, sigSize)))
                                {
                                    IntPtr baseAddressOfScan = memInfo.BaseAddress + regionOffset - overlapLen;
                                    matches.Add(baseAddressOfScan + matchPos);
                                }
                                searchOffset = matchPos + 1;
                            }
                            
                            if (bytesToRead >= overlapLen)
                            {
                                Buffer.MemoryCopy(chunkBuffer + bytesToRead - overlapLen, scanBuffer + ChunkSize, overlapLen, overlapLen);
                            }
                        }
                        regionOffset += bytesToRead;
                    }
                }
                currentAddress = memInfo.BaseAddress + memInfo.RegionSize;
            }
        }
        finally
        {
            NativeMemory.Free(chunkBuffer);
            NativeMemory.Free(scanBuffer);
        }
        return matches;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool SequenceMatch(ReadOnlySpan<byte> data)
    {
        for (int i = 0; i < data.Length; i++)
        {
            if (AobSignature[i] != AobWildcard && AobSignature[i] != data[i])
            {
                return false;
            }
        }
        return true;
    }

    public static void Main(string[] args)
    {
        Console.WriteLine($"Searching for process '{TargetProcessName}.exe'...");
        Process? process = Process.GetProcessesByName(TargetProcessName).FirstOrDefault();
        if (process == null) {
            Console.Error.WriteLine("Error: Process not found.");
            Console.ReadKey(); return;
        }
        Console.WriteLine($"Found process with PID: {process.Id}");

        IntPtr processHandle = OpenProcess(ProcessAccessFlags.QueryInformation | ProcessAccessFlags.VirtualMemoryRead, false, process.Id);
        if (processHandle == IntPtr.Zero) {
            Console.Error.WriteLine("Error: Could not open the process. Try running the tool with Administrator privileges.");
            Console.ReadKey(); return;
        }
        
        try {
            Console.WriteLine("\n*** IMPORTANT ***");
            Console.WriteLine("Please OPEN YOUR INVENTORY/BAG in the game.");
            Console.WriteLine("The tool will start scanning in 5 seconds...");
            Thread.Sleep(5000);

            Console.WriteLine("\n--- Starting full memory scan ---");

            var stopwatch = Stopwatch.StartNew();
            List<IntPtr> baseAddresses = ScanAobOptimized(processHandle);
            stopwatch.Stop();
            Console.WriteLine($"==> AOB scan time: {stopwatch.Elapsed.TotalSeconds:F4} seconds.");

            if (baseAddresses.Count == 0) {
                Console.Error.WriteLine("Scan failed: AOB pattern not found.");
                Console.ReadKey(); return;
            }
            Console.WriteLine($"Found {baseAddresses.Count} addresses. Starting to filter...");

            var candidateAddresses = new List<IntPtr>();
            var buffer = new byte[sizeof(int)];
            foreach (var addr in baseAddresses)
            {
                IntPtr potentialBaloAddr = addr + BaloOffset;
                fixed (byte* pBuffer = buffer)
                {
                    if (ReadProcessMemory(processHandle, potentialBaloAddr, pBuffer, buffer.Length, out _) && BitConverter.ToInt32(buffer, 0) == ConfirmValue)
                    {
                        candidateAddresses.Add(potentialBaloAddr);
                    }
                }
            }
            
            if (candidateAddresses.Count != 1) {
                Console.Error.WriteLine($"Filter failed: Found {candidateAddresses.Count} valid addresses instead of 1.");
                Console.ReadKey(); return;
            }
            
            IntPtr dynamicBaloAddress = candidateAddresses[0];
            Console.WriteLine($"\nSUCCESS! Found unique Bag address: 0x{dynamicBaloAddress.ToInt64():X}");

            IntPtr fishStateAddr = dynamicBaloAddress + FishStateOffset;
            Console.WriteLine("The tool is monitoring the fishing state (Press Ctrl+C to exit)...");

            Console.CancelKeyPress += (sender, e) => {
                e.Cancel = true; 
                Console.WriteLine("\nExit command received...");
                Environment.Exit(0);
            };

            while (true)
            {
                fixed (byte* pBuffer = buffer)
                {
                    if (ReadProcessMemory(processHandle, fishStateAddr, pBuffer, buffer.Length, out _))
                    {
                         Console.Write($"Reading fishing state at 0x{fishStateAddr.ToInt64():X} -> Value: {BitConverter.ToInt32(buffer, 0)}          \r");
                    }
                    else {
                        Console.WriteLine("\nError: Could not read memory. The game may have been closed.");
                        break;
                    }
                }
                Thread.Sleep(500);
            }
        }
        catch (Exception ex) { Console.WriteLine($"\nError: {ex.Message}"); }
        finally 
        { 
            CloseHandle(processHandle); 
            Console.WriteLine("\nTool has finished. Press Enter to exit.");
            Console.ReadKey();
        }
    }
}