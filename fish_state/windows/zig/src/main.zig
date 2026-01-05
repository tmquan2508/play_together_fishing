const std = @import("std");

const TARGET_PROCESS_NAME = "PlayTogether.exe";
const AOB_SIGNATURE = [_]u8{ 0x20, 0x41, 0xCD, 0xCC, 0x4C, 0x3E, '?', '?', '?', '?', '?', '?', 0x00, 0x00 };
const AOB_WILDCARD = '?';
const BALO_OFFSET = 214;
const CONFIRM_VALUE = 300;
const FISH_STATE_OFFSET = 308;
const CHUNK_SIZE = 4 * 1024 * 1024;

const HANDLE = ?*anyopaque;
const DWORD = u32;
const BOOL = i32;
const LPCVOID = ?*const anyopaque;
const LPVOID = ?*anyopaque;
const SIZE_T = usize;
const FALSE: BOOL = 0;
const TRUE: BOOL = 1;
const INVALID_HANDLE_VALUE = @as(HANDLE, @ptrFromInt(@as(usize, @bitCast(@as(isize, -1)))));

const PROCESSENTRY32 = extern struct {
    dwSize: u32,
    cntUsage: u32,
    th32ProcessID: u32,
    th32DefaultHeapID: usize,
    th32ModuleID: u32,
    cntThreads: u32,
    th32ParentProcessID: u32,
    pcPriClassBase: i32,
    dwFlags: u32,
    szExeFile: [260]u8,
};

const MEMORY_BASIC_INFORMATION = extern struct {
    BaseAddress: ?*anyopaque,
    AllocationBase: ?*anyopaque,
    AllocationProtect: u32,
    PartitionId: u16,
    RegionSize: usize,
    State: u32,
    Protect: u32,
    Type: u32,
};

const LARGE_INTEGER = i64;

extern "kernel32" fn CreateToolhelp32Snapshot(dwFlags: DWORD, th32ProcessID: DWORD) callconv(.winapi) HANDLE;
extern "kernel32" fn Process32First(hSnapshot: HANDLE, lppe: *PROCESSENTRY32) callconv(.winapi) BOOL;
extern "kernel32" fn Process32Next(hSnapshot: HANDLE, lppe: *PROCESSENTRY32) callconv(.winapi) BOOL;
extern "kernel32" fn CloseHandle(hObject: HANDLE) callconv(.winapi) BOOL;
extern "kernel32" fn OpenProcess(dwAccess: DWORD, bInherit: BOOL, dwId: DWORD) callconv(.winapi) HANDLE;
extern "kernel32" fn VirtualQueryEx(hProc: HANDLE, lpAddr: LPCVOID, lpBuf: *MEMORY_BASIC_INFORMATION, dwLen: SIZE_T) callconv(.winapi) SIZE_T;
extern "kernel32" fn ReadProcessMemory(hProc: HANDLE, lpBase: LPCVOID, lpBuf: LPVOID, nSize: SIZE_T, lpRead: *SIZE_T) callconv(.winapi) BOOL;
extern "kernel32" fn Sleep(dwMs: DWORD) callconv(.winapi) void;
extern "kernel32" fn QueryPerformanceCounter(lpPerformanceCount: *LARGE_INTEGER) callconv(.winapi) BOOL;
extern "kernel32" fn QueryPerformanceFrequency(lpFrequency: *LARGE_INTEGER) callconv(.winapi) BOOL;

fn getProcessIdByName(name: []const u8) !u32 {
    const snapshot = CreateToolhelp32Snapshot(0x00000002, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return error.SnapshotFailed;
    defer _ = CloseHandle(snapshot);
    var entry: PROCESSENTRY32 = undefined;
    entry.dwSize = @sizeOf(PROCESSENTRY32);
    if (Process32First(snapshot, &entry) == FALSE) return error.ProcessNotFound;
    while (true) {
        const exe_name = std.mem.sliceTo(&entry.szExeFile, 0);
        if (std.ascii.eqlIgnoreCase(exe_name, name)) return entry.th32ProcessID;
        if (Process32Next(snapshot, &entry) == FALSE) break;
    }
    return error.ProcessNotFound;
}

fn scanAob(allocator: std.mem.Allocator, h_proc: HANDLE) !std.ArrayListUnmanaged(usize) {
    var matches = std.ArrayListUnmanaged(usize){};
    const sig_len = AOB_SIGNATURE.len;
    const overlap_len = sig_len - 1;
    const chunk_buf = try allocator.alloc(u8, CHUNK_SIZE);
    defer allocator.free(chunk_buf);
    const scan_buf = try allocator.alloc(u8, CHUNK_SIZE + overlap_len);
    defer allocator.free(scan_buf);
    @memset(scan_buf, 0);
    var addr: usize = 0;
    var mem_info: MEMORY_BASIC_INFORMATION = undefined;
    while (VirtualQueryEx(h_proc, @ptrFromInt(addr), &mem_info, @sizeOf(MEMORY_BASIC_INFORMATION)) != 0) {
        if (mem_info.State == 0x1000 and (mem_info.Protect & 0x66) != 0) {
            var region_offset: usize = 0;
            while (region_offset < mem_info.RegionSize) {
                const to_read = @min(CHUNK_SIZE, mem_info.RegionSize - region_offset);
                var bytes_read: usize = 0;
                if (ReadProcessMemory(h_proc, @ptrFromInt(@intFromPtr(mem_info.BaseAddress) + region_offset), chunk_buf.ptr, to_read, &bytes_read) != FALSE) {
                    @memcpy(scan_buf[0..overlap_len], scan_buf[CHUNK_SIZE..][0..overlap_len]);
                    @memcpy(scan_buf[overlap_len..][0..bytes_read], chunk_buf[0..bytes_read]);
                    const area = scan_buf[0 .. overlap_len + bytes_read];
                    var i: usize = 0;
                    while (i <= area.len - sig_len) {
                        if (area[i] == AOB_SIGNATURE[0]) {
                            var match = true;
                            inline for (1..sig_len) |j| {
                                if (AOB_SIGNATURE[j] != AOB_WILDCARD and AOB_SIGNATURE[j] != area[i + j]) {
                                    match = false;
                                    break;
                                }
                            }
                            if (match) try matches.append(allocator, @intFromPtr(mem_info.BaseAddress) + region_offset - overlap_len + i);
                        }
                        i += 1;
                    }
                    if (bytes_read >= overlap_len) @memcpy(scan_buf[CHUNK_SIZE..][0..overlap_len], chunk_buf[bytes_read - overlap_len .. bytes_read]);
                }
                region_offset += to_read;
            }
        }
        addr = @intFromPtr(mem_info.BaseAddress) + mem_info.RegionSize;
    }
    return matches;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    std.debug.print("Searching for process '{s}'...\n", .{TARGET_PROCESS_NAME});
    const pid = getProcessIdByName(TARGET_PROCESS_NAME) catch {
        std.debug.print("Error: Process not found. Please make sure the game is running.\n", .{});
        _ = Sleep(2000); return;
    };
    std.debug.print("Process found with PID: {d}\n", .{pid});

    const h_proc = OpenProcess(0x0010 | 0x0400, FALSE, pid);
    if (h_proc == null) {
        std.debug.print("Error: Cannot open process. Try running the tool with Administrator privileges.\n", .{});
        return;
    }
    defer _ = CloseHandle(h_proc);

    std.debug.print("\n*** IMPORTANT ***\nPlease OPEN YOUR INVENTORY/BAG in the game.\nThe tool will start scanning in 5 seconds...\n", .{});
    Sleep(5000);

    std.debug.print("\n--- Starting full memory scan ---\n", .{});
    
    var freq: LARGE_INTEGER = undefined;
    var start_t: LARGE_INTEGER = undefined;
    var end_t: LARGE_INTEGER = undefined;
    _ = QueryPerformanceFrequency(&freq);
    _ = QueryPerformanceCounter(&start_t);

    var matches = try scanAob(allocator, h_proc);
    defer matches.deinit(allocator);
    
    _ = QueryPerformanceCounter(&end_t);
    const elapsed = @as(f64, @floatFromInt(end_t - start_t)) / @as(f64, @floatFromInt(freq));
    std.debug.print("==> AOB scan time: {d:.4} seconds.\n", .{elapsed});

    if (matches.items.len == 0) {
        std.debug.print("Scan failed: Array of Bytes (AOB) signature not found.\n", .{});
        return;
    }
    std.debug.print("Found {d} addresses. Starting to filter...\n", .{matches.items.len});

    var candidate_addr: usize = 0;
    var candidate_count: usize = 0;
    for (matches.items) |m| {
        const potential_balo_addr = m + BALO_OFFSET;
        var value: i32 = 0;
        var br: usize = 0;
        if (ReadProcessMemory(h_proc, @ptrFromInt(potential_balo_addr), &value, 4, &br) != FALSE) {
            if (value == CONFIRM_VALUE) {
                candidate_addr = potential_balo_addr;
                candidate_count += 1;
            }
        }
    }

    if (candidate_count != 1) {
        std.debug.print("Filter failed: Found {d} valid addresses instead of 1.\n", .{candidate_count});
        return;
    }

    const dynamic_balo_address = candidate_addr;
    std.debug.print("\nSUCCESS! Found unique Inventory address: 0x{X}\n", .{dynamic_balo_address});

    const fish_state_addr = dynamic_balo_address + FISH_STATE_OFFSET;
    std.debug.print("The tool is now monitoring the fishing state (Press Ctrl+C to exit)...\n", .{});

    while (true) {
        var state: i32 = 0;
        var br: usize = 0;
        if (ReadProcessMemory(h_proc, @ptrFromInt(fish_state_addr), &state, 4, &br) != FALSE) {
            std.debug.print("Reading fishing state at 0x{X} -> Value: {d}          \r", .{ fish_state_addr, state });
        } else {
            std.debug.print("\nError: Could not read memory. The game might have been closed.\n", .{});
            break;
        }
        Sleep(500);
    }
}