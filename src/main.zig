const std = @import("std");
const Event = @import("event.zig").Event;
const EventType = @import("event.zig").EventType;
const BpfLoader = @import("bpf.zig").BpfLoader;
const Notifier = @import("notify.zig").Notifier;

var should_exit: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

var global_notifier: ?*Notifier = null;
var global_loader: ?*BpfLoader = null;
var global_timeout_ms: i32 = 5000;

fn sigHandler(_: c_int) callconv(.c) void {
    should_exit.store(true, .release);
}

fn dropPrivileges() void {
    const sudo_uid_str = std.posix.getenv("SUDO_UID") orelse return;
    const sudo_gid_str = std.posix.getenv("SUDO_GID") orelse return;
    const uid = std.fmt.parseInt(u32, sudo_uid_str, 10) catch return;
    const gid = std.fmt.parseInt(u32, sudo_gid_str, 10) catch return;
    if (uid == 0) return;

    // Drop group first, then user (can't drop group after dropping root uid)
    _ = std.c.setegid(gid);
    _ = std.c.seteuid(uid);
    std.debug.print("dropped privileges to uid={} gid={}\n", .{ uid, gid });
}

// Dedup cache: suppress duplicate notifications for the same (pid, port, type)
// within a short window. Still logs every event to stdout.
const DedupKey = packed struct {
    pid: u32,
    port: u16,
    event_type: EventType,
};
const DEDUP_SLOTS = 64;
const DEDUP_WINDOW_NS: u64 = 2_000_000_000; // 2 seconds

var dedup_keys: [DEDUP_SLOTS]DedupKey = undefined;
var dedup_times: [DEDUP_SLOTS]u64 = [_]u64{0} ** DEDUP_SLOTS;

fn shouldNotify(pid: u32, port: u16, event_type: EventType) bool {
    const now = @as(u64, @intCast(std.time.nanoTimestamp()));
    const key = DedupKey{ .pid = pid, .port = port, .event_type = event_type };
    const key_bytes = std.mem.asBytes(&key);

    // Simple hash into dedup table
    var h: u32 = 0;
    for (key_bytes) |b| h = h *% 31 +% b;
    const slot = h % DEDUP_SLOTS;

    if (std.mem.eql(u8, std.mem.asBytes(&dedup_keys[slot]), key_bytes) and
        now - dedup_times[slot] < DEDUP_WINDOW_NS)
    {
        return false; // duplicate within window
    }

    dedup_keys[slot] = key;
    dedup_times[slot] = now;
    return true;
}

/// Resolve the real process name via /proc/<pid>/exe (readlink).
/// Falls back to the BPF comm (thread name) if readlink fails.
fn getProcessName(pid: u32, fallback: []const u8) []const u8 {
    const S = struct {
        var buf: [256]u8 = undefined;
        var path_buf: [32]u8 = undefined;
    };

    const path = std.fmt.bufPrintZ(&S.path_buf, "/proc/{}/exe", .{pid}) catch return fallback;
    const full = std.posix.readlinkat(std.posix.AT.FDCWD, path, &S.buf) catch return fallback;

    // Extract basename: "/usr/lib/firefox/firefox" → "firefox"
    if (std.mem.lastIndexOfScalar(u8, full, '/')) |pos| {
        return full[pos + 1 ..];
    }
    return full;
}

/// Look up the domain name from BPF DNS query cache.
fn resolveAddr(event: *const Event) ?[]const u8 {
    // Don't resolve DNS server connections themselves
    if (event.port == 53) return null;
    const loader = global_loader orelse return null;
    return loader.lookupDnsName(event.pid);
}

fn handleEvent(_: ?*anyopaque, data: ?*anyopaque, size: usize) callconv(.c) c_int {
    if (size < @sizeOf(Event)) return 0;
    const event: *const Event = @ptrCast(@alignCast(data));

    var addr_buf: [64]u8 = undefined;
    const addr = event.formatAddr(&addr_buf) catch "?";
    const comm = getProcessName(event.pid, event.getComm());
    const hostname = resolveAddr(event);

    // Format endpoint: hostname (ip):port or ip:port
    var endpoint_buf: [192]u8 = undefined;
    const endpoint = if (hostname) |name|
        (if (event.af == 10)
            std.fmt.bufPrint(&endpoint_buf, "{s} ([{s}]):{}", .{ name, addr, event.port })
        else
            std.fmt.bufPrint(&endpoint_buf, "{s} ({s}):{}", .{ name, addr, event.port })) catch "?"
    else
        (if (event.af == 10)
            std.fmt.bufPrint(&endpoint_buf, "[{s}]:{}", .{ addr, event.port })
        else
            std.fmt.bufPrint(&endpoint_buf, "{s}:{}", .{ addr, event.port })) catch "?";

    switch (event.event_type) {
        .connect => {
            std.debug.print("[connect] {s} (pid {}) -> {s}\n", .{ comm, event.pid, endpoint });

            if (shouldNotify(event.pid, event.port, event.event_type)) {
                var body_buf: [256]u8 = undefined;
                const body = std.fmt.bufPrintZ(&body_buf, "{s} (pid {}) -> {s}", .{
                    comm, event.pid, endpoint,
                }) catch "?";
                if (global_notifier) |n| {
                    n.notify("Outgoing Connection", body, global_timeout_ms);
                }
            }
        },
        .bind => {
            std.debug.print("[bind] {s} (pid {}) binding {s}\n", .{ comm, event.pid, endpoint });

            if (shouldNotify(event.pid, event.port, event.event_type)) {
                var body_buf: [256]u8 = undefined;
                const body = std.fmt.bufPrintZ(&body_buf, "{s} (pid {}) binding {s}", .{
                    comm, event.pid, endpoint,
                }) catch "?";
                if (global_notifier) |n| {
                    _ = n.notifyTracked("Port Binding", body, 0, event.pid);
                }
            }
        },
        .unbind => {
            std.debug.print("[unbind] {s} (pid {}) closed port {}\n", .{ comm, event.pid, event.port });
            if (global_notifier) |n| {
                n.closeForPid(event.pid);
            }
        },
        .dns_query => {
            // Read the raw DNS query from the BPF map and parse the domain name
            if (global_loader) |loader| {
                if (loader.lookupDnsName(event.pid)) |domain| {
                    std.debug.print("[dns] {s} (pid {}) resolving {s}\n", .{ comm, event.pid, domain });
                }
            }
        },
    }

    return 0;
}

pub fn main() !void {
    // Parse args
    var args = std.process.args();
    _ = args.next(); // skip program name

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--timeout")) {
            if (args.next()) |val| {
                global_timeout_ms = std.fmt.parseInt(i32, val, 10) catch {
                    std.debug.print("invalid timeout value: {s}\n", .{val});
                    return error.InvalidArgs;
                };
            }
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            std.debug.print(
                \\Usage: znitch [OPTIONS]
                \\
                \\eBPF-based network monitor with desktop notifications.
                \\Detects outgoing connections and port bindings.
                \\
                \\Options:
                \\  --timeout <ms>  Notification timeout for connections (default: 5000)
                \\  --help, -h      Show this help
                \\
                \\Permissions (pick one):
                \\  sudo setcap cap_bpf,cap_perfmon=ep ./znitch   (recommended)
                \\  sudo ./znitch                                  (works too)
                \\
            , .{});
            return;
        }
    }

    // Setup signal handlers
    const sa = std.posix.Sigaction{
        .handler = .{ .handler = sigHandler },
        .mask = std.posix.empty_sigset,
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &sa, null);
    std.posix.sigaction(std.posix.SIG.TERM, &sa, null);

    // Initialize BPF (needs root)
    std.debug.print("loading BPF program...\n", .{});
    var loader = BpfLoader.init() catch {
        std.debug.print("failed to open BPF object. Are you root?\n", .{});
        return error.BpfInitFailed;
    };
    defer loader.deinit();

    loader.load() catch {
        std.debug.print("failed to load BPF program.\n  Try: sudo setcap cap_bpf,cap_perfmon=ep znitch\n", .{});
        return error.BpfLoadFailed;
    };

    try loader.attachAll();
    try loader.setupRingBuffer(handleEvent, null);
    global_loader = &loader;

    // Drop privileges to the original user so D-Bus session bus works.
    // BPF fds are already open, ring buffer polling doesn't need root.
    dropPrivileges();

    // Initialize notification system (connects to D-Bus as the real user)
    var notifier = Notifier.init();
    defer notifier.deinit();
    global_notifier = &notifier;

    std.debug.print("znitch is running (timeout={d}ms). Press Ctrl+C to stop.\n", .{global_timeout_ms});

    // Event loop
    var reap_counter: u32 = 0;
    while (!should_exit.load(.acquire)) {
        _ = loader.poll(100) catch |err| {
            if (err == error.Interrupted) continue;
            return err;
        };

        // Check for dead processes every ~2 seconds (20 * 100ms poll)
        reap_counter += 1;
        if (reap_counter >= 20) {
            reap_counter = 0;
            notifier.reapStale();
        }
    }

    std.debug.print("\nshutting down.\n", .{});
}
