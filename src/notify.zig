const std = @import("std");
const dbus = @import("dbus.zig");

const MAX_TRACKED = 64;

const TrackedNotification = struct {
    id: u32 = 0,
    pid: u32 = 0,
    active: bool = false,
};

pub const Notifier = struct {
    fd: ?std.posix.fd_t = null,
    serial: u32 = 0,
    tracked: [MAX_TRACKED]TrackedNotification = .{TrackedNotification{}} ** MAX_TRACKED,

    pub fn init() Notifier {
        var notifier = Notifier{};
        notifier.connect() catch {
            std.log.warn("failed to connect to session bus (notifications disabled)", .{});
        };
        return notifier;
    }

    fn connect(self: *Notifier) !void {
        const addr = getBusAddress() orelse return error.NoBusAddress;
        const sock = try std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0);
        errdefer std.posix.close(sock);

        var sa = std.posix.sockaddr.un{ .path = undefined, .family = std.posix.AF.UNIX };
        @memset(&sa.path, 0);
        if (addr.len > sa.path.len) return error.PathTooLong;
        @memcpy(sa.path[0..addr.len], addr);

        try std.posix.connect(sock, @ptrCast(&sa), @sizeOf(std.posix.sockaddr.un));
        self.fd = sock;
        errdefer self.fd = null; // reset if auth/hello fails

        try self.authenticate();
        try self.hello();

        // Set non-blocking after auth (which needs blocking reads).
        // Prevents blocking in the event loop callback.
        const flags = try std.posix.fcntl(sock, std.posix.F.GETFL, @as(u32, 0));
        const NONBLOCK: u32 = @bitCast(std.posix.O{ .NONBLOCK = true });
        _ = try std.posix.fcntl(sock, std.posix.F.SETFL, flags | NONBLOCK);
    }

    fn authenticate(self: *Notifier) !void {
        const sock = self.fd orelse return error.NotConnected;

        // Send nul byte (required by D-Bus spec before auth)
        _ = try std.posix.write(sock, "\x00");

        // First try AUTH EXTERNAL with the effective UID
        const euid = std.os.linux.geteuid();
        var uid_str_buf: [16]u8 = undefined;
        const uid_str = std.fmt.bufPrint(&uid_str_buf, "{}", .{euid}) catch return error.FormatFailed;

        var auth_buf: [128]u8 = undefined;
        var auth_len: usize = 0;
        const prefix = "AUTH EXTERNAL ";
        @memcpy(auth_buf[0..prefix.len], prefix);
        auth_len = prefix.len;

        // Hex-encode each ASCII byte of the UID string
        for (uid_str) |ch| {
            auth_buf[auth_len] = hexDigit(ch >> 4);
            auth_buf[auth_len + 1] = hexDigit(ch & 0x0f);
            auth_len += 2;
        }
        auth_buf[auth_len] = '\r';
        auth_buf[auth_len + 1] = '\n';
        auth_len += 2;

        _ = try std.posix.write(sock, auth_buf[0..auth_len]);

        var resp: [256]u8 = undefined;
        const n = try std.posix.read(sock, &resp);
        const response = resp[0..n];

        if (std.mem.startsWith(u8, response, "OK ")) {
            _ = try std.posix.write(sock, "BEGIN\r\n");
            return;
        }

        // Server might respond with DATA (challenge) or REJECTED
        if (std.mem.startsWith(u8, response, "DATA")) {
            // Send the hex-encoded UID as DATA response
            var data_buf: [64]u8 = undefined;
            var data_len: usize = 0;
            const dp = "DATA ";
            @memcpy(data_buf[0..dp.len], dp);
            data_len = dp.len;
            for (uid_str) |ch| {
                data_buf[data_len] = hexDigit(ch >> 4);
                data_buf[data_len + 1] = hexDigit(ch & 0x0f);
                data_len += 2;
            }
            data_buf[data_len] = '\r';
            data_buf[data_len + 1] = '\n';
            data_len += 2;

            _ = try std.posix.write(sock, data_buf[0..data_len]);

            const n2 = try std.posix.read(sock, &resp);
            if (n2 >= 3 and std.mem.startsWith(u8, resp[0..n2], "OK ")) {
                _ = try std.posix.write(sock, "BEGIN\r\n");
                return;
            }
        }

        return error.AuthFailed;
    }

    fn hello(self: *Notifier) !void {
        self.serial += 1;
        const msg = dbus.buildMethodCall(
            self.serial,
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "Hello",
            "org.freedesktop.DBus",
            "",
            "",
        );
        try self.sendRaw(msg.data());
        // Read and discard the Hello reply
        var discard: [512]u8 = undefined;
        _ = std.posix.read(self.fd.?, &discard) catch {};
    }

    /// Drain pending incoming D-Bus messages (signals, etc.).
    fn drain(self: *Notifier) void {
        const sock = self.fd orelse return;
        var buf: [4096]u8 = undefined;
        // Use poll to avoid blocking — only read if data is ready
        var pfd = [1]std.posix.pollfd{.{ .fd = sock, .events = std.posix.POLL.IN, .revents = 0 }};
        var drained: usize = 0;
        while (drained < 16) : (drained += 1) {
            _ = std.posix.poll(&pfd, 0) catch break; // timeout=0: don't wait
            if (pfd[0].revents & std.posix.POLL.IN == 0) break;
            _ = std.posix.read(sock, &buf) catch break;
        }
    }

    fn sendRaw(self: *Notifier, data: []const u8) !void {
        const sock = self.fd orelse return error.NotConnected;
        self.drain();
        var sent: usize = 0;
        while (sent < data.len) {
            sent += try std.posix.write(sock, data[sent..]);
        }
    }

    fn readReply(self: *Notifier) ?u32 {
        const sock = self.fd orelse return null;
        // Brief poll — wait up to 50ms for the reply
        var pfd = [1]std.posix.pollfd{.{ .fd = sock, .events = std.posix.POLL.IN, .revents = 0 }};
        _ = std.posix.poll(&pfd, 50) catch return null;
        if (pfd[0].revents & std.posix.POLL.IN == 0) return null;

        var buf: [4096]u8 = undefined;
        const n = std.posix.read(sock, &buf) catch return null;
        return dbus.parseReplyU32(buf[0..n]);
    }

    pub fn deinit(self: *Notifier) void {
        for (&self.tracked) |*t| {
            if (t.active) {
                self.closeNotification(t.id);
                t.active = false;
            }
        }
        if (self.fd) |fd| {
            _ = std.c.close(fd);
        }
        self.fd = null;
    }

    pub fn notify(self: *Notifier, summary: [*:0]const u8, body: [*:0]const u8, timeout_ms: i32) void {
        _ = self.notifyTracked(summary, body, timeout_ms, null);
    }

    pub fn notifyTracked(self: *Notifier, summary: [*:0]const u8, body: [*:0]const u8, timeout_ms: i32, track_pid: ?u32) u32 {
        if (self.fd == null) return 0;

        const sum = std.mem.span(summary);
        const bod = std.mem.span(body);

        const notify_body = dbus.buildNotifyBody("znitch", 0, sum, bod, timeout_ms);

        self.serial += 1;
        const msg = dbus.buildMethodCall(
            self.serial,
            "/org/freedesktop/Notifications",
            "org.freedesktop.Notifications",
            "Notify",
            "org.freedesktop.Notifications",
            "susssasa{sv}i",
            notify_body.data(),
        );

        self.sendRaw(msg.data()) catch {
            std.log.warn("notification send failed", .{});
            return 0;
        };

        const notif_id = self.readReply() orelse 0;

        if (track_pid) |pid| {
            if (notif_id != 0) {
                var best: usize = 0;
                for (&self.tracked, 0..) |*t, i| {
                    if (!t.active) {
                        best = i;
                        break;
                    }
                    best = i;
                }
                self.tracked[best] = .{ .id = notif_id, .pid = pid, .active = true };
            }
        }

        return notif_id;
    }

    fn closeNotification(self: *Notifier, id: u32) void {
        const fd = self.fd orelse return;
        const close_body = dbus.buildCloseBody(id);
        self.serial += 1;
        const msg = dbus.buildMethodCall(
            self.serial,
            "/org/freedesktop/Notifications",
            "org.freedesktop.Notifications",
            "CloseNotification",
            "org.freedesktop.Notifications",
            "u",
            close_body.data(),
        );
        self.sendRaw(msg.data()) catch {
            // Socket is dead
            std.posix.close(fd);
            self.fd = null;
            return;
        };
        // Drain reply
        var discard: [256]u8 = undefined;
        _ = std.posix.read(fd, &discard) catch {};
    }

    pub fn closeForPid(self: *Notifier, pid: u32) void {
        for (&self.tracked) |*t| {
            if (t.active and t.pid == pid) {
                self.closeNotification(t.id);
                t.active = false;
            }
        }
    }

    pub fn reapStale(self: *Notifier) void {
        const S = struct {
            var path_buf: [32]u8 = undefined;
        };
        for (&self.tracked) |*t| {
            if (!t.active) continue;
            const path = std.fmt.bufPrintZ(&S.path_buf, "/proc/{}", .{t.pid}) catch continue;
            std.posix.access(path, std.posix.F_OK) catch {
                std.debug.print("[reap] closing notification for dead pid {}\n", .{t.pid});
                self.closeNotification(t.id);
                t.active = false;
            };
        }
    }
};

fn hexDigit(v: u8) u8 {
    return if (v < 10) '0' + v else 'a' + v - 10;
}

/// Get the D-Bus session bus socket path from environment or default location.
fn getBusAddress() ?[]const u8 {
    // Try DBUS_SESSION_BUS_ADDRESS (e.g. "unix:path=/run/user/1000/bus")
    if (std.posix.getenv("DBUS_SESSION_BUS_ADDRESS")) |addr| {
        if (std.mem.indexOf(u8, addr, "unix:path=")) |idx| {
            const path_start = idx + "unix:path=".len;
            // Find end (comma or end of string)
            const rest = addr[path_start..];
            if (std.mem.indexOfScalar(u8, rest, ',')) |comma| {
                return rest[0..comma];
            }
            return rest;
        }
    }

    // Fall back to standard XDG runtime dir (use euid for sudo compatibility)
    const S = struct {
        var buf: [64]u8 = undefined;
    };
    const uid = std.os.linux.geteuid();
    const path = std.fmt.bufPrint(&S.buf, "/run/user/{}/bus", .{uid}) catch return null;
    // Verify it exists
    std.posix.access(path, std.posix.F_OK) catch return null;
    return path;
}
