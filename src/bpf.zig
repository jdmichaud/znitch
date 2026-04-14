const std = @import("std");
const Event = @import("event.zig").Event;

const c = @cImport({
    @cInclude("bpf/libbpf.h");
    @cInclude("bpf/bpf.h");
});

const bpf_object_bytes = @embedFile("bpf_object");

pub const RingBufCallback = *const fn (?*anyopaque, ?*anyopaque, usize) callconv(.c) c_int;

pub const BpfLoader = struct {
    obj: *c.bpf_object,
    links: [16]?*c.bpf_link = [_]?*c.bpf_link{null} ** 16,
    link_count: usize = 0,
    rb: ?*c.ring_buffer = null,

    pub fn init() !BpfLoader {
        const obj = c.bpf_object__open_mem(bpf_object_bytes.ptr, bpf_object_bytes.len, null) orelse {
            std.log.err("failed to open BPF object", .{});
            return error.BpfOpenFailed;
        };
        return BpfLoader{ .obj = obj };
    }

    pub fn load(self: *BpfLoader) !void {
        const ret = c.bpf_object__load(self.obj);
        if (ret != 0) {
            std.log.err("failed to load BPF object", .{});
            return error.BpfLoadFailed;
        }
    }

    pub fn attachAll(self: *BpfLoader) !void {
        var prog: ?*c.bpf_program = null;
        while (true) {
            prog = c.bpf_object__next_program(self.obj, prog);
            if (prog == null) break;

            const link = c.bpf_program__attach(prog);
            if (link == null) {
                const name: [*c]const u8 = c.bpf_program__name(prog) orelse "?";
                std.log.err("failed to attach program {s}", .{name});
                return error.BpfAttachFailed;
            }

            if (self.link_count >= self.links.len) {
                return error.TooManyPrograms;
            }
            self.links[self.link_count] = link;
            self.link_count += 1;
        }
    }

    pub fn setupRingBuffer(self: *BpfLoader, callback: RingBufCallback, ctx: ?*anyopaque) !void {
        const map = c.bpf_object__find_map_by_name(self.obj, "events");
        if (map == null) {
            std.log.err("failed to find 'events' map", .{});
            return error.MapNotFound;
        }

        const fd = c.bpf_map__fd(map);
        if (fd < 0) return error.MapFdFailed;

        self.rb = c.ring_buffer__new(fd, callback, ctx, null);
        if (self.rb == null) {
            std.log.err("failed to create ring buffer", .{});
            return error.RingBufFailed;
        }
    }

    pub fn poll(self: *BpfLoader, timeout_ms: i32) !i32 {
        const ret = c.ring_buffer__poll(self.rb, timeout_ms);
        if (ret < 0) {
            const errno_val: u32 = @intCast(-ret);
            const errno = @as(std.posix.E, @enumFromInt(errno_val));
            if (errno == .INTR) return error.Interrupted;
            std.log.err("ring buffer poll failed: {}", .{errno});
            return error.PollFailed;
        }
        return ret;
    }

    pub fn deinit(self: *BpfLoader) void {
        if (self.rb) |rb| {
            c.ring_buffer__free(rb);
        }
        for (&self.links) |*link| {
            if (link.*) |l| {
                _ = c.bpf_link__destroy(l);
                link.* = null;
            }
        }
        c.bpf_object__close(self.obj);
    }

    /// Look up the last DNS query name, first per-PID then global.
    /// Raw DNS bytes are parsed here in userspace.
    pub fn lookupDnsName(self: *BpfLoader, pid: u32) ?[]const u8 {
        const DNS_RAW_MAX = 128;
        const S = struct {
            const DnsQuery = extern struct {
                raw: [DNS_RAW_MAX]u8,
                len: u32,
            };
            var result: DnsQuery = undefined;
            var name_buf: [128]u8 = undefined;
        };

        // Try per-PID first (for apps doing their own DNS)
        if (mapLookup(self.obj, "pid_dns_query", std.mem.asBytes(&pid), std.mem.asBytes(&S.result))) {
            if (parseDnsQuestionName(&S.result.raw, S.result.len, &S.name_buf)) |name|
                return name;
        }

        // Fall back to global last query (for systemd-resolved)
        var zero: u32 = 0;
        if (mapLookup(self.obj, "last_dns_query", std.mem.asBytes(&zero), std.mem.asBytes(&S.result))) {
            if (parseDnsQuestionName(&S.result.raw, S.result.len, &S.name_buf)) |name|
                return name;
        }

        return null;
    }
};

fn mapLookup(obj: *c.bpf_object, name: [*:0]const u8, key: []const u8, value: []u8) bool {
    const map = c.bpf_object__find_map_by_name(obj, name) orelse return false;
    const fd = c.bpf_map__fd(map);
    if (fd < 0) return false;
    return c.bpf_map_lookup_elem(fd, key.ptr, value.ptr) == 0;
}

/// Parse DNS wire-format question name from raw query bytes.
/// DNS format: [12-byte header] \x03www\x06google\x03com\x00
pub fn parseDnsQuestionName(data: []const u8, data_len: u32, out: []u8) ?[]const u8 {
    if (data_len < 13) return null;
    const len = @min(data_len, @as(u32, @intCast(data.len)));

    var src: usize = 12; // skip DNS header
    var dst: usize = 0;

    while (src < len) {
        const label_len = data[src];
        if (label_len == 0) break;
        if (label_len > 63) return null;

        if (dst > 0 and dst < out.len) {
            out[dst] = '.';
            dst += 1;
        }
        src += 1;

        const end = @min(src + label_len, len);
        const copy_end = @min(dst + (end - src), out.len);
        const n = copy_end - dst;

        // Validate label bytes are printable ASCII (reject binary garbage)
        for (data[src .. src + n]) |ch| {
            if (ch < 0x21 or ch > 0x7e) return null;
        }

        @memcpy(out[dst..copy_end], data[src .. src + n]);
        dst = copy_end;
        src = end;
    }

    if (dst == 0) return null;
    return out[0..dst];
}
