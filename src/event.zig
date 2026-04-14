const std = @import("std");

pub const EventType = enum(u8) {
    connect = 0,
    bind = 1,
    unbind = 2,
    dns_query = 3,
};

/// Shared event structure - must match the C struct in znitch.bpf.c exactly.
/// Using packed struct to match __attribute__((packed)) on the C side.
pub const Event = extern struct {
    pid: u32,
    uid: u32,
    port: u16,
    af: u16,
    addr_v4: u32, // network byte order
    addr_v6: [16]u8,
    event_type: EventType,
    comm: [16]u8,

    pub fn getComm(self: *const Event) []const u8 {
        const len = std.mem.indexOfScalar(u8, &self.comm, 0) orelse self.comm.len;
        return self.comm[0..len];
    }

    pub fn formatAddr(self: *const Event, buf: []u8) ![]const u8 {
        if (self.af == 2) { // AF_INET
            const addr = self.addr_v4;
            return std.fmt.bufPrint(buf, "{}.{}.{}.{}", .{
                addr & 0xFF,
                (addr >> 8) & 0xFF,
                (addr >> 16) & 0xFF,
                (addr >> 24) & 0xFF,
            });
        } else if (self.af == 10) { // AF_INET6
            return std.fmt.bufPrint(buf, "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
                self.addr_v6[0],  self.addr_v6[1],
                self.addr_v6[2],  self.addr_v6[3],
                self.addr_v6[4],  self.addr_v6[5],
                self.addr_v6[6],  self.addr_v6[7],
                self.addr_v6[8],  self.addr_v6[9],
                self.addr_v6[10], self.addr_v6[11],
                self.addr_v6[12], self.addr_v6[13],
                self.addr_v6[14], self.addr_v6[15],
            });
        }
        return "unknown";
    }
};
