const std = @import("std");
const testing = std.testing;
const bpf = @import("bpf.zig");
const event_mod = @import("event.zig");
const Event = event_mod.Event;
const EventType = event_mod.EventType;

// Helper: build a DNS query packet with a given domain name
fn buildDnsQuery(name: []const u8) [128]u8 {
    var pkt: [128]u8 = .{0} ** 128;

    // DNS header (12 bytes): ID=0x1234, flags=0x0100 (standard query), qdcount=1
    pkt[0] = 0x12;
    pkt[1] = 0x34;
    pkt[2] = 0x01; // QR=0 (query), opcode=0, RD=1
    pkt[3] = 0x00;
    pkt[4] = 0x00;
    pkt[5] = 0x01; // qdcount=1

    // Question section: encode domain name in wire format
    var pos: usize = 12;
    var start: usize = 0;
    for (name, 0..) |ch, i| {
        if (ch == '.') {
            const label_len = i - start;
            pkt[pos] = @intCast(label_len);
            pos += 1;
            @memcpy(pkt[pos .. pos + label_len], name[start..i]);
            pos += label_len;
            start = i + 1;
        }
    }
    // Last label
    const label_len = name.len - start;
    pkt[pos] = @intCast(label_len);
    pos += 1;
    @memcpy(pkt[pos .. pos + label_len], name[start..name.len]);
    pos += label_len;
    pkt[pos] = 0; // end of name

    return pkt;
}

test "parseDnsQuestionName: simple domain" {
    const pkt = buildDnsQuery("www.google.com");
    var out: [128]u8 = undefined;
    const result = bpf.parseDnsQuestionName(&pkt, 128, &out);
    try testing.expect(result != null);
    try testing.expectEqualStrings("www.google.com", result.?);
}

test "parseDnsQuestionName: single label" {
    const pkt = buildDnsQuery("localhost");
    var out: [128]u8 = undefined;
    const result = bpf.parseDnsQuestionName(&pkt, 128, &out);
    try testing.expect(result != null);
    try testing.expectEqualStrings("localhost", result.?);
}

test "parseDnsQuestionName: subdomain" {
    const pkt = buildDnsQuery("api.v2.example.co.uk");
    var out: [128]u8 = undefined;
    const result = bpf.parseDnsQuestionName(&pkt, 128, &out);
    try testing.expect(result != null);
    try testing.expectEqualStrings("api.v2.example.co.uk", result.?);
}

test "parseDnsQuestionName: too short packet" {
    const pkt = [_]u8{0} ** 10;
    var out: [128]u8 = undefined;
    const result = bpf.parseDnsQuestionName(&pkt, 10, &out);
    try testing.expect(result == null);
}

test "parseDnsQuestionName: zero data_len" {
    const pkt = [_]u8{0} ** 128;
    var out: [128]u8 = undefined;
    const result = bpf.parseDnsQuestionName(&pkt, 0, &out);
    try testing.expect(result == null);
}

test "parseDnsQuestionName: empty name (only null terminator at offset 12)" {
    var pkt: [128]u8 = .{0} ** 128;
    // Header only, question starts at 12 with a 0 byte (empty name)
    pkt[12] = 0;
    var out: [128]u8 = undefined;
    const result = bpf.parseDnsQuestionName(&pkt, 128, &out);
    try testing.expect(result == null);
}

test "parseDnsQuestionName: label too long (>63)" {
    var pkt: [128]u8 = .{0} ** 128;
    pkt[12] = 64; // label length 64, which is invalid (max 63)
    var out: [128]u8 = undefined;
    const result = bpf.parseDnsQuestionName(&pkt, 128, &out);
    try testing.expect(result == null);
}

test "parseDnsQuestionName: data_len shorter than packet" {
    const pkt = buildDnsQuery("www.google.com");
    var out: [128]u8 = undefined;
    // Only pass 20 bytes — should get truncated name
    const result = bpf.parseDnsQuestionName(&pkt, 20, &out);
    // At offset 12: \x03www\x06go... — "www" then partial "google"
    // With data_len=20, we have bytes 12..19 for the name = 8 bytes
    // \x03 w w w \x06 g o o -> "www.goo" (label "google" truncated at data boundary)
    try testing.expect(result != null);
    // The partial label should still produce some output
    try testing.expect(result.?.len > 0);
}

test "parseDnsQuestionName: small output buffer" {
    const pkt = buildDnsQuery("www.google.com");
    var out: [8]u8 = undefined;
    const result = bpf.parseDnsQuestionName(&pkt, 128, &out);
    try testing.expect(result != null);
    // Should be truncated to fit the output buffer
    try testing.expect(result.?.len <= 8);
}

test "Event.formatAddr: IPv4" {
    var event: Event = std.mem.zeroes(Event);
    event.af = 2;
    // 192.168.1.1 in network byte order (little-endian storage)
    event.addr_v4 = 0x0101A8C0; // 192.168.1.1

    var buf: [64]u8 = undefined;
    const result = try event.formatAddr(&buf);
    try testing.expectEqualStrings("192.168.1.1", result);
}

test "Event.formatAddr: IPv4 loopback" {
    var event: Event = std.mem.zeroes(Event);
    event.af = 2;
    event.addr_v4 = 0x0100007f; // 127.0.0.1

    var buf: [64]u8 = undefined;
    const result = try event.formatAddr(&buf);
    try testing.expectEqualStrings("127.0.0.1", result);
}

test "Event.getComm: null terminated" {
    var event: Event = std.mem.zeroes(Event);
    const name = "curl";
    @memcpy(event.comm[0..name.len], name);
    try testing.expectEqualStrings("curl", event.getComm());
}

test "Event.getComm: full buffer no null" {
    var event: Event = std.mem.zeroes(Event);
    @memset(&event.comm, 'x');
    try testing.expectEqual(@as(usize, 16), event.getComm().len);
}

test "Event struct size matches C" {
    // C struct without __attribute__((packed)):
    // pid(4) + uid(4) + port(2) + af(2) + addr_v4(4) + addr_v6(16) + event_type(1) + comm(16) = 49
    // + 3 bytes trailing padding to align to 4 = 52
    try testing.expectEqual(@as(usize, 52), @sizeOf(Event));
}

// --- DNS query name parsing: real-world wire-format packets ---

test "parseDnsQuestionName: real DNS query for reddit.com" {
    // Manually constructed: header(12) + \x06reddit\x03com\x00
    var pkt: [128]u8 = .{0} ** 128;
    pkt[0] = 0xAA; pkt[1] = 0xBB; // ID
    pkt[2] = 0x01; pkt[3] = 0x00; // flags: standard query
    pkt[4] = 0x00; pkt[5] = 0x01; // qdcount=1
    // Question: \x06reddit\x03com\x00
    pkt[12] = 6;
    @memcpy(pkt[13..19], "reddit");
    pkt[19] = 3;
    @memcpy(pkt[20..23], "com");
    pkt[23] = 0;

    var out: [128]u8 = undefined;
    const result = bpf.parseDnsQuestionName(&pkt, 24, &out);
    try testing.expect(result != null);
    try testing.expectEqualStrings("reddit.com", result.?);
}

test "parseDnsQuestionName: long subdomain chain" {
    const pkt = buildDnsQuery("a.b.c.d.e.f.example.com");
    var out: [128]u8 = undefined;
    const result = bpf.parseDnsQuestionName(&pkt, 128, &out);
    try testing.expect(result != null);
    try testing.expectEqualStrings("a.b.c.d.e.f.example.com", result.?);
}

test "parseDnsQuestionName: domain with hyphens and numbers" {
    const pkt = buildDnsQuery("my-server-01.us-east-1.compute.amazonaws.com");
    var out: [128]u8 = undefined;
    const result = bpf.parseDnsQuestionName(&pkt, 128, &out);
    try testing.expect(result != null);
    try testing.expectEqualStrings("my-server-01.us-east-1.compute.amazonaws.com", result.?);
}

test "parseDnsQuestionName: compressed pointer is rejected" {
    var pkt: [128]u8 = .{0} ** 128;
    pkt[5] = 0x01; // qdcount=1
    pkt[12] = 0xC0; // compression pointer (top 2 bits set)
    pkt[13] = 0x20;

    var out: [128]u8 = undefined;
    const result = bpf.parseDnsQuestionName(&pkt, 128, &out);
    try testing.expect(result == null);
}

test "parseDnsQuestionName: binary garbage is rejected" {
    // Simulate TLS data written to a reused DNS fd
    var pkt: [128]u8 = undefined;
    // Fill with random-looking binary data
    for (&pkt, 0..) |*b, i| b.* = @truncate(i *% 137 +% 42);
    // Even if byte 12 happens to be a valid label length,
    // the label bytes should fail the printable ASCII check
    pkt[12] = 5; // looks like a valid label length

    var out: [128]u8 = undefined;
    const result = bpf.parseDnsQuestionName(&pkt, 128, &out);
    try testing.expect(result == null);
}

test "parseDnsQuestionName: non-ASCII label bytes rejected" {
    var pkt: [128]u8 = .{0} ** 128;
    pkt[5] = 0x01; // qdcount=1
    pkt[12] = 3; // label length
    pkt[13] = 0x80; // non-ASCII byte
    pkt[14] = 0xFF;
    pkt[15] = 0x01;

    var out: [128]u8 = undefined;
    const result = bpf.parseDnsQuestionName(&pkt, 128, &out);
    try testing.expect(result == null);
}

test "EventType includes dns_query variant" {
    const et: EventType = .dns_query;
    try testing.expectEqual(@as(u8, 3), @intFromEnum(et));
}

test "EventType: all variants have correct values" {
    try testing.expectEqual(@as(u8, 0), @intFromEnum(EventType.connect));
    try testing.expectEqual(@as(u8, 1), @intFromEnum(EventType.bind));
    try testing.expectEqual(@as(u8, 2), @intFromEnum(EventType.unbind));
    try testing.expectEqual(@as(u8, 3), @intFromEnum(EventType.dns_query));
}
