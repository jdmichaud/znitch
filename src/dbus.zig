const std = @import("std");

const Header = struct {
    endian: u8 = 'l', // little-endian
    msg_type: u8,
    flags: u8 = 0,
    version: u8 = 1,
    body_len: u32 = 0,
    serial: u32,
    fields_len: u32 = 0,
};

const METHOD_CALL = 1;
const METHOD_RETURN = 2;

// Header field codes
const FIELD_PATH = 1;
const FIELD_INTERFACE = 2;
const FIELD_MEMBER = 3;
const FIELD_DESTINATION = 6;
const FIELD_SIGNATURE = 8;

/// Fixed-size D-Bus message buffer.
pub const Message = struct {
    buf: [4096]u8 = undefined,
    len: usize = 0,

    fn pad(self: *Message, a: usize) void {
        while (self.len % a != 0) {
            self.buf[self.len] = 0;
            self.len += 1;
        }
    }

    fn writeByte(self: *Message, v: u8) void {
        self.buf[self.len] = v;
        self.len += 1;
    }

    fn writeU32(self: *Message, v: u32) void {
        self.pad(4);
        std.mem.writeInt(u32, self.buf[self.len..][0..4], v, .little);
        self.len += 4;
    }

    fn writeI32(self: *Message, v: i32) void {
        self.pad(4);
        std.mem.writeInt(i32, self.buf[self.len..][0..4], v, .little);
        self.len += 4;
    }

    fn writeString(self: *Message, s: []const u8) void {
        self.writeU32(@intCast(s.len));
        @memcpy(self.buf[self.len .. self.len + s.len], s);
        self.len += s.len;
        self.writeByte(0); // nul terminator
    }

    /// Write an empty array with correct padding for element alignment.
    /// D-Bus spec: even empty arrays must pad to the element type's alignment.
    fn writeEmptyArray(self: *Message, element_alignment: usize) void {
        self.writeU32(0); // array length = 0
        self.pad(element_alignment); // pad to element alignment per spec
    }

    fn writeSignature(self: *Message, s: []const u8) void {
        self.writeByte(@intCast(s.len));
        @memcpy(self.buf[self.len .. self.len + s.len], s);
        self.len += s.len;
        self.writeByte(0);
    }

    pub fn data(self: *const Message) []const u8 {
        return self.buf[0..self.len];
    }
};

/// Build D-Bus header fields array for a method call.
fn buildHeaderFields(msg: *Message, path: []const u8, interface: []const u8, member: []const u8, destination: []const u8, body_sig: []const u8) void {
    // Reserve space for fields array length
    const fields_len_offset = msg.len;
    msg.writeU32(0); // placeholder

    const fields_start = msg.len;

    // PATH (1) = OBJECT_PATH
    msg.pad(8);
    msg.writeByte(FIELD_PATH);
    msg.writeSignature("o");
    msg.writeString(path);

    // INTERFACE (2) = STRING
    msg.pad(8);
    msg.writeByte(FIELD_INTERFACE);
    msg.writeSignature("s");
    msg.writeString(interface);

    // MEMBER (3) = STRING
    msg.pad(8);
    msg.writeByte(FIELD_MEMBER);
    msg.writeSignature("s");
    msg.writeString(member);

    // DESTINATION (6) = STRING
    msg.pad(8);
    msg.writeByte(FIELD_DESTINATION);
    msg.writeSignature("s");
    msg.writeString(destination);

    // SIGNATURE (8) = SIGNATURE
    if (body_sig.len > 0) {
        msg.pad(8);
        msg.writeByte(FIELD_SIGNATURE);
        msg.writeSignature("g");
        msg.writeSignature(body_sig);
    }

    // Write actual fields length
    const fields_len: u32 = @intCast(msg.len - fields_start);
    std.mem.writeInt(u32, msg.buf[fields_len_offset..][0..4], fields_len, .little);

    // Pad to 8-byte boundary before body
    msg.pad(8);
}

/// Build a complete D-Bus method call message.
pub fn buildMethodCall(serial: u32, path: []const u8, interface: []const u8, member: []const u8, destination: []const u8, body_sig: []const u8, body: []const u8) Message {
    var msg = Message{};

    // Fixed header (12 bytes, body_len filled later)
    msg.writeByte('l'); // little-endian
    msg.writeByte(METHOD_CALL);
    msg.writeByte(0); // flags
    msg.writeByte(1); // protocol version
    msg.writeU32(0); // body length placeholder (offset 4)
    msg.writeU32(serial);

    buildHeaderFields(&msg, path, interface, member, destination, body_sig);

    // Write body length at offset 4
    std.mem.writeInt(u32, msg.buf[4..8], @intCast(body.len), .little);

    // Append body
    @memcpy(msg.buf[msg.len .. msg.len + body.len], body);
    msg.len += body.len;

    return msg;
}

/// Build the message body for org.freedesktop.Notifications.Notify.
/// Signature: susssasa{sv}i
pub fn buildNotifyBody(app_name: []const u8, replaces_id: u32, summary: []const u8, body_text: []const u8, timeout: i32) Message {
    var msg = Message{};

    msg.writeString(app_name); // s: app_name
    msg.writeU32(replaces_id); // u: replaces_id
    msg.writeString(""); // s: app_icon
    msg.writeString(summary); // s: summary
    msg.writeString(body_text); // s: body
    msg.writeEmptyArray(4); // as: empty actions (string elements have 4-byte alignment)
    msg.writeEmptyArray(8); // a{sv}: empty hints (dict entry elements have 8-byte alignment)
    msg.writeI32(timeout); // i: expire_timeout

    return msg;
}

/// Build the message body for CloseNotification. Signature: u
pub fn buildCloseBody(notification_id: u32) Message {
    var msg = Message{};
    msg.writeU32(notification_id);
    return msg;
}

/// Parse a METHOD_RETURN reply to extract a UINT32 value (notification ID).
pub fn parseReplyU32(data: []const u8) ?u32 {
    if (data.len < 16) return null;
    if (data[0] != 'l') return null; // only little-endian
    if (data[1] != METHOD_RETURN) return null;

    const body_len = std.mem.readInt(u32, data[4..8], .little);
    const fields_len = std.mem.readInt(u32, data[12..16], .little);

    // Header fields start at offset 16, then padded to 8
    var body_start: usize = 16 + fields_len;
    body_start = (body_start + 7) & ~@as(usize, 7); // align to 8

    if (body_start + 4 > data.len or body_len < 4) return null;

    return std.mem.readInt(u32, data[body_start..][0..4], .little);
}

// --- Tests ---

test "Message: writeString" {
    var msg = Message{};
    msg.writeString("hello");
    // length(4) + "hello"(5) + nul(1) = 10 bytes
    try std.testing.expectEqual(@as(usize, 10), msg.len);
    try std.testing.expectEqual(@as(u32, 5), std.mem.readInt(u32, msg.buf[0..4], .little));
    try std.testing.expectEqualStrings("hello", msg.buf[4..9]);
    try std.testing.expectEqual(@as(u8, 0), msg.buf[9]);
}

test "Message: writeSignature" {
    var msg = Message{};
    msg.writeSignature("su");
    // len_byte(1) + "su"(2) + nul(1) = 4 bytes
    try std.testing.expectEqual(@as(usize, 4), msg.len);
    try std.testing.expectEqual(@as(u8, 2), msg.buf[0]);
}

test "Message: alignment" {
    var msg = Message{};
    msg.writeByte(0x42);
    msg.writeU32(100);
    // 1 byte + 3 padding + 4 bytes = 8
    try std.testing.expectEqual(@as(usize, 8), msg.len);
    try std.testing.expectEqual(@as(u32, 100), std.mem.readInt(u32, msg.buf[4..8], .little));
}

test "buildNotifyBody: byte-level format validation" {
    // Signature: susssasa{sv}i
    // This test validates the exact wire format to prevent regressions.
    const body = buildNotifyBody("znitch", 0, "Hi", "Bye", 5000);
    const d = body.data();

    var pos: usize = 0;

    // s: app_name = "znitch" (6 bytes)
    try std.testing.expectEqual(@as(u32, 6), std.mem.readInt(u32, d[pos..][0..4], .little));
    pos += 4;
    try std.testing.expectEqualStrings("znitch", d[pos .. pos + 6]);
    pos += 6 + 1; // + nul

    // u: replaces_id = 0 (pad to 4)
    pos = (pos + 3) & ~@as(usize, 3); // align to 4
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, d[pos..][0..4], .little));
    pos += 4;

    // s: app_icon = "" (0 bytes)
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, d[pos..][0..4], .little));
    pos += 4 + 0 + 1; // len + data + nul

    // s: summary = "Hi" (2 bytes, pad to 4 first)
    pos = (pos + 3) & ~@as(usize, 3);
    try std.testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, d[pos..][0..4], .little));
    pos += 4;
    try std.testing.expectEqualStrings("Hi", d[pos .. pos + 2]);
    pos += 2 + 1;

    // s: body = "Bye" (3 bytes, pad to 4 first)
    pos = (pos + 3) & ~@as(usize, 3);
    try std.testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, d[pos..][0..4], .little));
    pos += 4;
    try std.testing.expectEqualStrings("Bye", d[pos .. pos + 3]);
    pos += 3 + 1;

    // as: empty actions array (pad to 4, then UINT32 length = 0, pad to 4 for string alignment)
    pos = (pos + 3) & ~@as(usize, 3);
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, d[pos..][0..4], .little));
    pos += 4;
    // Element alignment for 's' is 4 — we're already 4-aligned after the UINT32

    // a{sv}: empty hints dict (pad to 4, UINT32 length = 0, then pad to 8 for dict entry alignment)
    pos = (pos + 3) & ~@as(usize, 3);
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, d[pos..][0..4], .little));
    pos += 4;
    // Element alignment for '{sv}' is 8 — pad to 8
    pos = (pos + 7) & ~@as(usize, 7);

    // i: expire_timeout = 5000
    pos = (pos + 3) & ~@as(usize, 3);
    try std.testing.expectEqual(@as(i32, 5000), std.mem.readInt(i32, d[pos..][0..4], .little));
    pos += 4;

    // Should have consumed exactly the whole body
    try std.testing.expectEqual(pos, d.len);
}

test "writeEmptyArray: element alignment padding" {
    // a{sv} (dict entries have 8-byte alignment): UINT32(0) + pad to 8
    var msg = Message{};
    msg.writeEmptyArray(8);
    // UINT32(0) at offset 0 = 4 bytes, then pad to 8 = 4 more bytes
    try std.testing.expectEqual(@as(usize, 8), msg.len);

    // as (strings have 4-byte alignment): UINT32(0), no extra padding needed
    var msg2 = Message{};
    msg2.writeEmptyArray(4);
    // UINT32(0) at offset 0 = 4 bytes, already 4-aligned
    try std.testing.expectEqual(@as(usize, 4), msg2.len);

    // Verify padding is zeroed
    for (msg.data()) |b| {
        try std.testing.expectEqual(@as(u8, 0), b);
    }
}

test "buildMethodCall: Hello message structure" {
    const msg = buildMethodCall(
        1,
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "Hello",
        "org.freedesktop.DBus",
        "",
        "",
    );
    const d = msg.data();

    // Fixed header
    try std.testing.expectEqual(@as(u8, 'l'), d[0]); // endian
    try std.testing.expectEqual(@as(u8, METHOD_CALL), d[1]); // type
    try std.testing.expectEqual(@as(u8, 0), d[2]); // flags
    try std.testing.expectEqual(@as(u8, 1), d[3]); // version
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, d[4..8], .little)); // body_len
    try std.testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, d[8..12], .little)); // serial

    // Header fields array length
    const fields_len = std.mem.readInt(u32, d[12..16], .little);
    try std.testing.expect(fields_len > 0);

    // Total message must be 8-byte aligned
    try std.testing.expectEqual(@as(usize, 0), d.len % 8);

    // First header field starts at offset 16, should be PATH(1)
    try std.testing.expectEqual(@as(u8, FIELD_PATH), d[16]);
}

test "buildMethodCall: message total is 8-byte aligned" {
    const body_data = buildNotifyBody("znitch", 0, "Title", "Body text", 5000);
    const msg = buildMethodCall(
        2,
        "/org/freedesktop/Notifications",
        "org.freedesktop.Notifications",
        "Notify",
        "org.freedesktop.Notifications",
        "susssasa{sv}i",
        body_data.data(),
    );

    // Header (before body) must be 8-byte aligned
    const fields_len = std.mem.readInt(u32, msg.buf[12..16], .little);
    const header_end = 16 + fields_len;
    const body_start = (header_end + 7) & ~@as(usize, 7);
    try std.testing.expectEqual(@as(usize, 0), body_start % 8);

    // Body length in header must match actual body
    const body_len = std.mem.readInt(u32, msg.buf[4..8], .little);
    try std.testing.expectEqual(body_data.len, body_len);
    try std.testing.expectEqual(body_start + body_len, msg.len);
}

test "parseReplyU32: valid reply" {
    // Build a fake METHOD_RETURN with body containing u32 = 42
    var buf: [64]u8 = .{0} ** 64;
    buf[0] = 'l'; // little-endian
    buf[1] = METHOD_RETURN;
    buf[2] = 0; // flags
    buf[3] = 1; // version
    std.mem.writeInt(u32, buf[4..8], 4, .little); // body_len = 4
    std.mem.writeInt(u32, buf[8..12], 1, .little); // serial
    std.mem.writeInt(u32, buf[12..16], 0, .little); // fields_len = 0
    // Body at offset 16 (aligned to 8 already)
    std.mem.writeInt(u32, buf[16..20], 42, .little);

    const result = parseReplyU32(&buf);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(u32, 42), result.?);
}

test "parseReplyU32: too short" {
    const buf = [_]u8{0} ** 10;
    try std.testing.expect(parseReplyU32(&buf) == null);
}
