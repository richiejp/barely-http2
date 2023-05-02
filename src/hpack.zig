//! Decodes HPACK headers and encodes them as simply as possible

const std = @import("std");
const Type = std.builtin.Type;
const mem = std.mem;
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectEqualStrings = std.testing.expectEqualStrings;
const print = std.debug.print;
const xtob = std.fmt.hexToBytes;

const ENHUFF = @import("huff.zig").ENHUFF;
const DEHUFF = @import("huff.zig").DEHUFF;

const hdrIndx = @import("hdrIndx.zig");
const HdrFieldRepr = hdrIndx.HdrFieldRepr;
const HdrConst = hdrIndx.HdrConst;
const Hdr = hdrIndx.Hdr;
const STATIC_INDX = hdrIndx.STATIC_INDX;

/// An iterator that takes I/O buffers, a decoding table and returns
/// header entries. The table is mutated so you can't run the iterator
/// twice.
pub const Decoder = struct {
    /// buffer containing the encoded data
    from: []const u8,
    /// A scratch buffer for decoded headers
    to: []u8,
    table: hdrIndx.Table = hdrIndx.Table{},

    pub fn init(from: []const u8, to: []u8) Decoder {
        return .{
            .from = from,
            .to = to,
        };
    }

    pub fn newData(self: *Decoder, from: []const u8, to: []u8) void {
        self.from = from;
        self.to = to;
    }

    /// Get the next header. The contents of the header may be
    /// borrowed from the scratch buffer or the table's buffer.
    pub fn next(self: *Decoder) !HdrConst {
        if (self.from.len < 1)
            return error.EndOfData;

        const table = &self.table;
        const tag = self.from[0];
        const repr = try HdrFieldRepr.from(tag);

        switch (repr) {
            .indexed => {
                const i = try decodeInt(u8, 7, &self.from);
                return table.get(i);
            },
            .indexedNameAddValue => {
                const i = try decodeInt(u8, 6, &self.from);
                const ihdr = try table.get(i);
                const hdr = .{
                    .name = ihdr.name,
                    .value = try decodeStr(&self.from, &self.to),
                };

                try table.add(hdr.name, hdr.value);

                return hdr;
            },
            .indexedNameLitValue => {
                const i = try decodeInt(u8, 4, &self.from);
                const ihdr = try table.get(i);
                const hdr = .{
                    .name = ihdr.name,
                    .value = try decodeStr(&self.from, &self.to),
                };

                return hdr;
            },
            .addNameAddValue, .litNameLitValue => {
                self.from = self.from[1..];

                const hdr: HdrConst = .{
                    .name = try decodeStr(&self.from, &self.to),
                    .value = try decodeStr(&self.from, &self.to),
                };

                if (repr == .addNameAddValue)
                    try table.add(hdr.name, hdr.value);

                return hdr;
            },
        }
    }
};

/// Very lazy HPACK encoder
pub const Encoder = struct {
    to: []u8,
    used: usize = 0,

    pub fn init(to: []u8) Encoder {
        return .{ .to = to };
    }

    pub fn next(self: *Encoder, hdr: Hdr) !usize {
        if (self.to.len == self.used)
            return error.ToBufferEmpty;

        switch (hdr) {
            .indexed => |indx| {
                const used = try encodeInt(7, @enumToInt(indx), self.to[self.used..]);
                self.to[self.used] |= 0x80;
                self.used += used;
            },
            else => unreachable,
        }

        return self.used;
    }
};

const UnpackError = error{
    IntTooBig,
};

/// Get the unsigned type big enough to count the bits in T. Needed
/// because Zig constrains the right hand side of a shift to an
/// integer only big enough to perform a full shift. Which is only u3
/// for u8 (for e.g.).
///
/// Meanwhile I don't know a way to specify this type other than to
/// construct it like this.
fn ShiftSize(comptime T: type) type {
    const ShiftInt = Type{
        .Int = .{
            .signedness = std.builtin.Signedness.unsigned,
            .bits = comptime std.math.log2_int(u16, @bitSizeOf(T)),
        },
    };

    return @Type(ShiftInt);
}

fn decodeInt(comptime T: type, comptime n: u3, buf: *[]const u8) !T {
    const prefix = (1 << n) - 1;
    var b = buf.*[0];
    var i: T = b & prefix;

    if (i < prefix) {
        buf.* = buf.*[1..];
        return i;
    }

    var j: ShiftSize(T) = 1;
    while ((j - 1) * 7 < @bitSizeOf(T)) : (j += 1) {
        b = buf.*[j];

        i += @as(T, (b & 0x7f)) << (7 * (j - 1));

        if (b < 0x80)
            break;
    } else {
        return UnpackError.IntTooBig;
    }

    buf.* = buf.*[j + 1 ..];
    return i;
}

fn encodeInt(comptime n: u3, val: anytype, buf: []u8) !usize {
    const vtype = @TypeOf(val);
    const prefix: u8 = (1 << n) - 1;

    if (val < prefix) {
        buf[0] &= ~prefix;
        buf[0] |= @truncate(u8, val);
        return 1;
    }

    buf[0] |= prefix;

    var i: vtype = val - prefix;
    var k: usize = 1;

    while (true) {
        buf[k] = 0x80 | @truncate(u8, i);

        i >>= 7;
        k += 1;

        if (i == 0)
            break;
    }

    buf[k - 1] &= 0x7f;

    return k;
}

/// Decode a string which if it is not Huffman encoded is fairly
/// straight forward.
///
/// If it is Huffman encoded then we have to deal with the fact
/// Huffman codes are not byte aligned and are variable length.
///
/// We could put the huffman codes in a binary tree and lookup one bit
/// at a time. However I doubt this is the right place to start on
/// common CPUs.
///
/// So instead we shift (at most) the next four bytes into a
/// buffer. Then compare the first bits of the first byte to the
/// shortest huffman codes. If it doesn't match any, then move on to
/// longer codes until we are comparing all four bytes.
///
/// I haven't done any research into the fastest methods of Huffman
/// decoding. This is just a first approximation.
fn decodeStr(from: *[]const u8, to: *[]u8) ![]const u8 {
    const huffman = from.*[0] & 0x80 == 0x80;
    const len = try decodeInt(u16, 7, from);
    const str = from.*[0..len];

    from.* = from.*[len..];

    if (!huffman)
        return str;

    var i: u16 = 0;
    var j: u32 = 0;
    var k: u16 = 0;
    var c = [_]u8{0} ** 5;

    all: while (i < len) {
        mem.copy(u8, &c, str[i..std.math.min(i + 5, str.len)]);

        const j_rem = @truncate(u3, j);

        var l: u3 = 0;
        while (j_rem > 0 and l < c.len - 1) : (l += 1) {
            c[l] <<= j_rem;
            c[l] |= c[l + 1] >> @truncate(u3, 8 - @as(u4, j_rem));
        }

        var glen: u5 = 0;
        const dehuff = decode: for (DEHUFF) |group| {
            glen = 1 + ((group.len - 1) >> 3);

            if (glen != group.codes[0].code.len)
                return error.GlenWrongLen;

            const bits_left = str.len * 8 - j;
            if (bits_left < group.len) {
                if (glen > 1 or j_rem < 1)
                    return error.HuffNoMatchInputEndedEarly;

                const pad_mask = @truncate(u8, @as(u16, 0xff00) >> @truncate(u4, bits_left));
                if (c[0] & pad_mask == pad_mask)
                    break :all
                else
                    return error.HuffInvalidPadding;
            }

            const glen_rem = @truncate(u3, group.len);
            const last_mask = if (glen_rem == 0)
                0xff
            else
                @truncate(u8, @as(u16, 0xff00) >> glen_rem);
            const last = c[glen - 1];

            for (group.codes) |huff| {
                if (huff.code[glen - 1] != last_mask & last)
                    continue;

                if (mem.eql(u8, huff.code[0 .. glen - 1], c[0 .. glen - 1]))
                    break :decode huff;
            }
        } else {
            return error.HuffNoMatch;
        };

        j += dehuff.len;
        i = @truncate(u16, j / 8);

        to.*[k] = dehuff.sym;
        k += 1;
    }

    const ret = to.*[0..k];
    to.* = to.*[k..];

    return ret;
}

test "decode plain string" {
    var to = [_]u8{126} ** 16;
    var tos: []u8 = to[0..];
    const str = [_]u8{0x07} ++ "Wibble!";
    var strs: []const u8 = str[0..];

    try expectEqualStrings("Wibble!", try decodeStr(&strs, &tos));

    const str1 = [_]u8{ 0x7f, 0x17 } ++ ("Wibble, wobble!" ** 10);
    strs = str1[0..];

    try expectEqualStrings(("Wibble, wobble!" ** 10), try decodeStr(&strs, &tos));
}

test "decode Huffman letter" {
    var to = [_]u8{126} ** 16;
    var tos: []u8 = to[0..];
    const str = [_]u8{ 0x81, 0x1f };
    var strs: []const u8 = str[0..];

    try expectEqualStrings("a", try decodeStr(&strs, &tos));
}

test "decode Huffman string" {
    var to = [_]u8{0x00} ** 16;
    var tos: []u8 = to[0..];
    const str = [_]u8{ 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    var strs: []const u8 = str[0..];

    try expectEqualStrings("www.example.com", try decodeStr(&strs, &tos));
}

test "decode prefix int" {
    var buf = [_]u8{ 0x6f, 0x7f, 0x7f, 0x01 };
    var slice: []const u8 = buf[0..];

    try expect(try decodeInt(u8, 7, &slice) == 0x6f);
    try expect(slice[0] == 0x7f);
    try expect(slice.len == 3);

    slice = buf[0..];
    buf[0] = 0x7f;
    try expect(try decodeInt(u16, 7, &slice) == 0xfe);
    try expect(slice.len == 2);

    const buf2 = [_]u8{ 0x1f, 0xff, 0xff, 0x01 };
    slice = buf2[0..];
    try expectEqual(@as(u32, 0x1f + 0x7f + (0x7f << 7) + (0x01 << 14)), try decodeInt(u32, 5, &slice));

    const buf3 = [_]u8{0x05};
    slice = buf3[0..];
    try expectEqual(@as(u32, 0x05), try decodeInt(u32, 4, &slice));
}

test "encode prefix int" {
    var buf = [_]u8{0xff} ** 8;

    try expectEqual(@as(usize, 2), try encodeInt(7, @as(u8, 0x7f), &buf));
    try expect(buf[0] == 0xff);

    buf[0] = 0x00;
    try expect(try encodeInt(7, @as(u16, 0x6f), &buf) == 1);
    try expect(buf[0] == 0x6f);

    buf[0] = 0xe0;
    try expect(try encodeInt(5, @as(u32, 0xff), &buf) == 3);
    try expect(buf[0] == 0xff);
    try expectEqual(@as(u8, 0xe0), buf[1]);
    try expect(buf[2] == 0x01);
    try expect(buf[3] == 0xff);

    buf[0] = 0x00;
    try expect(try encodeInt(5, @as(u8, 0xff), &buf) == 3);
    try expect(buf[0] == 0x1f);
    try expect(buf[1] == 0xe0);
    try expect(buf[2] == 0x01);
    try expect(buf[3] == 0xff);

    buf[0] = 0x00;
    try expect(try encodeInt(7, @as(u8, 0x7f), &buf) == 2);
    try expectEqual(@as(u8, 0x7f), buf[0]);
    try expectEqual(@as(u8, 0x00), buf[1]);

    buf[0] = 0xff;
    try expect(try encodeInt(4, @as(u8, 0x05), &buf) == 1);
    try expectEqual(@as(u8, 0xf5), buf[0]);
}

test "encode decode prefix int" {
    var buf = [_]u8{0xff} ** 16;
    var i: u32 = 2;
    var j: u32 = 3;
    var k: u32 = 5;

    while (k < ~@as(u32, 0) - (j + i)) : ({
        const n = i + j;

        i = j;
        j = k;
        k = n;
    }) {
        const used = try encodeInt(4, @as(u32, k), &buf);
        var slice: []const u8 = buf[0..used];
        try expectEqual(k, try decodeInt(u32, 4, &slice));
    }

    const max_int = ~@as(u64, 0);
    const used = try encodeInt(7, max_int, &buf);
    var slice: []const u8 = buf[0..used];
    try expectEqual(max_int, try decodeInt(u64, 7, &slice));
}

fn initTestDec(req_hex: []const u8) !Decoder {
    const S = struct {
        var from_buf: [4096]u8 = .{0xaa} ** 4096;
        var to_buf: [4096]u8 = .{0x55} ** 4096;
    };
    const from = try xtob(&S.from_buf, req_hex);

    return Decoder.init(from, &S.to_buf);
}

fn expectNext(dec: *Decoder, name: []const u8, value: []const u8) !void {
    const hdr = try dec.next();

    try expectEqualStrings(name, hdr.name);
    try expectEqualStrings(value, hdr.value);
}

fn expectSeq(dec: *Decoder, hdrs: []const [2][]const u8) !void {
    for (hdrs) |hdr| {
        try expectNext(dec, hdr[0], hdr[1]);
    }
}

test "C.2.1. Literal Header Field with Indexing" {
    var dec = try initTestDec("400a637573746f6d2d6b65790d637573746f6d2d686561646572");

    try expectNext(&dec, "custom-key", "custom-header");
}

test "C.2.2. Literal Header Field without Indexing" {
    var dec = try initTestDec("040c2f73616d706c652f70617468");

    try expectNext(&dec, ":path", "/sample/path");
}

test "C.2.3. Literal Header Field Never Indexed" {
    var dec = try initTestDec("100870617373776f726406736563726574");

    try expectEqual(dec.table.indx.len, 0);
    try expectNext(&dec, "password", "secret");
}

test "C.2.4. Indexed Header Field" {
    var dec = try initTestDec("82");

    try expectNext(&dec, ":method", "GET");
}

fn expectReqSeq(dec: *Decoder) !void {
    try expectSeq(dec, &.{
        .{ ":method", "GET" },
        .{ ":scheme", "http" },
        .{ ":path", "/" },
        .{ ":authority", "www.example.com" },
    });

    try expectSeq(dec, &.{
        .{ ":method", "GET" },
        .{ ":scheme", "http" },
        .{ ":path", "/" },
        .{ ":authority", "www.example.com" },
        .{ "cache-control", "no-cache" },
    });

    try expectSeq(dec, &.{
        .{ ":method", "GET" },
        .{ ":scheme", "https" },
        .{ ":path", "/index.html" },
        .{ ":authority", "www.example.com" },
        .{ "custom-key", "custom-value" },
    });
}

test "C.3. Request Examples without Huffman Coding" {
    const hex =
        "828684410f7777772e6578616d706c652e636f6d" ++
        "828684be58086e6f2d6361636865" ++
        "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565";

    var dec = try initTestDec(hex);
    try expectReqSeq(&dec);
}

test "C.4.  Request Examples with Huffman Coding" {
    const hex =
        "828684418cf1e3c2e5f23a6ba0ab90f4ff" ++
        "828684be5886a8eb10649cbf" ++
        "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf";
    var dec = try initTestDec(hex);
    try expectReqSeq(&dec);
}

fn expectRespSeq(dec: *Decoder) !void {
    try expectSeq(dec, &.{
        .{ ":status", "302" },
        .{ "cache-control", "private" },
        .{ "date", "Mon, 21 Oct 2013 20:13:21 GMT" },
        .{ "location", "https://www.example.com" },
    });

    try expectSeq(dec, &.{
        .{ ":status", "307" },
        .{ "cache-control", "private" },
        .{ "date", "Mon, 21 Oct 2013 20:13:21 GMT" },
        .{ "location", "https://www.example.com" },
    });

    try expectSeq(dec, &.{
        .{ ":status", "200" },
        .{ "cache-control", "private" },
        .{ "date", "Mon, 21 Oct 2013 20:13:22 GMT" },
        .{ "location", "https://www.example.com" },
        .{ "content-encoding", "gzip" },
        .{ "set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" },
    });
}

test "C.5.  Response Examples without Huffman Coding" {
    const hex =
        "4803333032580770726976617465611d4d6f6e2c203231204f63742032303133" ++
        "2032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d70" ++
        "6c652e636f6d" ++
        "4803333037c1c0bf" ++
        "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d" ++
        "54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f5049" ++
        "5541585157454f49553b206d61782d6167653d333630303b2076657273696f6e" ++
        "3d31";
    var dec = try initTestDec(hex);
    dec.table.size = 256;

    try expectRespSeq(&dec);
}

test "C.6.  Response Examples with Huffman Coding" {
    const hex =
        "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a6" ++
        "2d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3" ++
        "4883640effc1c0bf" ++
        "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab" ++
        "77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f" ++
        "9587316065c003ed4ee5b1063d5007";
    var dec = try initTestDec(hex);
    dec.table.size = 256;

    try expectRespSeq(&dec);
}
