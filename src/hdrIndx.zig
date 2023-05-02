//! The HPACK decoder table implementation

const std = @import("std");
const mem = std.mem;
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;
const expectEqualStrings = std.testing.expectEqualStrings;

/// Entries in the static table with both a name and value
pub const StaticIndxBoth = enum(u8) {
    methodGet = 2,
    pathRoot = 4,
    schemeHttp = 6,
    schemeHttps = 7,
    status200 = 8,
    status404 = 13,
};

/// Entries in the static table where just the name is defined
pub const StaticIndxName = enum(u8) {
    authority = 1,
};

/// How a header field is encoded
pub const HdrFieldRepr = enum {
    /// 6.1 Indexed Header Field Representation
    /// Prefix: 1
    indexed,
    /// 6.2.1.  Literal Header Field with Incremental Indexing
    /// Prefix: 01
    indexedNameAddValue,
    addNameAddValue,
    /// 6.2.2.  Literal Header Field without Indexing
    /// Prefix: 0000 or 0001
    indexedNameLitValue,
    litNameLitValue,

    pub fn from(tag: u8) !HdrFieldRepr {
        if (tag & 0b1000_0000 != 0)
            return HdrFieldRepr.indexed;

        if (tag & 0b0100_0000 != 0) {
            if (tag & 0b0011_1111 != 0)
                return HdrFieldRepr.indexedNameAddValue
            else
                return HdrFieldRepr.addNameAddValue;
        }

        if (tag & 0b0010_0000 != 0)
            return error.DynTableSizeUpdate;

        if (tag & 0b0000_1111 != 0)
            return HdrFieldRepr.indexedNameLitValue;

        return HdrFieldRepr.litNameLitValue;
    }
};

/// Union of header field structs used for declaring what data we wish
/// to send.
///
/// We don't bother to add values to the index so they are left as void.
pub const Hdr = union(HdrFieldRepr) {
    indexed: StaticIndxBoth,
    indexedNameAddValue: void,
    indexedNameLitValue: struct { name: StaticIndxName, value: []const u8 },
    addNameAddValue: void,
    litNameLitValue: struct { name: []const u8, value: []const u8 },
};

/// A decoded header field.
pub const HdrConst = struct {
    name: []const u8,
    value: []const u8,
};

/// The content of the table entries; A FIFO buffer.
///
/// It's a buffer with capacity 3x the size of the minimum table size
/// required by HPACK. This allows us to keep adding entries in
/// contiguous chunks with only an occasional copy.
///
/// New entries are added before start and their length subtracted
/// from start.  When start gets below the minimum table size,
/// everything is shifted backwards.
///
/// Only 2X the table size would be needed except that a new entry can
/// reference the index of an entry which is about to be removed.
const HdrData = struct {
    /// The start of the first entry (most recently added)
    start: u16 = 2 * 4096,
    /// Where the start was at the previous copy to shift everything backwards.
    /// Needed to correct indexes for copied items.
    prevStart: u16 = 3 * 4096,
    /// The length of the current entries
    len: u16 = 0,
    /// The data
    vec: [3 * 4096]u8 = undefined,
};

/// An entry in the table data. Sort of like a slice, but using
/// 16-bit indexes.
const HdrPtr = struct {
    start: u16,
    nameLen: u16,
    valueLen: u16,
};

/// An inner table indexing the table's entries. Needed because the
/// entries are uneven.
const HdrIndx = struct {
    start: u8 = 127,
    len: u8 = 0,
    vec: [256]HdrPtr = undefined,
};

/// The encapsulating Table struct because I forgot that files in Zig
/// are structs.
pub const Table = struct {
    data: HdrData = HdrData{},
    indx: HdrIndx = HdrIndx{},
    size: u16 = 4096,

    fn capacity(self: *Table) u16 {
        return self.data.vec.len / 3;
    }

    /// Get an entry from the table. The returned struct is borrowed
    /// and needs to be copied if it is to be used after it has been
    /// evicted from the table.
    pub fn get(self: *Table, i: u8) !HdrConst {
        const data = &self.data;
        const indx = &self.indx;
        const slen = STATIC_INDX.len;

        if (i == 0)
            return error.InvalidIndexZero;

        if (i < slen)
            return STATIC_INDX[i];

        if (i - slen >= indx.len) {
            return error.IndexTooBig;
        }

        const hdr = indx.vec[indx.start + (i - slen)];
        const start = if (hdr.start < data.start)
            2 * self.capacity() + (hdr.start - data.prevStart)
        else
            hdr.start;

        const value_start = start + hdr.nameLen;

        return .{
            .name = data.vec[start..value_start],
            .value = data.vec[value_start .. value_start + hdr.valueLen],
        };
    }

    /// The length of the table according to the HPACK spec
    fn nominalLen(self: *Table, name: []const u8, value: []const u8) usize {
        const estimated_overhead = 32 * (1 + @as(usize, self.indx.len));

        return self.data.len + name.len + value.len + estimated_overhead;
    }

    /// Add an entry to the table. The name and value arguments can
    /// point to an existing entry which will evict itself.
    pub fn add(self: *Table, name: []const u8, value: []const u8) !void {
        const data = &self.data;
        const indx = &self.indx;

        while (self.nominalLen(name, value) > self.size) {
            if (indx.len == 0)
                return;

            const last = indx.vec[indx.start + indx.len - 1];

            data.len -= last.nameLen + last.valueLen;
            indx.len -= 1;
        }

        if (indx.start == 0) {
            mem.copy(HdrPtr, indx.vec[128..], indx.vec[0..128]);
            indx.start = 128;
        }

        indx.len += 1;
        indx.start -= 1;

        const hdr = &indx.vec[indx.start];
        hdr.nameLen = @truncate(u16, name.len);
        hdr.valueLen = @truncate(u16, value.len);

        data.start -= hdr.nameLen;
        data.start -= hdr.valueLen;
        hdr.start = data.start;

        data.len += hdr.nameLen;
        data.len += hdr.valueLen;

        const value_start = hdr.start + hdr.nameLen;

        mem.copy(u8, data.vec[hdr.start..value_start], name);
        mem.copy(u8, data.vec[value_start .. value_start + hdr.valueLen], value);

        if (data.start < self.capacity()) {
            mem.copyBackwards(
                u8,
                data.vec[2 * self.capacity() ..],
                data.vec[data.start .. data.start + data.len],
            );
            data.prevStart = data.start;
            data.start = 2 * self.capacity();
        }
    }
};

test "Add item" {
    var table = Table{};

    try table.add(":path", "/");
    const hdr = try table.get(62);

    try expect(table.indx.len == 1);
    try expectEqualStrings(":path", hdr.name);
    try expectEqualStrings("/", hdr.value);
}

test "Add items" {
    var table = Table{};
    var names = std.ArrayList([6]u8).init(std.testing.allocator);
    var values = std.ArrayList([7]u8).init(std.testing.allocator);
    var i: u8 = 0;
    var last_k: u8 = 0;

    while (i < 265 - 62) : (i += 1) {
        try table.add(
            try std.fmt.bufPrint(try names.addOne(), "name{x:0<2}", .{i}),
            try std.fmt.bufPrint(try values.addOne(), "value{x:0<2}", .{i}),
        );

        var j: u8 = 0;
        while (j <= i) : (j += 1) {
            const k = i - j;

            if (k > 193)
                continue;

            const hdr = table.get(62 + k) catch |e| {
                if (e != error.IndexTooBig)
                    return e;

                try expect((1 + k) * @as(usize, 32 + 6 + 7) > 4096);
                last_k = k - 1;

                continue;
            };

            try expect(k * @as(usize, 32 + 6 + 7) <= 4096);
            try expectEqualStrings(&names.items[j], hdr.name);
            try expectEqualStrings(&values.items[j], hdr.value);
        }
    }

    // Check we don't evict trailing entries until after we copy them for
    // 4.4.  Entry Eviction When Adding New Entries
    i = 0;
    while (i < 255) : (i += 1) {
        const hdr = try table.get(62 + last_k);
        try table.add(hdr.name, "value??");
    }

    names.deinit();
    values.deinit();
}

test "Add big items" {
    var table = Table{};
    var name = [_]u8{'$'} ** 64;
    var value = [_]u8{'%'} ** 1024;
    var i: u16 = 62;

    while (i < 256) : (i += 1) {
        _ = try std.fmt.bufPrint(&name, "name{x}", .{i});
        _ = try std.fmt.bufPrint(&value, "value{x}", .{i});
        try table.add(&name, &value);

        const hdr = try table.get(62);
        try expectEqualStrings(&name, hdr.name);
        try expectEqualStrings(&value, hdr.value);

        if (i > 62)
            _ = try table.get(63);
        if (i > 63)
            _ = try table.get(64);

        try std.testing.expectError(error.IndexTooBig, table.get(65));
    }
}

pub const STATIC_INDX = [62]HdrConst{
    .{ .name = "", .value = "" },
    .{ .name = ":authority", .value = "" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-charset", .value = "" },
    .{ .name = "accept-encoding", .value = "gzip," },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "accept-ranges", .value = "" },
    .{ .name = "accept", .value = "" },
    .{ .name = "access-control-allow-origin", .value = "" },
    .{ .name = "age", .value = "" },
    .{ .name = "allow", .value = "" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "cache-control", .value = "" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-encoding", .value = "" },
    .{ .name = "content-language", .value = "" },
    .{ .name = "content-length", .value = "" },
    .{ .name = "content-location", .value = "" },
    .{ .name = "content-range", .value = "" },
    .{ .name = "content-type", .value = "" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "expect", .value = "" },
    .{ .name = "expires", .value = "" },
    .{ .name = "from", .value = "" },
    .{ .name = "host", .value = "" },
    .{ .name = "if-match", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "if-unmodified-since", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "max-forwards", .value = "" },
    .{ .name = "proxy-authenticate", .value = "" },
    .{ .name = "proxy-authorization", .value = "" },
    .{ .name = "range", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "refresh", .value = "" },
    .{ .name = "retry-after", .value = "" },
    .{ .name = "server", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = "strict-transport-security", .value = "" },
    .{ .name = "transfer-encoding", .value = "" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "vary", .value = "" },
    .{ .name = "via", .value = "" },
    .{ .name = "www-authenticate", .value = "" },
};
