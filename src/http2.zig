const std = @import("std");
const mem = std.mem;
const net = std.net;
const assert = std.debug.assert;
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;

const hpack = @import("hpack.zig");
const hdrIndx = @import("hdrIndx.zig");

const FrameType = enum(u8) {
    data,
    headers,
    priority,
    rstStream,
    settings,
    pushPromise,
    ping,
    goAway,
    windowUpdate,
    continuation,
    _,
};

const DataFlags = packed struct {
    endStream: bool,
    unused: u6 = 0,
    padded: bool,
};

const HeadersFlags = packed struct {
    endStream: bool,
    unused1: bool = false,
    endHeaders: bool,
    padded: bool,
    unused2: bool = false,
    priority: bool,
    unused3: u2 = 0,
};

const SettingsFlags = packed struct {
    ack: bool,
    unused: u7 = 0,
};

comptime {
    for (&[_]type{ DataFlags, HeadersFlags, SettingsFlags }) |T| {
        assert(@sizeOf(T) == 1);
    }
}

const FrameFlags = union(enum) {
    data: DataFlags,
    headers: HeadersFlags,
    settings: SettingsFlags,
    unused: u8,
    unknown: u8,
};

pub const FrameHdr = struct {
    length: u24,
    type: FrameType,
    flags: FrameFlags,
    r: bool = false,
    id: u31,

    pub fn from(buf: *const [9]u8) FrameHdr {
        const ftype = @intToEnum(FrameType, buf[3]);

        return .{
            .length = mem.readIntBig(u24, buf[0..3]),
            .type = ftype,
            .flags = switch (ftype) {
                .headers => .{ .headers = @bitCast(HeadersFlags, buf[4]) },
                .settings => .{ .settings = @bitCast(SettingsFlags, buf[4]) },
                .windowUpdate => .{ .unused = buf[4] },
                else => .{ .unknown = buf[4] },
            },
            .r = @bitCast(bool, @truncate(u1, buf[5] >> 7)),
            .id = @intCast(u31, mem.readIntBig(u32, buf[5..9]) & 0x7fffffff),
        };
    }

    pub fn to(self: FrameHdr, buf: []u8) []const u8 {
        mem.writeIntBig(u24, buf[0..3], self.length);
        buf[3] = @enumToInt(self.type);
        buf[4] = switch (self.flags) {
            .data => |flags| @bitCast(u8, flags),
            .headers => @bitCast(u8, self.flags.headers),
            .settings => @bitCast(u8, self.flags.settings),
            else => unreachable,
        };
        // r is always 0
        mem.writeIntBig(u32, buf[5..9], @intCast(u32, self.id));

        return buf[0..9];
    }
};

const DataPayload = struct {
    data: []const u8,
    padding: []const u8,
};

const HeadersPayload = struct {
    headerBlockFragment: []const u8,

    hdec: *hpack.Decoder,

    pub fn init(hdec: *hpack.Decoder, from: []const u8, to: []u8) HeadersPayload {
        hdec.from = from;
        hdec.to = to;

        return .{
            .headerBlockFragment = from,
            .hdec = hdec,
        };
    }

    pub fn next(self: *HeadersPayload) !hdrIndx.HdrConst {
        return self.hdec.next();
    }
};

const HeadersOpts = struct {
    stream_id: u31,
    end_stream: bool,
};

const SettingId = enum(u16) {
    headerTableSize = 0x1,
    enablePush,
    maxConcurrentStreams,
    initialWindowSize,
    maxFrameSize,
    maxHeaderListSize,
};

const Setting = union(SettingId) {
    headerTableSize: u32,
    enablePush: bool,
    maxConcurrentStreams: u32,
    initialWindowSize: u31,
    maxFrameSize: u24,
    maxHeaderListSize: u32,
};

const SettingsPayload = struct {
    settings: []const u8,
    used: usize,

    pub fn init(buf: []const u8) SettingsPayload {
        return .{ .settings = buf, .used = 0 };
    }

    pub fn next(self: *SettingsPayload) !Setting {
        if (self.settings.len - self.used == 0)
            return error.EndOfData;

        if (self.settings.len - self.used < 6)
            return error.UnexpectedEndOfData;

        const buf = self.settings[self.used..][0..6];
        self.used += 6;

        const id = mem.readIntBig(u16, buf[0..2]);
        const val = mem.readIntBig(u32, buf[2..]);

        return switch (id) {
            1 => .{ .headerTableSize = val },
            2 => .{ .enablePush = @bitCast(bool, @intCast(u1, val)) },
            3 => .{ .maxConcurrentStreams = val },
            4 => .{ .initialWindowSize = @intCast(u31, val) },
            5 => .{ .maxFrameSize = @intCast(u24, val) },
            6 => .{ .maxHeaderListSize = val },
            else => error.NoIdeaWhatThatSettingIs,
        };
    }
};

const WindowUpdatePayload = struct {
    r: bool,
    windowSizeIncrement: u31,

    pub fn init(buf: *const [4]u8) WindowUpdatePayload {
        return .{
            .r = @bitCast(bool, @truncate(u1, buf[0] >> 7)),
            .windowSizeIncrement = @intCast(u31, mem.readIntBig(u32, buf) & 0x7fffffff),
        };
    }
};

const Payload = union(enum) {
    headers: HeadersPayload,
    settings: SettingsPayload,
    windowUpdate: WindowUpdatePayload,
    not_implemented: void,
};

pub const Frame = struct {
    hdr: FrameHdr,
    payload: Payload,

    pub fn init(h: FrameHdr, hdec: *hpack.Decoder, from: []const u8, to: []u8) Frame {
        const p: Payload = switch (h.type) {
            .headers => .{ .headers = HeadersPayload.init(hdec, from, to) },
            .settings => .{ .settings = SettingsPayload.init(from) },
            .windowUpdate => .{
                .windowUpdate = WindowUpdatePayload.init(from[0..4]),
            },
            else => .not_implemented,
        };

        return .{ .hdr = h, .payload = p };
    }
};

pub fn Connection(comptime Reader: type, comptime Writer: type) type {
    const preface = [_]u8{
        0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f,
        0x32, 0x2e, 0x30, 0x0d, 0x0a, 0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a,
        0x0d, 0x0a,
    };

    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        frame_in: []u8,
        have: usize = 0,
        used: usize = 0,

        headers_in: []u8,
        hdec: hpack.Decoder,
        frame_out: []u8,

        reader: Reader,
        writer: Writer,

        pub fn init(
            a: std.mem.Allocator,
            buf_len: usize,
        ) !Self {
            return .{
                .allocator = a,
                .frame_in = try a.alloc(u8, buf_len),
                .headers_in = try a.alloc(u8, buf_len),
                .hdec = .{ .from = undefined, .to = undefined },
                .frame_out = try a.alloc(u8, buf_len),
                .reader = undefined,
                .writer = undefined,
            };
        }

        pub fn reinit(self: *Self, r: Reader, w: Writer) void {
            self.have = 0;
            self.used = 0;
            self.reader = r;
            self.writer = w;

            mem.set(u8, self.frame_in, 0);
            mem.set(u8, self.frame_out, 0);
            mem.set(u8, self.headers_in, 0);
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.frame_in);
            self.allocator.free(self.frame_out);
            self.allocator.free(self.headers_in);
        }

        fn read(self: *Self, needed: usize) ![]const u8 {
            var have = self.have - self.used;
            const in = self.frame_in[self.used..];

            const len = if (have < needed)
                try self.reader.readAtLeast(in, needed - have)
            else
                0;

            have += len;
            self.have += len;

            if (have == 0)
                return error.EndOfData;

            if (have < needed)
                return error.UnexpectedEndOfData;

            self.used += needed;

            return in[0..needed];
        }

        pub fn start(self: *Self) !void {
            const pface = try self.read(preface.len);

            if (mem.eql(u8, &preface, pface))
                std.log.info("<<< Got preface!", .{})
            else {
                std.log.info("<<< Expected preface, bug got\n: {s}", .{pface});
                return error.InvalidPreface;
            }

            std.log.info(">>> Sending server preface", .{});
            const empty_settings = FrameHdr{
                .length = 0,
                .type = .settings,
                .flags = .{ .settings = .{ .ack = false } },
                .id = 0,
            };
            try self.writer.writeAll(empty_settings.to(self.frame_out));
        }

        pub fn nextFrameHdr(self: *Self) !FrameHdr {
            return FrameHdr.from((try self.read(9))[0..9]);
        }

        pub fn nextFrame(self: *Self) !Frame {
            const hdr = try self.nextFrameHdr();

            return Frame.init(
                hdr,
                &self.hdec,
                try self.read(hdr.length),
                self.headers_in,
            );
        }

        pub fn sendHeaders(
            self: *Self,
            opts: HeadersOpts,
            headers: []const hdrIndx.Hdr,
        ) !void {
            var henc = hpack.Encoder.init(self.frame_out[9..]);
            var hlen: usize = 0;

            for (headers) |h| hlen += try henc.next(h);

            const out_hdr = FrameHdr{
                .length = @intCast(u24, hlen),
                .type = .headers,
                .flags = .{ .headers = .{
                    .endStream = opts.end_stream,
                    .endHeaders = true,
                    .padded = false,
                    .priority = false,
                } },
                .id = opts.stream_id,
            };
            _ = out_hdr.to(self.frame_out[0..9]);

            try self.writer.writeAll(self.frame_out[0 .. 9 + hlen]);
        }
    };
}

pub const NetConnection = Connection(std.net.Stream, std.net.Stream);

fn serve(h2c: *NetConnection) !void {
    try h2c.start();

    while (h2c.nextFrame()) |frame| {
        std.log.info("<<< {} {}", frame);

        var payload = frame.payload;

        switch (payload) {
            .settings => |*settings| {
                while (settings.next()) |setting| {
                    std.log.info("    {}", .{setting});
                } else |err| {
                    if (err != error.EndOfData) return err;
                }
            },
            .headers => |*headers| {
                while (headers.next()) |h| {
                    std.log.info("    {s} => {s}", h);
                } else |err| {
                    if (err != error.EndOfData) return err;
                }

                std.log.info(">>> Sending 200 OK and end stream", .{});

                try h2c.sendHeaders(.{
                    .end_stream = true,
                    .stream_id = frame.hdr.id,
                }, &.{.{
                    .indexed = .status200,
                }});
            },
            else => {},
        }
    } else |err| {
        if (err != error.EndOfData)
            return err;
    }
}

pub fn main() !void {
    var h2c = try NetConnection.init(std.heap.page_allocator, 1 << 14);
    defer h2c.deinit();

    const self_addr = try net.Address.resolveIp("127.0.0.1", 9001);
    var listener = net.StreamServer.init(.{});
    try listener.listen(self_addr);
    defer listener.close();

    std.log.info("Listening on {}; press Ctrl-C to exit...", .{self_addr});

    while (listener.accept()) |conn| {
        defer conn.stream.close();

        std.log.info("Accepted Connection from: {}", .{conn.address});

        h2c.reinit(conn.stream, conn.stream);

        serve(&h2c) catch |err| {
            if (@errorReturnTrace()) |bt| {
                std.log.err("{}: {}", .{ err, bt });
            } else {
                std.log.err("{}", .{err});
            }
        };
    } else |err| return err;
}

test "Frame header unpacking" {
    var bytes = [_]u8{ 0x00, 0x00, 0xaa } ++
        [_]u8{@enumToInt(FrameType.settings)} ++
        [_]u8{@bitCast(u8, FrameFlags{ .settings = .{ .ack = true } })} ++
        [_]u8{ 0x80, 0x00, 0x00, 0xff };

    const frm = FrameHdr.from(&bytes);
    const efrm = FrameHdr{
        .length = 0xaa,
        .type = .settings,
        .flags = FrameFlags{ .settings = .{ .ack = true } },
        .r = true,
        .id = 255,
    };

    try expectEqual(efrm.type, frm.type);
    try expectEqual(efrm.length, frm.length);
    try expectEqual(efrm.type, frm.type);
    try expectEqual(efrm.flags.settings, frm.flags.settings);

    try expectEqual(efrm.id, frm.id);
}
