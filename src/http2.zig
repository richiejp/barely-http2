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

// In a packed struct bool is one bit in length, so we can represent
// the individual flags as struct fields.

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

/// Tagged union of the frame flags. It's a tagged union for the silly
/// reason that they automatically get printed correctly. The type
/// field in FrameHdr already provides the tag, but I don't think this
/// can be expressed in Zig. There are possible alternatives I haven't
/// tried to avoid this repetition.
const FrameFlags = union(enum) {
    data: DataFlags,
    headers: HeadersFlags,
    settings: SettingsFlags,
    unused: u8,
    unknown: u8,
};

/// All HTTP/2 traffic is made up of frames with a fixed sized header
/// of the same format. Each frame specifies its type and payload
/// length. On an abstract level this makes parsing HTTP/2 traffic
/// easy.
///
/// The only complicatin in Zig being the interactiong between
/// endianess and packed u24. Otherwise we could declare the flags as
/// u8, mark the struct as packed then do a single @ptrCast. I tried
/// something like this, but got in a mess and settled on the below.
pub const FrameHdr = struct {
    /// Length of the frame's payload
    length: u24,
    /// How we should interpret everything that follows
    type: FrameType,
    flags: FrameFlags,
    /// A reserved bit, which we can set to 1 as an act of rebellion.
    r: bool = false,
    /// The stream ID or zero if this frame applies to the connection.
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

/// The payload for a data frame. The padding is only present if the
/// padding flag is set.
const DataPayload = struct {
    data: []const u8,
    padding: []const u8,
};

/// The payload of a headers frame is HPACK encoded. We always need to
/// decode all the headers to make sure the decoding table is correct
/// (unless we stop caring about any headers on this connection).
///
/// This is a one-shot iterator which returns borrowed values. Values
/// returned by next should be copied before calling next again or
/// moving on. The decoder's state is mutated, so the iterator can not
/// be restarted without an old copy of the decoder.
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

/// Settings limit what we can send to the other side. This is
/// essentially an iterator which returns a tagged u32
const SettingsPayload = struct {
    settings: []const u8,

    pub fn init(buf: []const u8) SettingsPayload {
        return .{ .settings = buf };
    }

    pub fn next(self: *SettingsPayload) !Setting {
        if (self.settings.len == 0)
            return error.EndOfData;

        if (self.settings.len < 6)
            return error.UnexpectedEndOfData;

        const buf = self.settings[0..6];

        self.settings = self.settings[6..];

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

/// Rate limiting; we're not supposed to send more data than has been
/// added to the window.
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

/// A partially or fully decoded frame. In some cases the payload
/// field can be used to get an iterator which will complete the
/// decoding.
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

/// HTTP/2's idea of a connection which wraps around the underlying
/// stream.  Usually the underlying stream will be a TCP connection,
/// but could by anything which provides the Reader and Writer
/// interfaces e.g. a file or buffer with captured frame data in.
///
/// This is essentially an iterator interface to the underlying
/// data. Which recurses into iterators for the various types of frame
/// payload.
///
/// It only allocates memory during init and we can reuse the
/// connection object by calling reinit. This preempts the No. 1
/// performance issue I have seen in most open source libraries.
///
/// One should assume that any pointers it returns are to buffers it
/// allocated at init time. So their lifetime is only until the next
/// call to nextFrame[Hdr]. Long lived data therefor needs to be
/// copied. Whether this is an issue depends on the use case.
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

        /// Start the HTTP/2 connection as the server and assuming
        /// "prior knowledge". This is a simple case of reading in the
        /// magic string (preface) sent by the client and sending a
        /// settings frame.
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

        /// Lower level iterator which returns just the frame
        /// header. Potentially this can be used to skip over
        /// uninteresting frames.
        pub fn nextFrameHdr(self: *Self) !FrameHdr {
            return FrameHdr.from((try self.read(9))[0..9]);
        }

        /// Returns a slightly higher level Frame payload iterator and
        /// frame header object. Still pretty low level. We'd probably
        /// want to abstract this into streams and abstract streams
        /// into requests and responses.
        pub fn nextFrame(self: *Self) !Frame {
            const hdr = try self.nextFrameHdr();

            return Frame.init(
                hdr,
                &self.hdec,
                try self.read(hdr.length),
                self.headers_in,
            );
        }

        /// Send a HPACK headers frame with some headers. Nothing todo
        /// with the frame header itself. Totally confusing.
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

/// One of two entry points in this code base, just prints the frames
/// it receives and sends an empty 200 OK response.
pub fn main() !void {
    var h2c = try NetConnection.init(std.heap.page_allocator, 1 << 14);
    defer h2c.deinit();

    const self_addr = try net.Address.resolveIp("127.0.0.1", 9000);
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
