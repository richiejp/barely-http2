// Copyright (c) 2023 Richard Palethorpe <io@richiejp.com>

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

const std = @import("std");
const assert = std.debug.assert;
const net = std.net;
const mem = std.mem;
const fs = std.fs;
const io = std.io;

const http2 = @import("http2.zig");

const ServeFileError = error{
    RecvHeaderEOF,
    PrefixDidNotMatch,
    HeaderDidNotMatch,
    FrameHdrDidNotMatch,
    FrameTooBig,
};

fn sendFile(
    h2c: *http2.NetConnection,
    dir: fs.Dir,
    stream_id: u31,
    path: []const u8,
) !void {
    var file_path: []const u8 = undefined;

    if (path[0] != '/')
        return ServeFileError.HeaderDidNotMatch;

    if (mem.eql(u8, path, "/"))
        file_path = "index"
    else
        file_path = path[1..];

    var file_ext = fs.path.extension(file_path);
    var path_buf: [fs.MAX_PATH_BYTES]u8 = undefined;

    if (file_ext.len == 0) {
        var path_fbs = io.fixedBufferStream(&path_buf);

        try path_fbs.writer().print("{s}.html", .{file_path});
        file_ext = ".html";
        file_path = path_fbs.getWritten();
    }

    std.log.info("*** Opening {s}", .{file_path});

    var body_file = dir.openFile(file_path, .{}) catch |err| {
        try h2c.sendHeaders(.{
            .end_stream = true,
            .stream_id = stream_id,
        }, &.{.{
            .indexed = .status404,
        }});

        return err;
    };
    defer body_file.close();

    std.log.info(">>> Sending OK headers", .{});
    try h2c.sendHeaders(.{
        .end_stream = false,
        .stream_id = stream_id,
    }, &.{.{
        .indexed = .status200,
    }});

    const file_len = try body_file.getEndPos();

    const zero_iovec = &[0]std.os.iovec_const{};
    const max_frame_len = 1 << 14;
    var send_total: usize = 0;

    while (send_total < file_len) {
        const len_left = file_len - send_total;
        const frame_len = std.math.min(max_frame_len, len_left);
        const data_hdr = http2.FrameHdr{
            .length = @intCast(u24, frame_len),
            .type = .data,
            .flags = .{ .data = .{
                .endStream = len_left == frame_len,
                .padded = false,
            } },
            .id = stream_id,
        };
        var data_buf: [9]u8 = undefined;

        std.log.info(">>> Sending DATA {}", .{data_hdr});
        try h2c.writer.writeAll(data_hdr.to(&data_buf));

        var send_len: usize = 0;
        while (send_len < frame_len) {
            send_len += try std.os.sendfile(
                h2c.writer.handle,
                body_file.handle,
                send_total,
                frame_len - send_len,
                zero_iovec,
                zero_iovec,
                0,
            );
        }

        send_total += send_len;
    }

    std.log.info(">>> Sent {} file bytes", .{send_total});
}

fn serveFiles(h2c: *http2.NetConnection, dir: fs.Dir) !void {
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
                var path: ?[]const u8 = null;

                while (headers.next()) |h| {
                    std.log.info("    {s} => {s}", h);

                    if (mem.eql(u8, ":path", h.name))
                        path = h.value;
                } else |err| {
                    if (err != error.EndOfData) return err;
                }

                if (path) |p|
                    try sendFile(h2c, dir, frame.hdr.id, p)
                else
                    return error.DidntFindThePathHeader;
            },
            else => {},
        }
    } else |err| {
        if (err != error.EndOfData)
            return err;
    }
}

pub fn main() anyerror!void {
    var args = std.process.args();
    const exe_name = args.next() orelse "zelf-zerve2";
    const public_path = args.next() orelse {
        std.log.err("Usage: {s} <dir to serve files from>", .{exe_name});
        return;
    };

    var dir = try fs.cwd().openDir(public_path, .{});
    const self_addr = try net.Address.resolveIp("127.0.0.1", 9000);
    var listener = net.StreamServer.init(.{});
    try listener.listen(self_addr);
    defer listener.close();

    var h2c = try http2.NetConnection.init(std.heap.page_allocator, 1 << 14);
    defer h2c.deinit();

    std.log.info("Listening on {}; press Ctrl-C to exit...", .{self_addr});

    while (listener.accept()) |conn| {
        defer conn.stream.close();

        std.log.info("Accepted Connection from: {}", .{conn.address});
        h2c.reinit(conn.stream, conn.stream);

        serveFiles(&h2c, dir) catch |err| {
            if (@errorReturnTrace()) |bt| {
                std.log.err("Failed to serve client: {}: {}", .{ err, bt });
            } else {
                std.log.err("Failed to serve client: {}", .{err});
            }
        };
    } else |err| {
        return err;
    }
}
