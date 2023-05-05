# Barely HTTP/2 in Zig

Something like the minimum Zig implementation of HTTP/2 to serve a
request from Curl. I still need to use TLS and ALPN to get browsers
working.

There are quite some comments in the source code and a blog article:
https://richiejp.com/barely-http2-zig

This is for a follow on article to:
https://richiejp.com/zig-vs-c-mini-http-server

## Serve files

Run the following

```sh
$ zig run src/self-serve2.zig -- /static/site
info: Listening on 127.0.0.1:9000; press Ctrl-C to exit...

```

Then in a different terminal

```sh
$ curl -s -v --http2-prior-knowledge http://localhost:9000
```

## Just print frame info

A second entry point in the main lib just prints the HTTP/2 frames it
receives.

```sh
$ zig run src/http2.zig
```
