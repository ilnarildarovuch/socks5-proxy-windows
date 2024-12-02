# Socks5-Proxy

A minimal [SOCKS5](https://tools.ietf.org/html/rfc1928) proxy written in C.

## Build

You could build it with GCC.

```sh
gcc proxy.c -o proxy.exe -lws2_32 -O3
```

## Run

Run a SOCKS5 proxy.

```sh
./proxy.exe
```

Test it with `curl`.

```sh
curl --socks5 127.0.0.1:1080 https://www.baidu.com
```

You may also set the proxy in your browser as SOCKS5 on 127.0.0.1:1080, and start browsing websites.
