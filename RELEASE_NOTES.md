v0.65.5

- Introduces an overload of `Net.setProxy()` that supports HTTP and SOCKS proxies in addition to the
   "transparent TLS proxies" already supported. Supported schemes: "socks5" (or just "socks"),
   "socks5h", "socks4", "socks4a", "https", "http", and "org.signal.tls".
