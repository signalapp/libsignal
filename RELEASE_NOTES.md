v0.65.4

- Introduces Net.setProxyFromUrl(), which supports HTTP and SOCKS proxies in addition to the
  "transparent TLS proxies" already supported on Net. Supported schemes: "socks5" (or just "socks"),
  "socks5h", "socks4", "socks4a", "https", "http", and "org.signal.tls".

- backup: Remove DirectStoryReplyMessage.storySentTimestamp

- net: Enable using ChatConnection for key transparency operations (still Java only)
