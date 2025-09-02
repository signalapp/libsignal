# Networking

libsignal has a number of networking-related APIs, collectively referred to as "libsignal-net". These currently provide connections to the [chat server][chat], contact discovery service, and SVR-B, with the possibility of eventually handling every connection to a server run by Signal.


## The Net class

**Net** (or **Network** on Android) is the top-level manager for connections made from libsignal. It records the environment (production or staging), the user agent to use for all connections (appending its own version string), and any configurable options that apply to all connections, such as whether IPv6 networking is enabled. Internally, it also owns a Rust-managed thread pool for dispatching I/O operations and processing responses. Some operations (e.g. CDS) are provided directly on Net; others use a separate connection object (e.g. chat) where the Net instance is merely used to connect.


## Implementation Organization

In the Rust layer, libsignal-net is broken up into three separate crates:

- `libsignal-net-infra`: Server- and connection-agnostic implementations of networking protocols
- `libsignal-net`: Connections specifically to Signal services, rather than generic reusable work
- `libsignal-net-chat`: Presents the high-level request APIs of the Signal chat server in a protocol-agnostic way (see the [Chat][] page for more info)

(These boundaries are approximate, because ultimately it's all going to be exposed to the apps anyway; these are *not* some of the crates designed to be generally reusable outside Signal.)

[chat]: ./chat.md
