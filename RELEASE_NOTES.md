v0.82.0

- Node: migrate libsignal-client to the ECMAScript module format (from CommonJS).

- Node: interfaces now use property notation for method requirements, which TypeScript can check more strictly.

- net: Direct connections to the Signal servers will be tried as a fallback if connecting through an HTTP or SOCKS proxy fails or takes too long.
