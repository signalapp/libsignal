v0.67.4

- Android and iOS: ChatConnectionListener has a new optional callback for server alerts.
  (Already added for Node in v0.67.2.)

- Net.preconnectChat will start the connection process for an authenticated chat connection
  without needing a username and password ready.

- Rust: Update some dependencies (including boring) to the lastest compatible versions.

- Net: Harmonized WebSocket PING interval with the client keep-alive interval to conserve resources.
