v0.88.2

- java: Expose `BackupJsonExporter` for takeout usage.

- Expose `useH2ForAuthChat` remote configuration key to use HTTP/2 for AuthenticatedChatConnection's non-fronted connections.

- The `disableNagleAlgorithm` remote config flag has been removed, as the experiment has been deployed successfully.

- keytrans: Improve monitor_and_search logic to handle a wider set of scenarios (keep monitoring unchanged mappings, while falling back to search for the rest).

- Windows: revert change to build without build without `+crt-static`
