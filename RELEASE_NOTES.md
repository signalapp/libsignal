v0.69.0

- Net: Remove the fallback connect code paths for CDSI. This is a breaking change.

- backups: Validate ChatFolder::id

- Node: GroupIdentifier now has a custom toString() (to its base64 representation)

- Net: onConnectionInterrupted will now pass along ConnectedElsewhere and ConnectionInvalidated as disconnection reasons, when applicable.
