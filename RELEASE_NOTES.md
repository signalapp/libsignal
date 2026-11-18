v0.108.2

- Node: The prebuilt binaries for `@signalapp/libsignal-client` are now distributed via `optionalDependencies` `@signalapp/libsignal-client-darwin`, `@signalapp/libsignal-client-linux`, and `@signalapp/libsignal-client-win32`. Dependent packages can continue solely referencing `@signalapp/libsignal-client`, but any custom packaging logic may need to be updated, and developers will need to take note if they want to inspect binaries for an OS other than the one they are running. (Note that the binaries are *not* split up by CPU architecture to help with the common case of packaging a "universal" application.)

- Node: Local development now uses `pnpm` instead of `npm`. Dependent packages should not need to change anything.
