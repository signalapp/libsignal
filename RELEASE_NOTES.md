v0.77.0

- Java: Align cancellation behavior of our CompletableFuture with the one from OpenJDK:

    - The parameter to `cancel()` is ignored.
    - `completeExceptionally(someCancellationException)` is treated as a cancellation.
    - `get()` can now directly throw CancellationExceptions (as documented) instead of wrapping them in ExecutionException.

    Cancellations of libsignal operations continue to propagate bidirectionally when using CompletableFuture's transformation methods, unlike the version in OpenJDK.
