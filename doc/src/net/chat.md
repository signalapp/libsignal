# Chat

Signal's chat server was historically been built on plain HTTP REST requests; to improve responsiveness for online clients, this was switched over to a pair of persistent WebSocket connections---one authenticated, one unauthenticated. To ease migration, these connections use an HTTP-like protobuf interface to provide the same API that REST used to, along with a dedicated "reverse request" mode for pushing incoming messages and notifying clients when the queue is empty. libsignal has two modes for working with chat connections: plain RPC, and "typed APIs".


## WebSocket RPC

To directly use this WebSocket RPC from libsignal, use the `connectAuth(enticated)Chat` or `connectUnauth(enticated)Chat` methods on a Net(work) instance. This produces an AuthenticatedChatConnection or an UnauthenticatedChatConnection, respectively, each of which has a `send()` method that can send a REST-like request. Note that for Android or iOS, the connection must be `start()`ed with a listener before it can be used.

The listener callbacks only cover disconnection and the two message-queue events, though these events are guaranteed to be delivered in order. They do not provide general-purpose server->client communication, even though the underlying protobuf interface would allow it.

### Preconnecting

If the time spent establishing a TLS connection becomes significant, Net also has a `preconnectChat()` call, which does the "early" part of connection establishment and then pauses, waiting for a later call to `connectAuthenticatedChat()`. This allows parallelizing the connection attempt with, say, loading the username and password used for the auth socket. This is considered an optimization; if `connectAuthenticatedChat()` isn't called soon after the initial `preconnectChat()` call, or if the connection parameters change in between, the preconnected socket will be silently discarded. If `connectAuthenticatedChat()` isn't called at *all,* the preconnected socket may not ever be cleaned up (but the server will eventually hang up on it).


## High-level Request APIs (a.k.a "Typed APIs")

To improve on the limitations of the current endpoints and the WebSocket RPC system, the chat server will support a new gRPC-based API that can replace the WebSocket RPC. Rather than have all clients bring up their own gRPC clients, libsignal will provide high-level equivalents for all the APIs currently using `send()` calls, and then transparently switch them to gRPC calls later. Using these high-level APIs differs slightly on each platform.

### Android

The typed APIs are provided as "services" that wrap the corresponding ChatConnection. For example:

```kotlin
val usernamesService = UnauthUsernamesService(chatConnection)
val response = usernamesService.lookUpUsernameHash(hash).get() // or await()
```

Unlike most libsignal APIs, which throw exceptions, the service APIs produce `RequestResult`s, a sealed interface of `Success` (what you wanted), `NonSuccess` (a request-specific error), and `Failure` (a standard transport error of some kind). This design was based on what Signal-Android was using elsewhere!

### iOS

The typed APIs are implemented directly on the corresponding ChatConnection, but also grouped into "service" protocols. Several hoops were jumped through to make it possible to access these in a generic way via the helper `UnauthServiceSelector` type (see there for more details).

```swift
// Assuming a helper accessService(_:as:) method added in the app.
try await accessService(chatConnection, as: .usernames) { usernamesService in
    let response = try await usernamesService.lookUpUsernameHash(hash)
}
```

Each request can throw request-specific errors as well as standard transport errors.

### Desktop

The typed APIs are implemented directly on the corresponding ChatConnection, but also grouped into "service" interfaces. The libsignal tests contain an example of how to limit access in a generic way (see ServiceTestUtils.ts).

```typescript
// Assuming a helper accessUnauthService() method added in the app.
const service = connectionManager.accessUnauthService<UnauthUsernamesService>();
const response = await service.lookUpUsernameHash(hash);
```

Each request can throw (reject the promise) with request-specific errors as well as standard transport errors.
