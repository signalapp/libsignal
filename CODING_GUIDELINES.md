# High-Level Priorities

1. Ease of Use / Protection Against Misuse
2. Maintainability
3. Code Size
4. Performance

These should usually be prioritized in that order, but adjust the trade-off as necessary for whatever you're working on.

# General

- **The bridging layer is not API.** As noted in the [readme](README.md), the primary purpose of this library is to provide good Java, Swift, and TypeScript APIs. We also try to make the non-bridge crates have a nice API, both for our own maintainence, testing, and internal use; and for external users who want to use or fork our crate. However, the Rust APIs in rust/bridge/ and the raw C symbols / JNI entry points / Node module we build are not considered public-facing at all. Use that to keep everything else nice!

    (Not that you should be sloppy in the bridging layer. Maintainability is still a priority!)

- **Public APIs should follow the convention of their language/environment.** What makes a good Java API is different from what makes a good Swift API or TypeScript API (or Rust API). It's okay if that leads to differently-shaped public APIs or even multiple bridge functions.

- But, **try not to repeat implementation details across app languages**. If something has to be changed in multiple places, it's going to get out of sync. It's better if we can put that information in the Rust bridging layer and have the app languages access it that way.

    The exception is tests, where we do primary testing in Rust but still want to have good coverage for all three app languages. We've missed edge cases for just one app language too many times in the past.

- **Every change should have tests** or be covered by existing tests. There are sometimes exceptions to this, but a lot of times the act of justifying the exception can suggest how to write the tests instead.

- **Logs should not contain user data**, including the default stringification for errors (Rust's Display, Java and TypeScript's `toString()`, Swift's `description`). "Debug" and "verbose" log levels are an exception to this, since they are turned off at compile time in our client library release builds. Note that this isn't "any information that can uniquely distinguish one user from another" (an ephemeral public key can do that, and there are legitimate reasons to log those; use your best judgment), but it is "any information that includes user input" (such as unencrypted usernames), "any information that can be linked back to a Signal account" (such as identity keys), and of course "any passwords or private keys".

    One place where this is particularly subtle is when working with types that come from dependencies, especially errors. If the dependency has access to any such potentially-sensitive information, it's best to assume it could make it into arbitrary output, including error messages. The libsignal-net crate is particularly sensitive to this and constrains its errors with a custom LogSafeDisplay trait, but this isn't perfect.

    Low-level objects like ServiceId and ProtocolAddress do not follow this rule; instead, they stringify in fixed formats that are easy to filter from higher-level logs en masse.

- **Logs should be kept minimal on success paths**. It's harder to find significant information in a sea of "operation succeeded!", and in the worst case we'd hit the log size limit sooner. (Clients only keep a few days of logs, and they'll keep even less if the recent logs are taking up too much space.) Even on failure paths, consider how much will end up in client logs, and if it'll be redundant with a higher-level log. Especially when logging in a loop. But don't go too far: it's important to know when certain events happen in relation to earlier or later failures.

    As with the previous rule, this does not apply to the "debug" and "verbose" log levels, which are turned off at compile time in our client library release builds.


# Rust

- **We avoid including multiple versions of crates in our build products when reasonable.** This is purely for code size reasons, not compile time; we allow multiple versions of crates for host and testing dependencies. This is enforced in CI with the [verify_duplicate_crates](bin/verify_duplicate_crates) script.

- **Panics are caught** and reported to apps as recoverable errors, so everything we make has to be unwind-safe in at least a basic sense.

- **Prefer `expect()` to `unwrap()`.** As noted, we don't have a no-panics policy, but `expect()` forces you to write down why you believe something should *never* happen except for programmer errors. In particular, untrusted input that fails to validate should *not* panic.

    (Yes, there's a Clippy lint for this, but we also have a lot of code that predates this guideline.)

- You don't have to write doc comments on everything, but **if you do write a comment, make it a doc comment**, because they show up more nicely in IDEs.

- We build with a pinned nightly toolchain, but **we also support stable**. The specific minimum supported version of stable is checked in CI (specifically, at the top of [build_and_test.yml](.github/workflows/build_and_test.yml)). We permit ourselves to bump this as needed, but try not to do so capriciously because we know external people might be in non-rustup scenarios where getting a new stable is tricky. If you need to bump the minimum supported version of stable, make sure the next release has a "breaking" version number.

- **We do not have a changelog file**; we rely on [GitHub displaying all our releases](https://github.com/signalapp/libsignal/releases).

- **Avoid `cargo add`**, or fix up the Cargo.toml afterwards. Some of our dependency lists are organized and `cargo add` doesn't respect that.

- We do not have consistent guidelines for how to do errors in Rust, and the different crates do them differently. :-(

- When profiling on an aarch64 device, you need to **explicitly enable hardware AES support** in the `aes` crate:

        RUSTFLAGS="--cfg aes_armv8 ${RUSTFLAGS:-}"

    These are automatically detected on x86_64, but will require an opt-in for aarch64 until we can update to `aes 0.9` or newer (not out yet at the time of this writing). All our app library build scripts set this themselves, but doing a manual `cargo build --release` will not.


## Async

- When using the `select!` macro, **prefer `tokio::select!` over `futures::select!`**. They are not the same! `futures::select!` tries to make you think about use in loops by requiring that the futures be FusedFutures. However, many real-world futures do not implement FusedFuture, which means you have to call `fuse()` somewhere; it's easy to mistakenly do that *every time through the loop* instead of ahead of time. Doing so may also make it harder to use other methods of the Future in question, if the `select!` is not consuming.

    `tokio::select!` does not require FusedFuture, so you may need to add a guard clause (e.g. `, if !future.is_terminated`) if you're polling in a loop (or if the future may have already been completed for some other reason).

    More background here: "[Why doesn't tokio::select! require FusedFuture?](https://users.rust-lang.org/t/why-doesnt-tokio-select-require-fusedfuture/46975)"

- When bridging async APIs that use `#[bridge_io]`, **remember that the arguments and results will cross thread/queue/actor boundaries**, even in Node where there's only one JavaScript thread. Most of the time Rust's own Send/Sync checking will prevent this from being a problem, but whatever types are passed across the bridge layer will be unchecked, and you, the author of the code, will have to think about whether it's a problem (on both sides of the bridge). Usually it won't be! Value types like C structs and immutable Java objects are fine, it's only mutable objects and raw pointers where you have to be careful.

    Async APIs that do not use `#[bridge_io]` are always run on the calling thread: for Java and Swift, they are run to completion immediately, and for Node they are run by being scheduled on the JavaScript microtask queue. However, in theory any calls back into app code could still lead to reentrant use, and any borrowed Rust objects might be accessed from other threads while the operation is ongoing.


# Java

- Many of our APIs are shared between Android and Server, and we also run the client tests on desktop machines, so **stick to Java 8** unless you've verified that something newer is available on Android (back to our earliest supported version, API level 21, at the time of this writing), and don't use Android-specific APIs unless you're actually in Android-specific code. (This *should* be checked in CI but things have slipped through before, and it'll save you time to know whether you're allowed to use something.)

- **Put server-specific APIs in the server/ folder if they're not needed to test client features**, so they don't add code size for Android.

- **Put tests in the client/ folder unless they're testing server-only APIs**, so they can be run on both desktop machines and Android devices (and emulators).

- **Write javadocs** unless an API is trivial (or not app-team-facing). Even for internal methods, though, if you do write a comment, make it a doc comment (like for Rust code), because it shows up in IDEs.

- Our Java code gets minified with [Android's R8] tool, which scans for usages of all items (classes, methods, fields) and prunes those that are never used. It can't see usages from Rust code via JNI, so additional annotations are required. **Annotate classes, methods, and fields that are accessed via JNI with `@CalledFromNative`**, which is recognized by the directives in [`libsignal.pro`], to ensure they are kept.

[Android's R8]: https://developer.android.com/build/shrink-code
[`libsignal.pro`]: ./java/shared/resources/META-INF/proguard/libsignal.pro


# Swift

- We support back to **iOS 13** (at the time of this writing), so newer APIs may not be available. This will be checked on build, so you can't get it wrong.

- **Write API docs** using [DocC syntax][] (a Markdown dialect), unless an API is trivial (or not app-team-facing). Even for internal methods, though, if you do write a comment, make it a doc comment (like for Rust code), because it shows up in IDEs.

- To make sure that error messages get into logs, we use the `failOnError` helper instead of `try!` for forcing an unwrap on the result of an operation that can throw an error.

- [`Sendable`][] is a part of Swift's concurrency-checking model similar to Rust's `Send` and `Sync`. In general, **any `public` struct or enum should be marked `Sendable`** unless it wraps something that isn't Sendable (or if it's an enum just used for namespacing). You don't have to do this for non-public structs and enums; Swift will infer whether they are Sendable within the library automatically.

    Classes are trickier: a class that will forever be immutable is safe to mark `Sendable`, as is a class whose methods are designed to be called from multiple threads (often shortened to "this class is thread-safe"). However, unless you can make the class `final` *and* it doesn't have a superclass that's non-`Sendable`, the compiler won't be able to check it for you, and you'll have to write `@unchecked Sendable` instead. Be careful that this really is safe, and that we won't ever want to introduce mutating operations! It's easier to add Sendable later than to remove it, so err on the side of not including it.

    As an approximation, `Sendable` in Swift is *roughly* equivalent to Rust's `Send` for value types (e.g. structs) and `Sync` for reference types (e.g. classes), because every reference in Swift has an implicit `Arc` around it.

[DocC syntax]: https://www.swift.org/documentation/docc/writing-symbol-documentation-in-your-source-files
[`Sendable`]: https://developer.apple.com/documentation/swift/sendable


# TypeScript

- **Write API docs** using [JSDoc](https://jsdoc.app), unless an API is trivial (or not app-team-facing). Even for internal methods, though, if you do write a comment, make it a doc comment (like for Rust code), because it shows up in IDEs.

- **Include server APIs** in the TypeScript package; [@signalapp/mock-server][] exists.

[@signalapp/mock-server]: https://github.com/signalapp/Mock-Signal-Server


# Other useful documents

We don't adhere to these exactly but they're often useful tiebreakers or points of reference:

- [Official Rust API guidelines](https://rust-lang.github.io/api-guidelines/)
- [Fuchsia Netstack Team's Rust Patterns](https://fuchsia.dev/fuchsia-src/contribute/contributing-to-netstack/rust-patterns)
- [Official Swift API guidelines](https://www.swift.org/documentation/api-design-guidelines/)
