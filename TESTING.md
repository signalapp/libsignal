For the most part, libsignal is tested using each language's usual testing infrastructure, as described in the main [README.md](./README.md):

```shell
# Rust
% cargo test --workspace --all-features

# Java / Android
% ./gradlew client:test server:test android:connectedAndroidTest

# Node
% npm run build && npm run tsc && npm run test

# Swift
% ./build_ffi.sh --generate-ffi && swift test
```

However, sometimes there are some more interesting test configurations; those are documented here.


# Rust Benchmarks

- If you are testing on an ARM64 device (including Desktop), you should compile with `RUSTFLAGS="--cfg aes_armv8"` to enable hardware support in the `aes` crate.

- Similarly, although most tests are not very sensitive to the speed of SHA-2, you should also compile with `--features sha2/asm`. (`libsignal-message-backup` turns this on by default as a dev-dependency.) This will go away when we get to update to sha2 0.11.

All of these configuration options are normally set either at the bridge crate level or in the build scripts for each bridged platform, but they may not be set when running with plain `cargo bench`.


# Running cross-compiling Rust tests with custom runners

Rust allows running tests with cross-compiled targets, but normally that only works if your system supports executing the cross-compiled binary (like Intel targets on ARM64 macOS or Windows, or 32-bit targets on 64-bit Linux or Windows). However, by overriding the "runner" setting for a particular target, we can run cross-compiled tests as well.

## Running Rust tests on Android Devices (including the emulator)

1. Connect your device, or start an emulator and let it finish booting.

2. Make sure `adb` is in your path, or set `ADB` to the path to `adb` (it's usually in `$ANDROID_SDK_ROOT/platform-tools/adb`).

3. Set the following environment variables, filling in `path/to/ndk` and `YOUR_HOST_HERE`:

    ```shell
    ANDROID_NDK_HOME=path/to/ndk
    CARGO_PROFILE_TEST_STRIP=debuginfo   # make the "push" step take less time
    CARGO_PROFILE_BENCH_STRIP=debuginfo  # same for benchmarks
    CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=path/to/ndk/toolchains/llvm/prebuilt/YOUR_HOST_HERE/bin/aarch64-linux-android21-clang
    CARGO_TARGET_AARCH64_LINUX_ANDROID_RUNNER=bin/adb-run-test # in the repo root
    ```

    (If working with a different target architecture, don't forget to change the environment variables above. You may need to set additional environment variables depending on what you're building; see [`build_jni.sh`][java/build_jni.sh] for the full set that libsignal-jni uses.)

4. Finally, run `cargo test --target aarch64-linux-android -p PACKAGE`.

When running against an actual device, the "push" step in [`adb-run-test`][bin/adb-run-test] can be a bit flaky. Turning on the developer option "Stay awake" in the system settings seems to help.

You may need to push additional resources if the test expects to find them relative to the working directory, which you can `adb push` as well. (If you're writing the test, prefer `include_bytes!` instead to avoid this.)


## Running Rust tests in the iOS Simulator

1. Start a simulator and let it finish booting.

2. Set the following environment variable:

    ```shell
    CARGO_TARGET_AARCH64_APPLE_IOS_SIM_RUNNER='xcrun simctl spawn booted'
    ```

    (if working on an Intel Mac, don't forget to change the environment variables above to match the Intel simulator target)

3. Finally, run `cargo test --target aarch64-apple-ios-sim -p PACKAGE`.

If the test has resources found relatively, you’ll have to hack them in by loading them into the simulator’s root, which is located at `~/Developer/CoreSimulator/Devices/YOUR_SIMULATOR_UUID/data`. (If you're writing the test, prefer `include_bytes!` instead to avoid this.)
