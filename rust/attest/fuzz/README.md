This directory contains fuzz targets used with `cargo fuzz`.

```
// In the top-level source directory
cargo install cargo-fuzz
cargo fuzz list
cargo +nightly fuzz run <fuzz-target>

// If you have custom seed inputs
cargo +nightly fuzz run <fuzz-target> fuzz/corpus/<fuzz-target> fuzz/seeds/<fuzz-target>

// If you find a crash
RUST_BACKTRACE=1 cargo +nightly fuzz run -D <fuzz-target> <crash-artifact>
```

For more information, including how to check the coverage of the explored corpus, see <https://rust-fuzz.github.io>.
