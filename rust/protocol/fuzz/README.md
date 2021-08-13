This directory contains fuzz targets used with `cargo fuzz`.

```
// In the parent directory (rust/protocol)
cargo install cargo-fuzz
cargo fuzz list
cargo fuzz run <fuzz-target>

// If you find a crash
RUST_BACKTRACE=1 cargo fuzz run -D <fuzz-target> <crash-artifact>
```

For more information, including how to check the coverage of the explored corpus, see <https://rust-fuzz.github.io>.
