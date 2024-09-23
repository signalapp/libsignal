# Notes on GitHub Actions

## Why not use `actions/cache` in the Rust jobs?

In Sep 2024, the slowest part of `build_and_test.yml` was the main Rust job, which runs several Rust-related checks---some using our pinned nightly, others using our MSRV, and still others with both toolchains. The slowest *parts* of the job are just building things, and that's at least partly because each step requires slightly different configurations, making the rebuilds less incremental than they might otherwise be. The second slowest job is the Java one, which builds the main library in several slices.

It might be reasonable to try to cache some of this work, either using [`actions/cache`][] directly or another action built on top of it like [`Swatinem/rust-cache`][]. However, it's not clear how much of a benefit we'll actually get:

- Turning off `CARGO_INCREMENTAL` (as suggested by `rust-cache`) would save some space in our target directories, but we actually do build our local crates in a few different configurations, so we might make builds longer if we do that.

- Fetching dependencies takes about 1m out of our total time, not enough to be worth targeting specifically.

- We build with two different Rust toolchains, so any caching we do is doubled. The Java build only uses one toolchain, but it builds release instead of debug, and does multiple slices. If we fill up our entire cache quota (10GB) by accident, we lose most of the benefits as each job's cache evicts one of the other ones.

- Building with a lower debug info setting might save on the space of build intermediates, but is then testing something different than what people usually use at their desk.

[`actions/cache`]: https://github.com/actions/cache
[`Swatinem/rust-cache`]: https://github.com/Swatinem/rust-cache
