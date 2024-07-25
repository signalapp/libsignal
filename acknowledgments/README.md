This directory contains pre-generated acknowledgments for the Rust dependencies of libsignal. CI enforces that they are kept up to date.

## Updating

If you update libsignal's dependencies, you'll need to update this listing. Install [cargo-about][] if you haven't already:

```shell
cargo +stable install --locked cargo-about --version $(cat acknowledgments/cargo-about-version)
```

Then:

1. Run `bin/regenerate_acknowledgments.sh`.
2. Check the HTML output for new "synthesized" entries. This can indicate that the license for a particular dependency was not properly detected.
3. If there are any unaccounted-for "synthesized" entries, add new "[clarify][]" entries to about.toml.

Apart from the projects in this very repo, there are a few other crates that unavoidably have "synthesized" licenses based on their Cargo manifests:

- cesu8: Very old crate whose repository contains a license file for the Rust project itself, rather than the crate.
- half: Not actually synthesized! Their license file just matches the synthesized text perfectly. A bug in cargo-about, presumably.
- pqcrypto-\*: Uploaded without a license file, though a license is listed in the Cargo.toml for each crate. The Kyber implementations we use are released as [Public Domain][kyber], so no acknowledgment is necessary.

[cargo-about]: https://embarkstudios.github.io/cargo-about/
[clarify]: https://embarkstudios.github.io/cargo-about/cli/generate/config.html#the-clarify-field-optional
[kyber]: https://github.com/PQClean/PQClean/blob/round3/crypto_kem/kyber1024/clean/LICENSE
