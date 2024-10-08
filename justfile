# List of commands runnable with https://github.com/casey/just
#
# When adding new recipes, include a one-line comment describing the behavior
# to be displayed by `just --list` next to the name.

_default:
    echo "no default recipe; run with --list to see all recipes"
    exit 1

# Regenerate bridge code for all three app languages.
generate-bridge:
    rust/bridge/jni/bin/gen_java_decl.py
    rust/bridge/node/bin/gen_ts_decl.py
    swift/build_ffi.sh --generate-ffi

# Auto-format code in Java, Rust, Swift, and TypeScript
format-all:
    cargo fmt
    taplo fmt
    (cd swift && swiftformat --swiftversion 5 .)
    (cd node && yarn format)
    (cd java && ./gradlew spotlessApply)

# Same as format-all, but does not actually make changes; merely fails if code is not yet formatted.
check-format-all:
    cargo fmt --all -- --check
    taplo fmt --check
    (cd swift && swiftformat --swiftversion 5 . --lint)
    (cd node && yarn format-check)
    (cd java && ./gradlew spotlessCheck)

# Runs some quick local checks; useful to make sure CI will not fail immediately after push.
check-pre-commit:
    just check-format-all
    (cd node && yarn lint)
    (cd swift && ./verify_error_codes.sh)
    (cd swift && swiftlint lint --strict)
    cargo test --workspace --all-features --verbose --no-fail-fast -- --include-ignored
    cargo clippy --workspace --all-targets --all-features --keep-going -- -D warnings
    @printf "\e[32mBasic pre-commit checks passed! ✅ Hopefully good to push! 🤞\e[0m\n"
