# List of commands runnable with https://github.com/casey/just
#
# When adding new recipes, include a one-line comment describing the behavior
# to be displayed by `just --list` next to the name.

_default:
    echo "no default recipe; run with --list to see all recipes"
    exit 1

generate-jni:
    rust/bridge/jni/bin/gen_java_decl.py

generate-ffi:
    swift/build_ffi.sh --generate-ffi

generate-node:
    rust/bridge/node/bin/gen_ts_decl.py

alias generate-java := generate-jni
alias generate-swift := generate-ffi
alias generate-ts := generate-node

# Regenerate bridge code for all three app languages.
generate-bridge: generate-jni generate-node generate-ffi

format-jni:
    (cd java && ./gradlew spotlessApply)

format-ffi:
    (cd swift && swiftformat --swiftversion 5 .)

format-node:
    (cd node && npm run format)

alias format-java := format-jni
alias format-swift := format-ffi
alias format-ts := format-node

# Auto-format code in Java, Rust, Swift, and TypeScript
format-all: format-jni format-ffi format-node
    cargo fmt
    taplo fmt

# Same as format-all, but does not actually make changes; merely fails if code is not yet formatted.
check-format-all:
    cargo fmt --all -- --check
    taplo fmt --check
    (cd swift && swiftformat --swiftversion 5 . --lint)
    (cd node && npm run format-check)
    (cd java && ./gradlew spotlessCheck)

# Runs some quick local checks; useful to make sure CI will not fail immediately after push.
check-pre-commit:
    just check-format-all
    (cd node && npm run lint)
    (cd swift && ./verify_error_codes.sh)
    (cd swift && swiftlint lint --strict)
    cargo test --workspace --all-features --verbose --no-fail-fast -- --include-ignored
    cargo clippy --workspace --all-targets --all-features --keep-going -- -D warnings
    @printf "\e[32mBasic pre-commit checks passed! ✅ Hopefully good to push! 🤞\e[0m\n"
