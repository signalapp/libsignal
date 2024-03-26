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
