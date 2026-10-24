#!/usr/bin/env bash
# Generates the Swift and Kotlin bindings for passbox-ffi.
#
#   crates/ffi/generate-bindings.sh [out-dir]
#
# The bindings are generated from the compiled library ("library mode"), so
# they always match the Rust code. Mobile builds run this script; the output
# is not committed.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
out="${1:-$root/target/bindings}"

cargo build --manifest-path "$root/Cargo.toml" --package passbox-ffi
case "$(uname -s)" in
  Darwin) lib="$root/target/debug/libpassbox_ffi.dylib" ;;
  *) lib="$root/target/debug/libpassbox_ffi.so" ;;
esac

for language in swift kotlin; do
  cargo run --quiet --manifest-path "$root/Cargo.toml" --package passbox-ffi \
    --features bindgen --bin uniffi-bindgen -- \
    generate --library "$lib" --language "$language" --no-format --out-dir "$out/$language"
done
echo "Bindings written to $out"
