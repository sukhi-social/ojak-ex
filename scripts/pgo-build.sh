#!/usr/bin/env bash
# Build the NIF library with profile-guided optimisation.
#
#   scripts/pgo-build.sh [TARGET]      TARGET defaults to this machine's.
#
# 1. build the library with profiling counters in it;
# 2. load it into a real BEAM and run bench/pgo_workload.exs, which writes the
#    counters out when the VM exits;
# 3. merge them, and build again, this time letting rustc use them;
# 4. run the Elixir tests against the result.
#
# The result is dist/libojak_nif-TARGET.so (a Mach-O dylib on macOS, still
# named .so, as priv/ojak_nif.so is) and its .sha256.
#
# OJAK_PGO=0 builds the same way but without the profile: the baseline to
# measure against. OJAK_PGO_ROUNDS sets the size of the workload.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

host=$(rustc -vV | sed -n 's/^host: //p')
target=${1:-$host}
elixir_dir=$root
data=$root/target/pgo-data/$target
merged=$root/target/pgo-data/$target.profdata

# Same flags for every build of one target, so that cargo can tell when
# nothing needs doing. Fat LTO and one codegen unit let the profile reach
# across crates (ojak-sig, rsa and the rest are separate crates).
export CARGO_PROFILE_RELEASE_LTO=fat
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
export OJAK_NIF_TARGET=$target
base_flags=""
case $target in
  # A cdylib cannot be linked with a static libc.
  *-musl) base_flags="-C target-feature=-crt-static" ;;
esac

# The only llvm-profdata that reads what this rustc writes is its own.
profdata=$(find "$(rustc --print sysroot)" -name llvm-profdata -type f | head -n 1)
if [ "${OJAK_PGO:-1}" != 0 ] && [ -z "$profdata" ]; then
  echo "llvm-profdata not found; run: rustup component add llvm-tools" >&2
  exit 1
fi

if [ "${OJAK_PGO:-1}" != 0 ]; then
  echo "== 1/4 build with counters ($target)"
  rm -rf "$data" "$merged"
  mkdir -p "$data"
  export RUSTFLAGS="$base_flags -C profile-generate=$data"
  cargo build --release -p ojak-nif --target "$target"

  echo "== 2/4 run the workload"
  (
    cd "$elixir_dir"
    LLVM_PROFILE_FILE="$data/ojak-%p-%m.profraw" \
      mix run --no-start bench/pgo_workload.exs
  )
  if ! ls "$data"/*.profraw > /dev/null 2>&1; then
    echo "the workload wrote no profile; the library did not flush it on exit" >&2
    exit 1
  fi

  echo "== 3/4 merge, and build with the profile"
  "$profdata" merge -o "$merged" "$data"/*.profraw
  export RUSTFLAGS="$base_flags -C profile-use=$merged"
else
  echo "== baseline build, no profile ($target)"
  export RUSTFLAGS="$base_flags"
fi
cargo build --release -p ojak-nif --target "$target"

echo "== 4/4 test the result"
(cd "$elixir_dir" && mix test)

ext=so
[ "$(uname)" = Darwin ] && ext=dylib
mkdir -p "$root/dist"
out=$root/dist/libojak_nif-$target.so
cp "target/$target/release/libojak_nif.$ext" "$out"
if command -v sha256sum > /dev/null; then sum="sha256sum"; else sum="shasum -a 256"; fi
(cd "$root/dist" && $sum "libojak_nif-$target.so" > "libojak_nif-$target.so.sha256")
echo "built $out"
