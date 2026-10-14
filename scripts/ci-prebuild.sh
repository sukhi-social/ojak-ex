#!/usr/bin/env bash
# What one CI job does for one target: a baseline build and a PGO build, a
# speed check of both, and the PGO library left in dist/. The table goes to
# target/summary-TARGET.md.
#
#   scripts/ci-prebuild.sh TARGET
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
export PATH="$HOME/.cargo/bin:$PATH"

target=${1:?usage: ci-prebuild.sh TARGET}
lib=libojak_nif-$target.so
elixir_dir=$root
mkdir -p target dist/baseline

sha256sum_of() {
  if command -v sha256sum > /dev/null; then sha256sum "$1" | cut -c1-12; else shasum -a 256 "$1" | cut -c1-12; fi
}

OJAK_PGO=0 scripts/pgo-build.sh "$target"
mv "dist/$lib" "dist/$lib.sha256" dist/baseline/
scripts/pgo-build.sh "$target"

# Another workload than the one the profile came from, so that a gain is not
# just the build remembering its lesson.
#
# This does not go through Mix: its compile alias runs `cargo build` and copies
# the plain library over priv/, which would make both runs measure the same
# library. The Elixir files are compiled by hand into a directory shaped like
# an application (ebin/ and priv/), and `elixir -pa` runs the benchmark.
app=$root/target/compare-app/ojak
rm -rf "$app" && mkdir -p "$app/ebin" "$app/priv"
elixirc -o "$app/ebin" $(find "$elixir_dir/lib" -name '*.ex')
for which in baseline pgo; do
  if [ "$which" = baseline ]; then from=dist/baseline/$lib; else from=dist/$lib; fi
  cp "$from" "$app/priv/ojak_nif.so"
  echo "$which: $(sha256sum_of "$app/priv/ojak_nif.so")"
  elixir -pa "$app/ebin" "$elixir_dir/bench/compare.exs" > "target/compare-$which.txt"
done

{
  echo "### $target"
  echo
  echo "Median of five runs, ms per call. Baseline: same flags, no profile."
  echo
  echo "| call | baseline | PGO | time change (minus is faster) |"
  echo "|---|---|---|---|"
  awk '
    function name(line) { sub(/ +[0-9.]+ ms$/, "", line); return line }
    NR == FNR { n = name($0); order[++count] = n; base[n] = $(NF - 1); next }
    { pgo[name($0)] = $(NF - 1) }
    END {
      for (i = 1; i <= count; i++) {
        n = order[i]
        printf "| %s | %s | %s | %+.1f%% |\n", n, base[n], pgo[n], (pgo[n] - base[n]) / base[n] * 100
      }
    }' target/compare-baseline.txt target/compare-pgo.txt
} > "target/summary-$target.md"
cat "target/summary-$target.md"

rm -rf dist/baseline
