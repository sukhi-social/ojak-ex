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
elixir_dir=$root/crates/ojak-nif/elixir
mkdir -p target dist/baseline

OJAK_PGO=0 scripts/pgo-build.sh "$target"
mv "dist/$lib" "dist/$lib.sha256" dist/baseline/
scripts/pgo-build.sh "$target"

# Another workload than the one the profile came from, so that a gain is not
# just the build remembering its lesson.
for which in baseline pgo; do
  if [ "$which" = baseline ]; then from=dist/baseline/$lib; else from=dist/$lib; fi
  cp "$from" "$elixir_dir/priv/ojak_nif.so"
  (cd "$elixir_dir" && mix run --no-start --no-compile bench/compare.exs) > "target/compare-$which.txt"
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
