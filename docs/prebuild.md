# Prebuilt libraries (Linux, PGO)

`.github/workflows/prebuild.yml` builds `libojak_nif` for four targets and,
on a `v*` tag, attaches them to a release with their `.sha256`:

| target | built on |
|---|---|
| x86_64-unknown-linux-gnu | Ubuntu 22.04 (glibc 2.35) |
| aarch64-unknown-linux-gnu | Ubuntu 22.04 arm |
| x86_64-unknown-linux-musl | `elixir:1.20-alpine` |
| aarch64-unknown-linux-musl | `elixir:1.20-alpine` on arm |

By hand ("Run workflow") the libraries are only kept as workflow artifacts.
Nothing downloads them yet: `mix compile` still runs `cargo build`.

## How the profile is made

`scripts/pgo-build.sh TARGET` builds the library with counters, loads it into
a real BEAM, runs `bench/pgo_workload.exs` (sign, verify, LD signatures,
proofs, JSON-LD, on several processes), merges the counters, and builds again
with them. It then runs the Elixir tests on the result. It stops if the run
wrote no counters. `OJAK_PGO=0` skips the profile, for a baseline.

Both builds use fat LTO and one codegen unit. `OJAK_NIF_TARGET` (read by the
Mix build task) makes cargo take `--target`, so build scripts and proc macros
are not built with the counters.

Try it here: `rustup component add llvm-tools`, then
`scripts/pgo-build.sh`. The library is left in `dist/`.

## Does it help?

A little, and not everywhere. On Apple silicon (aarch64-apple-darwin), median
of five runs, repeated twice with the same result:

| | plain `cargo build --release` | fat LTO, 1 unit | + PGO |
|---|---|---|---|
| proof verify | 0.0688 ms | 0.0638 | 0.0598 |
| JSON-LD normalize | 0.0801 | 0.0729 | 0.0688 |
| LD verify | 0.3537 | 0.3480 | 0.3216 |
| HTTP sign (RSA) | 0.7192 | 0.7126 | 0.7502 |

The flags give 5 to 8 percent on the small calls. The profile moves things by
a few percent either way, and the direction changes a little each time the
library is rebuilt: in two Mac builds the small calls (proofs, JSON-LD) were 1
to 7 percent faster and the RSA calls 2 to 7 percent slower. RSA is bignum
arithmetic and was already tight. Read this as "PGO is a wash here", not as a
gain.

An earlier version of the benchmark compared the same library with itself:
`mix run --no-compile` still ran the compile alias, which copied the plain
build over `priv/`. `scripts/ci-prebuild.sh` now compiles the Elixir files by
hand and runs `elixir -pa`, and prints the checksum of each library it
measures.

Each CI job builds both and writes the speed of both to its summary, on
another workload than the one the profile came from. Read it before trusting
the build.

## What CI showed (run 38530432203, workflow_dispatch)

All four targets built, ran the profile workload, and passed the 57 Elixir
tests on both the baseline and the PGO library. That includes the musl
targets inside `elixir:1.20-alpine` and the arm runner with `setup-beam`. One
run each, on shared runners, so a few percent is noise.

| target | where PGO helped | where it did not |
|---|---|---|
| x86_64 gnu | most calls, 4 to 6 percent faster | proof sign, +1 |
| aarch64 gnu | LD verify, proofs, JSON-LD: 2 to 8 percent faster | RSA sign, +1 |
| aarch64 musl | LD verify, JSON-LD: 3 to 4 percent faster | RSA sign, +1 |
| x86_64 musl | LD verify, proofs, JSON-LD: 1 to 3 percent faster | RSA sign and verify, 4 to 7 percent slower |

So: a small gain on the JSON and proof paths, none or a loss on RSA. Whether
it is worth the second build is for you to decide from your own summaries.

## Not checked

- A `v*` tag, so the `release` job has not run.
- A library from here loaded into a real application (only the tests did).
- Nothing signs the libraries; the `.sha256` only catches a bad download.
- Nothing downloads them yet: `mix compile` still runs `cargo build`.
