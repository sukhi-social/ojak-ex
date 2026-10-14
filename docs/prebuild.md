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

Not shown. On Apple silicon (aarch64-apple-darwin) the PGO library, a
baseline with the same flags, and a plain `cargo build --release` all ran
within 1 to 2 percent of each other, which is the noise. Most of the time
goes to RSA arithmetic, which is already tight.

So each job builds both and writes the speed of both to its summary
(`scripts/ci-prebuild.sh`), on another workload than the one the profile came
from. Read it before trusting the build.

## Not checked

- The workflow has not run on GitHub.
- Profiling on musl, and `erlef/setup-beam` on the arm runner, are untested.
- Whether a musl library built this way loads in `elixir:1.20-alpine`.
- Nothing signs the libraries; the `.sha256` only catches a bad download.
