#!/bin/sh
# Install the Rust toolchain named in rust-toolchain.toml, with llvm-tools
# (the profile merger PGO needs). Works on a GitHub runner, which has rustup,
# and in a bare Alpine container, which does not.
set -eu

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

if ! command -v rustup > /dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none --profile minimal
fi

channel=$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)
rustup toolchain install "$channel" --profile minimal --component llvm-tools
rustc -vV
