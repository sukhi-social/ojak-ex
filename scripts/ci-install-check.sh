#!/bin/sh
# After a release: depend on it from GitHub the way a user does, with no Rust
# on the PATH, so the build cannot quietly fall back to cargo. Then use it.
#
#   scripts/ci-install-check.sh TAG
set -eu

tag=${1:?usage: ci-install-check.sh TAG}
dir=$(mktemp -d)
cd "$dir"

cat > mix.exs <<MIX
defmodule Check.MixProject do
  use Mix.Project
  def project, do: [app: :check, version: "0.0.0", deps: [{:ojak, github: "sukhi-social/ojak-ex", tag: "$tag"}]]
  def application, do: []
end
MIX

# The PATH without any directory that has cargo or rustc.
keep=""
old_ifs=$IFS
IFS=:
for d in $PATH; do
  if [ ! -x "$d/cargo" ] && [ ! -x "$d/rustc" ]; then keep="$keep:$d"; fi
done
IFS=$old_ifs
PATH=${keep#:}
export PATH
if command -v cargo > /dev/null; then echo "cargo is still on the PATH" >&2; exit 1; fi

mix deps.get
mix compile 2>&1 | tee out.txt
grep -q "using the prebuilt library" out.txt || { echo "the prebuilt library was not used" >&2; exit 1; }

mix run -e '
  {:ok, key} = Ojak.Key.generate(:ed25519)
  note = %{"@context" => "https://www.w3.org/ns/activitystreams", "id" => "https://x.example/1", "type" => "Note"}
  {:ok, signed} = Ojak.Proof.sign(note, key, verification_method: "https://x.example/u#k")
  {:ok, _} = Ojak.Proof.verify(signed, fetch_key: fn _ -> {:ok, key.public} end)
  IO.puts("ojak works")
'
