#!/usr/bin/env bash
# Try the prebuilt-library path of `mix ojak_nif.build` against a local web
# server, in a copy of this tree so that your priv/ is left alone.
#
#   scripts/pgo-build.sh      # first: makes dist/libojak_nif-HOST.so
#   scripts/test-prebuilt.sh
#
# The library is named for this machine's Rust target, and fetched over HTTP
# from 127.0.0.1 with OJAK_NIF_BASE_URL, so this runs anywhere (the real
# download is only for Linux).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
host=$(rustc -vV | sed -n 's/^host: //p')
lib=libojak_nif-$host.so
[ -f "$root/dist/$lib" ] || { echo "no dist/$lib; run scripts/pgo-build.sh first" >&2; exit 1; }

work=$(mktemp -d)
server_pid=""
trap '[ -n "$server_pid" ] && kill "$server_pid" 2> /dev/null; rm -rf "$work"' EXIT

mkdir -p "$work/tree" "$work/serve"
rsync -a --exclude target --exclude _build --exclude deps --exclude priv --exclude dist --exclude .git "$root/" "$work/tree/"
cp "$root/dist/$lib" "$root/dist/$lib.sha256" "$work/serve/"

port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
(cd "$work/serve" && exec python3 -m http.server "$port" --bind 127.0.0.1 > "$work/server.log" 2>&1) &
server_pid=$!
sleep 1

cd "$work/tree"
export OJAK_NIF_TARGET=$host
export OJAK_NIF_BASE_URL=http://127.0.0.1:$port
dist_sum=$(cut -d' ' -f1 "$work/serve/$lib.sha256")

sha_of() { if command -v sha256sum > /dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
failures=0
check() { # check "name" condition-command...
  local name=$1; shift
  if "$@"; then echo "  ok    $name"; else echo "  FAIL  $name"; failures=$((failures + 1)); fi
}
compile() { mix compile 2>&1 | tee "$work/out.txt" > /dev/null; }
said() { grep -q "$1" "$work/out.txt"; }
did_not_say() { ! grep -q "$1" "$work/out.txt"; }
priv_is_dist() { [ "$(sha_of priv/ojak_nif.so)" = "$dist_sum" ]; }
priv_is_not_dist() { [ "$(sha_of priv/ojak_nif.so)" != "$dist_sum" ]; }
fresh() { rm -rf priv; }

echo "== a clone does not fetch, unless asked"
fresh; compile
check "builds with cargo" did_not_say "using the prebuilt"
check "priv is the cargo build" priv_is_not_dist

echo "== asked to fetch"
export OJAK_NIF_PREBUILT=1
fresh; compile
check "says it used the prebuilt" said "using the prebuilt library"
check "priv is the published library" priv_is_dist
compile
check "the second compile does not fetch again" did_not_say "using the prebuilt"
check "and does not build" did_not_say "building with cargo"
check "priv is still the published library" priv_is_dist

echo "== the checksum is wrong"
printf '%064d  %s\n' 0 "$lib" > "$work/serve/$lib.sha256"
fresh; compile
check "says why" said "checksum_mismatch"
check "builds with cargo instead" said "building with cargo"
check "the bad library is not used" priv_is_not_dist

echo "== no such release"
export OJAK_NIF_BASE_URL=http://127.0.0.1:$port/v9.9.9
fresh; compile
check "says 404" said "http, 404"
check "builds with cargo instead" priv_is_not_dist

echo "== OJAK_NIF_BUILD=1"
export OJAK_NIF_BASE_URL=http://127.0.0.1:$port
printf '%s  %s\n' "$dist_sum" "$lib" > "$work/serve/$lib.sha256"
fresh; OJAK_NIF_BUILD=1 compile
check "does not fetch" did_not_say "using the prebuilt"
check "priv is the cargo build" priv_is_not_dist

echo "== the Elixir tests, with the published library in place"
fresh; compile
mix test 2>&1 | tail -3
check "priv is the published library" priv_is_dist

[ "$failures" = 0 ] && echo "all ok" || { echo "$failures failed"; exit 1; }
