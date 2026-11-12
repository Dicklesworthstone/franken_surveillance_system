#!/bin/bash
# Round-trip a fresh standard LZMA2 stream through the patched SDK harness.
# The vendor format needed several SDK patches; this proves the patched decoder is still
# byte-exact for *standard* streams, which every vendor claim must not regress.
#   usage: lzma2_roundtrip.sh <harness> [bytes]
set -u
H=${1:?harness path}
N=${2:-100000}
D=$(mktemp -d)
head -c "$N" /dev/urandom > "$D/plain"
xz --format=raw --lzma2=dict=6144 -c "$D/plain" > "$D/stream"
"$H" "$D/stream" 0 40 0 2>/dev/null > "$D/out"
if cmp -s "$D/out" "$D/plain"; then echo "ROUNDTRIP OK ($N bytes)"; exit 0; fi
echo "ROUNDTRIP FAIL: $(wc -c < "$D/out") of $N bytes"; exit 1
