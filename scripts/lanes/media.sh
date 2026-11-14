#!/usr/bin/env bash
# QL-MEDIA-001 — media probe lane (FSS-053).
#
# The probe is a contract on *exit status*, so the lane drives the real binary instead of only calling
# the library: a lane that passes without executing the shipped path proves nothing. Every fixture is a
# header prefix; the expected status is the assertion.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

# Reuse a binary if one is present: the lane is about behaviour, and rebuilds are the slowest thing in
# it (a flaky build queue must not read as a probe failure).
BIN=""
HOST="$(rustc -vV 2>/dev/null | sed -n 's/^host: //p')"
for candidate in "target/${HOST}/debug/fss-probe" target/*/debug/fss-probe target/debug/fss-probe; do
  [[ -x "$candidate" ]] && { BIN="$candidate"; break; }
done
if [[ -z "$BIN" ]]; then
  BIN="$("${RUN[@]}" cargo --offline build -q --message-format=json -p fss-cli --bin fss-probe \
    | python3 -c 'import json,sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("reason") == "compiler-artifact" and m["target"]["name"] == "fss-probe":
        print(m["executable"])')"
fi
[[ -x "$BIN" ]] || { printf 'fss-probe is neither built nor buildable\n' >&2; exit 1; }

check() { # check <expected-exit> <label> <printf-format>
  local want="$1" label="$2" fixture="$3"
  local got=0
  printf "$fixture" | "$BIN" --bytes 16 >/dev/null 2>&1 || got=$?
  if [[ "$got" != "$want" ]]; then
    printf 'probe %s: exit %s, wanted %s\n' "$label" "$got" "$want" >&2
    exit 1
  fi
  printf 'probe %s: exit %s\n' "$label" "$got"
}

checkp() { # checkp <expected-exit> <label> <printf-format>  — --parameters mode
  local want="$1" label="$2" fixture="$3"
  local got=0
  printf "$fixture" | "$BIN" --parameters --bytes 16 >/dev/null 2>&1 || got=$?
  if [[ "$got" != "$want" ]]; then
    printf 'parameters %s: exit %s, wanted %s\n' "$label" "$got" "$want" >&2
    exit 1
  fi
  printf 'parameters %s: exit %s\n' "$label" "$got"
}

check 0 matroska            '\x1a\x45\xdf\xa3matroska'
check 0 isobmff-brand       '\x00\x00\x00\x18ftypavc1'
check 0 jpeg                '\xff\xd8\xff\xe0ACameraX'
check 10 short-head         'FLV'
check 11 unknown            'RIFFxxxxWAVE'
checkp 10 parameters-short  '\x00\x00\x00\x01\x67'
