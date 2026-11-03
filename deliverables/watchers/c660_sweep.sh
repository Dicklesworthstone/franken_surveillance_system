#!/bin/bash
# Compatibility entrypoint: the implementation (and its tests) live in
# deliverables/scripts/c660_sweep_watch.sh.
#
# The inline version that used to live here could never fire: its ARP match did `octet + 0` in
# awk, so the hex octets `3d`/`d1`/`2f`/`b9` truncated to `3`/`0`/`2`/`0`. It also fired against
# stale ARP entries with no ICMP check and resumed a stale brute index across batches.
exec "$(cd "$(dirname "$0")" && pwd)/../scripts/c660_sweep_watch.sh" "$@"
