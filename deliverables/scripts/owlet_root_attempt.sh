#!/bin/sh
# One-command Owlet root attempt: fires the full mint->probe->ACK->0x06E3->avClientStart
# chain ONLY when .4.163 answers (ARP present or frames on the wire); exits 1 silently
# otherwise. Safe to run on a tick — the liveness gate is inside.
PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin
export PATH
HERE=$(cd "$(dirname "$0")" && pwd)
exec sudo -n python3 "$HERE/owlet_root_attempt.py" "$@"
