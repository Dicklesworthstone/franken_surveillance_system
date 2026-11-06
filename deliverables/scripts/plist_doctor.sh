#!/bin/bash
# Launchd/plist fleet doctor — validate every com.jeffreyemanuel.* plist BEFORE it costs hours.
#
# Born from the 2026-11-06 8883 outage (12h broker death, 1094 'PEM lib' crashes):
#   1. a root plist ProgramArguments pointed at a STALE WORKTREE copy of wyze_ota_arm.sh
#      (.ntm/worktrees/...omp_3) whose cert code had the known cert+key-concat defect;
#   2. the SAME label (com.jeffreyemanuel.wyze-broker) was loaded in BOTH the system
#      domain (/Library/LaunchDaemons) and the user domain (~/Library/LaunchAgents),
#      so two KeepAlive supervisors raced each other's bring-up generations;
#   3. plist env OTA_MD5 / CAP_PATH / CAM_MAC drifted from the served capsule bytes.
# A 30-second preflight would have caught all three. This is that preflight.
#
#   plist_doctor.sh [--json] [--only LABEL]
#
# Exit 0 = every plist passes; exit 1 = at least one finding. Read-only: this
# never edits, unloads, or deletes anything (machine RULE 1: no deletions
# without explicit approval). --fix is deliberately NOT implemented; findings
# name the exact key so any agent can fix in one deliberate step.
#
# Checks per plist:
#   P1  ProgramArguments paths exist and are NOT under a worktree (.ntm/, *worktree*)
#   P2  label domain placement: loaded in system xor gui — both is a finding
#   P3  env coherence for known labels (wyze-broker: CAP_PATH file exists,
#       OTA_MD5 == md5 of that file, CAM_MAC/MAC normalization consistent)
#   P4  StandardOut/StandardError paths writable by the owning domain's user
set -u
JSON=0
ONLY=""
[ "${1:-}" = "--json" ] && { JSON=1; shift; }
[ "${1:-}" = "--only" ] && { JSON=0; ONLY="${2:-}"; shift 2; }

FINDINGS=0
CHECKED=0
OUT=""

add() { # add <severity> <plist> <check> <detail>
  FINDINGS=$((FINDINGS+1))
  [ -n "$OUT" ] && OUT+=",
"
  OUT+="$(printf '{"severity":"%s","plist":"%s","check":"%s","detail":"%s"}' "$1" "$2" "$3" "$4")"
}

norm_mac() { # zero-padded, separators stripped, lowercase — same rule as wyze_mitm_up.sh
  local f out=
  for f in $(echo "$1" | tr 'A-F' 'a-f' | tr ':.-' '   '); do
    out="$out$(printf '%2s' "$f" | tr ' ' 0)"
  done
  echo "$out"
}

# domain placement: loaded where?
domain_of() { # label -> "system" | "gui" | "both" | "none"
  local label=$1 s=g n=g
  sudo -n launchctl print "system/$label" >/dev/null 2>&1 && s=y
  launchctl print "gui/$(id -u)/$label" >/dev/null 2>&1 && n=y
  if [ "$s" = y ] && [ "$n" = y ]; then echo both
  elif [ "$s" = y ]; then echo system
  elif [ "$n" = y ]; then echo gui
  else echo none; fi
}

plists() {
  cat /Library/LaunchDaemons/*.plist 2>/dev/null
  cat ~/Library/LaunchAgents/com.jeffreyemanuel.*.plist 2>/dev/null
}

# iterate the union of root + user plists with the jeffreyemanuel label
for pl in /Library/LaunchDaemons/com.jeffreyemanuel.*.plist ~/Library/LaunchAgents/com.jeffreyemanuel.*.plist; do
  [ -f "$pl" ] || continue
  label=$(basename "$pl" .plist)
  [ -n "$ONLY" ] && [ "$label" != "$ONLY" ] && continue
  CHECKED=$((CHECKED+1))

  # P1: argument paths exist, not worktree
  i=0
  while :; do
    i=$((i+1))
    arg=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:$i" "$pl" 2>/dev/null) || break
    case "$arg" in
      /*) ;;
      *) continue ;;  # not a path-looking arg (bash flags etc.)
    esac
    case "$arg" in
      *.sh|*/scripts/*|*/bin/*)
        if [ ! -e "$arg" ]; then
          add error "$pl" "P1-path-missing" "$arg does not exist"
        elif printf '%s' "$arg" | grep -qE '/\.ntm/|worktree'; then
          add error "$pl" "P1-worktree-path" "$arg is under a worktree — runtime truth must be the canonical checkout"
        fi
        ;;
    esac
  done

  # P2: domain placement
  dom=$(domain_of "$label")
  case "$dom" in
    both) add error "$pl" "P2-duplicate-domain" "label loaded in BOTH system and gui domains — KeepAlive supervisors race (the 2026-11-06 broker outage)" ;;
    none) add warn  "$pl" "P2-not-loaded"   "plist exists on disk but is not loaded in any domain" ;;
  esac

  # P3: env coherence for known labels
  if printf '%s' "$label" | grep -q 'wyze-broker'; then
    cap=$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:CAP_PATH' "$pl" 2>/dev/null || true)
    md5v=$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:OTA_MD5' "$pl" 2>/dev/null || true)
    cam=$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:CAM_MAC' "$pl" 2>/dev/null || true)
    mac=$(/usr/libexec/PlistBuddy -c 'Print :EnvironmentVariables:MAC' "$pl" 2>/dev/null || true)
    if [ -n "$cap" ]; then
      f="/tmp/fwserve/$cap"
      if [ ! -s "$f" ]; then
        add error "$pl" "P3-capsule-missing" "CAP_PATH=$cap but $f is missing/empty"
      elif [ -n "$md5v" ]; then
        actual=$(md5 -q "$f" 2>/dev/null)
        [ "$actual" = "$md5v" ] || add error "$pl" "P3-md5-mismatch" "OTA_MD5=$md5v but $f is $actual (device stops at the MD5 gate)"
      fi
    fi
    if [ -n "$cam" ] && [ -n "$mac" ]; then
      [ "$(norm_mac "$cam")" = "$(norm_mac "$mac")" ] || add error "$pl" "P3-mac-divergence" "CAM_MAC=$cam vs MAC=$mac normalize differently"
    fi
  fi

  # P4: log paths writable by the right user (root daemon -> root-writable is fine;
  # user agent -> must be user-writable or the plane dies silently at first write)
  case "$pl" in
    ~/Library/LaunchAgents/*|*LaunchAgents*)
      for key in StandardOutPath StandardErrorPath; do
        lp=$(/usr/libexec/PlistBuddy -c "Print :$key" "$pl" 2>/dev/null) || continue
        ldir=$(dirname "$lp")
        [ -d "$ldir" ] || { add error "$pl" "P4-logdir-missing" "$ldir does not exist"; continue; }
        [ -w "$lp" ] || [ -w "$ldir" ] || add error "$pl" "P4-logdir-unwritable" "$lp not writable by user (plane dies silently on first write)"
      done
      ;;
  esac
done

if [ "$JSON" = 1 ]; then
  printf '{"checked":%d,"findings":%d,\n"items":[\n%s\n]}\n' "$CHECKED" "$FINDINGS" "$OUT"
else
  echo "== plist doctor: checked $CHECKED plists, $FINDINGS findings"
  if [ "$FINDINGS" -gt 0 ]; then
    printf '%s' "$OUT" | /usr/bin/python3 -c '
import json, sys
for line in sys.stdin.read().replace("},\n{", "}\n{").splitlines():
    if not line.strip(): continue
    d = json.loads(line)
    mark = "✗" if d["severity"] == "error" else "⚠"
    print(f"  {mark} {d[\"check\"]}: {d[\"plist\"].split(\"/\")[-1]} — {d[\"detail\"]}")
'
  fi
fi

[ "$FINDINGS" -eq 0 ]
