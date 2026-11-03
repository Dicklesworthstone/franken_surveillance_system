#!/bin/bash
# Compatibility entrypoint: the implementation (and its tests) live in
# deliverables/scripts/c660_convert_watch.sh.
#
# The launchd plist used to name a path inside an ntm worktree, so pruning that worktree armed
# nothing at all. launchd names this file, which resolves the implementation at run time.
exec "$(cd "$(dirname "$0")" && pwd)/../scripts/c660_convert_watch.sh" "$@"
