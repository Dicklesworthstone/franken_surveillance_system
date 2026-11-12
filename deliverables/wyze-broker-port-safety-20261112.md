# Wyze broker port isolation, 2026-11-12

The prior bring-up script enumerated listeners by TCP port across all local
addresses and sent SIGTERM to non-forge PIDs. A legitimate RCH listener on a
different address also uses port 9101. The script now leaves existing listeners
untouched, excludes 9101 from the cleanup sweep, and binds its image server to
the configured camera-facing `UP` address. An occupied port is reported rather
than cleared. A stale conflicting listener may therefore require separate
reconciliation; this change does not prove that the image server is serving.

The script was replaced atomically without restarting or stopping services.
`bash -n`, `git diff --check`, and static checks for the no-kill cleanup, scoped
bind, and excluded port passed. An isolated dynamic-shell behavioral check was
rejected by automatic safety review and was not executed. A proposed separate
address-specific health-check edit was also rejected by automatic review; the
existing generic 9101 health check can still mistake another listener for the
camera-facing image server. Do not treat that check as proof of service.

During a point-in-time observation after the change, RCH remained on the same
PID for several minutes and the G4 recorder and its local fallback timer were
active. A privileged read-only scan observed 61 fallback MP4 files updated in
the prior hour. The upload timer was active but its last service run failed;
recent logs contained a timeout. These observations do not establish
continuous coverage, successful remote upload, or that every broker generation
has loaded the revised script.
