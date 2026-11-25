# Live daemon manifest changes

`ReloadManifest` validates the complete candidate before changing live camera
metadata or perception. A refused reload leaves the active manifest and camera
owners unchanged, and the daemon continues supervising its existing sources.

## Changes requiring restart

The following settings belong to resources constructed at startup. Change them
with a drained restart rather than a live reload:

| Resource | Settings |
|---|---|
| Deployment and IPC identity | Site ID, deployment root, IPC override |
| Storage owners | Capacity, watermarks, pack target, scrub budget, hot retention |
| Camera inventory | Camera additions, removals, or sensor identity replacement |
| Source and credentials | Adapter, endpoint, secret handle, authentication realm, RTSP session options |
| Frame and coverage binding | Dimensions and primary zone |
| Bounded camera buffers | Ring frame and byte limits |
| Resident detector contract | Minimum score threshold |

The resident model cache identifies a package by digest and execution profile;
changing its immutable score contract requires restart with the current cache.

New manifest fields are refused until their live activation semantics are
explicitly implemented. A reload mixing supported and unsupported changes is
refused as a whole.

## Supported live changes

The daemon can apply detector package path/digest, topology, OSD ignore
rectangles, priority, zone memberships, failure domains, reconnect bounds, stall
timeout, and GOP frame count. A detector package requires its exact digest and
successful local loading before activation.

An identical manifest emits `manifest_reload_unchanged` without rebuilding the
perception pipeline. Timing or GOP changes preserve accumulated clock and
perception state. Changing reconnect bounds rebuilds only the affected camera's
backoff; an already scheduled reconnect is rescheduled within the new bounds.

Every reload outcome includes the queued operation ID. A
`manifest_reload_refused` delta includes a stable error ID, and restart refusals
name the unsupported field. A successful reload retains the
`manifest_reloaded site=...` outcome prefix.

## Regression checks

```sh
bash scripts/check_daemon_contracts.sh
```

This runs the locked, offline daemon suite, including atomic refusal, camera
inventory, supported updates, no-op preservation, invalid detector packages, and
correlated IPC reload outcomes. The existing hosted reference workflow runs the
same command as supplementary feedback. Local DSR qualification remains the
authority for release and deployment claims.
