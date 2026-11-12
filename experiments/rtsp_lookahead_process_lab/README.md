# RTSP lookahead process fixture

This package runs the existing `fss-cli` process fixture without building all
of that package's unrelated binaries. It uses the same dependency versions as
the workspace lockfile. The operator supplies explicit paths for separately
built, hash-checked Linux binaries through `FSS_CAPTURE_RTSP_BIN`,
`FSS_IMPORT_RTSP_BIN`, `FSS_ARCHIVE_BIN`, and `FSS_FILE_BIN`.

The `source_lookahead_records_variable_intervals_and_accounts_for_final_picture`
test uses a synthetic loopback RTSP camera. It is not evidence of physical
camera identity, direct UniFi control, continuous recording, or retention.
