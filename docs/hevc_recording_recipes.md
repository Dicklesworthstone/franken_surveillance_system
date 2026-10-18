# Portable HEVC recipe reconstruction

An already-durable datagram prefix can now be paired with immutable HEVC
reconstruction instructions and processed through `fss-archive`. The operator
command never contacts a camera, restores a credential, guesses a clock, or
substitutes a codec. Source retention alone still does not supply original
parameter sets or independent media timing.

## Preparing the original instructions

The library namespace is `fss_reference::rtsp::recording_recipe::hevc`.
`RecordingRecipe::new` takes the recovered exact `DatagramArchive`, original
`HevcReplaySpec`, original `HevcRecordingReplaySpec`, an ordered vector of
`RecordingTimingDecision`, and externally supplied `RecordingRecipeLimits`.
Each decision binds the native `HevcPictureTimingRequest` and the observation
count at which it appeared, plus its explicit decode time, duration and signed
composition offset. Retain actual requests from `DatagramHevcRecordingReplay`;
RTP timestamps and host arrival times must not be promoted to decode timing.

`storage::PreparedRecordingRecipe::prepare` and `publish` use the existing
source-first/root-last publisher. Save the returned `RecordingRecipePin` outside
the process. Its `recipe` field hashes canonical instructions, while `root`
commits their manifest and every required original datagram root. A structural
recipe can be stored even when a later native request will reject a decision;
stored instructions are not proof that reconstruction succeeded.

Version 1 uses native IDR window cuts and one explicit final-prefix seal. It does
not encode arbitrary mid-prefix seal actions. A collector that needs an unrecorded
manual cut refuses instead of inventing one. The full encoding, original
VPS/SPS/PPS, per-component resource bounds, source pin and all timing decisions
are immutable. Configuration or source changes need new instructions and identity.
The recipe contains no raw media, network permission, operational deadline or
work-budget grant. Its root references the independently retained source.

There is no CLI recipe-authoring shortcut or automatic capture-time recipe
recording in this increment. Operators need a retained recipe and its original
source-scope fields before invoking the following commands.

## Checking and reconstructing

Use the exact recipe identities and original source fields, not a mutable latest
pointer. Both commands accept the same fields and current resource ceilings:

```text
fss-archive check-recipe --codec hevc \
  --root /absolute/existing/archive \
  --recipe-id sha256:RECIPE --recipe-root sha256:RECIPE_ROOT \
  --ingress ORIGINAL_INGRESS --generation ORIGINAL_GENERATION --ssrc ORIGINAL_SSRC \
  --peer ORIGINAL_IP:PORT --authority ORIGINAL_HOST \
  --rtp-channel 0 --rtcp-channel 1 \
  --receive-clock sha256:ORIGINAL_CLOCK \
  --retention-evidence sha256:ORIGINAL_RETENTION
```

Replace the placeholders with the independently accepted original values.
`check-recipe` loads the source-closed recipe, verifies the current entire source
chain, and executes the complete bounded native program without staging or
publishing output objects. Ordinary exclusive-open and recovery synchronization
still apply; this is not a forensic read-only open.

To publish, change the command to `reconstruct-recipe` and add `--commit yes`.
It first validates the entire program and holds its bounded completed windows.
A missing, unused or mismatched timing decision cannot publish earlier windows.
Only after preparation succeeds does it revalidate source, publish each native
HEVC recording, and publish the derived completion graph last. Existing different
roots, unexpected output ordinals, broken roots and unresolved temporary state
refuse. Repeating the exact command after a lost reply reuses the same window and
completion roots; it does not allocate another archive epoch or duplicate windows.
A failed publication can have committed earlier windows or an uncertain final
root. Retain the original pin/store and reconcile rather than deleting files.

Omitting `--codec`, or choosing `avc`, retains the existing AVC format, reporting
and approval behavior. HEVC is never autodetected from untrusted metadata.
`--commit` is inapplicable to `check-recipe`; all malformed options refuse before
opening storage. The existing limits include `--max-work`, `--max-steps`,
`--timeout-ms`, `--max-windows`, `--max-output-bytes`, `--max-datagrams`,
`--max-source-bytes`, `--max-recipe-bytes`, `--max-timings`, and spool ceilings.
These do not enlarge the compiled default native HEVC configuration ceilings.

## Reading the result correctly

The bounded `fss.local_reconstruction_operator.v1` report includes `codec: hevc`,
the exact recipe and result pins, publication status, completed windows and the
full current source head observed at load. Verified descendants outside the recipe
are excluded from replay; corrupt descendants still prevent a safe load.

`observations_read` counts original observations actually interpreted.
`remaining_datagrams` counts selected observations left after an actual in-band
end-of-bitstream. `end_of_bitstream` is true only for that native boundary, not
for exhaustion of the selected source. Queued NALs, incomplete groups and
fragments remain separately accounted for. `released_packets` means copies
released from active HEVC collection, including packets already represented in
windows; it is not an omission or extra-custody count.

The result always keeps `capture_complete: false` and
`archive_index_published: false`. The derived completion root establishes this
bounded reconstruction outcome, not physical continuity, a finished camera
session, decoded-pixel qualification or a catalog publication. Saved bytes that
cannot complete a picture remain incomplete, including zero-window outcomes.

## Validation and compatibility

`hevc_recording_recipe_contract`, `hevc_reconstruction_operation` and
`hevc_reconstruction_recipe_process` cover exact canonical decoding, component
ceilings, native-byte equality, cold source-closed loading, current authority,
full-program refusal, real EOB, output bounds, publication crash points, lost
acknowledgements, explicit codec/commit selection and real child-process checks.
Cold native HEVC pixel decoding checks the published windows after the operation
owners have been dropped. Existing AVC recipe/process tests remain the oracle for
unchanged defaults. Tests are native fixtures, not camera, power-loss, encryption,
always-on throughput or release qualification.
