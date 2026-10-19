# Retained camera localization and native replay

`fss-file localize --retain-result yes` closes the gap between a useful camera-pose proposal
and a proposal that can be independently reproduced after the owner files disappear. It
retains the exact property-twin archive, the exact localization atlas archive, every semantic
input to the computation, and the complete candidate receipt in a ledgered publication. Its
immutable identity can then be read or natively verified from the deployment alone.

The existing `localize` command keeps its behavior unless `--retain-result yes` is supplied.
Both paths still produce inactive pose candidates, explicit insufficient-match outcomes or
bounded geometric failures. They do not activate calibration, certify coverage, authenticate
the map author's claims, or establish absence from a recording.

## Publish a replayable result

Use the existing owner-pinned localization arguments and add `--retain-result yes`:

```sh
fss-file localize --root deployment --site site:property \
  --import-id sha256:IMPORT --segment 0 --interpretation gray \
  --twin property.fsstwin --twin-sha256 sha256:TWIN --scene-sha256 sha256:SCENE \
  --property 1 --revision 1 \
  --atlas property.fssatlas --atlas-sha256 sha256:ATLAS \
  --atlas-provenance-sha256 sha256:PROVENANCE \
  --image-mode pinhole --camera 1920,1080,1200,1200,960,540 \
  --image-domain sha256:IMAGE_DOMAIN \
  --report-out proposal.json --receipt-out proposal.receipt --retain-result yes
```

The uppercase digest names above are placeholders for complete 64-digit SHA-256 values.
The supplied camera parameters and image domain must describe the actual native image grid.
Raw-lens input instead uses the existing `--image-mode raw`, source camera, distortion,
calibration, maximum radius and luma-range arguments. AVC and HEVC require the existing
explicit random-access range and YCbCr interpretation; the selected segment remains its
original coding-order index even when output pictures reorder for display.

On success the command additionally prints:

```text
localization_identity=sha256:...
localization_root=sha256:...
localization_receipt=sha256:...
```

Preserve all three values when passing the result to another operator. The identity is the
digest of the complete canonical recipe, the root names its publication, and the receipt
digest pins the exact candidate result. The root is published only after all package objects
are staged and verified. Its normal `local_root_reachability` ledger record completes the
publication. The package uses the `recorded-localization-<identity hex>` slot and canonical
domain `fss.recorded_twin_localization_package.v1` (FMT-009). The existing candidate receipt
format is unchanged.

The recipe freezes source import identity and original authority anchor; selected segment
and range; all read and codec limits; component interpretation; current privacy binding;
exact twin, scene, atlas, atlas provenance and descriptor-generation pins; camera/lens and
image-domain inputs; and complete extraction, matching and pose solver options. Its children
retain the original import root, candidate receipt, both archives, recipe, and the existing
JPEG decode root when applicable. Video decoding remains read-only and adds no decode root.
The process-local geometry basis is freshly allocated when the archives are imported; it
is not serialized as if it were a durable object identity.

## Inspect or independently reproduce it

Reading checks immutable package objects, complete twin/atlas byte custody, root-to-ledger
closure, retained-source/capsule bindings and the sensor's current privacy binding. It
does not execute the codecs or prove that the candidate computation is correct:

```sh
fss-file read-localization --root deployment --site site:property \
  --localization-id sha256:IDENTITY --expected-root sha256:ROOT \
  --expected-receipt sha256:RECEIPT --receipt-out retained.receipt
```

It reports `native_replay_verified=false`. Native verification is a separate explicit action:

```sh
fss-file verify-localization --root deployment --site site:property \
  --localization-id sha256:IDENTITY --expected-root sha256:ROOT \
  --expected-receipt sha256:RECEIPT --execute-perception yes \
  --report-out reproduced.json
```

This command imports the retained archives under their exact generation pins, independently
decodes the retained encoded JPEG/AVC/HEVC bytes, applies the current retained privacy mask,
and runs the recorded image preparation, native feature extraction, matching and pose search.
For JPEG, the existing luma derivative is reopened and verified against a new native decode;
a matching digest of cached luma alone does not satisfy replay. The complete reproduced
candidate receipt must match byte for byte, including source and native decoder receipts,
privacy, image/lens parameters, descriptor decisions, solver candidates and localizer work.
Only then does it report `native_replay_verified=true` and optionally export the pose report.

Neither inspection nor native verification stages package objects, publishes a root, appends
authority, or activates a calibration. Wrong root/receipt pins, missing or corrupted archives,
unavailable source/decode custody, current privacy changes, unsupported native decode,
cancellation, work exhaustion and divergent results all refuse. Unknown options and attempts
to replace the retained camera, source or archive parameters are rejected by the CLI parser.
Exports retain the existing create-only, outside-deployment file policy.

## Bounds and recovery

The canonical recipe is capped at 4 KiB; the twin archive at its owner's existing 64 MiB
limit; the atlas at 8 MiB; and the candidate receipt at 256 KiB. Existing localizer bounds
remain: at most 1,024 coded segments, a maximum image axis of 4,096 and at most 4,194,304
pixels, 512 query features and 1,024 RANSAC trials. Existing codec, archive, spool and ledger
limits can refuse an input earlier.

The caller's `--work-units` and `--geometry-work-units` are current cumulative execution
allowances. They do not replace any retained semantic recipe parameter. Geometry work defaults
to 2,000,000,000 units. Package reads reserve the admitted byte ceiling before the spool
allocates or hashes an object, so a tiny twin still consumes a 64 MiB read allowance. The CLI's
initial open plus verification admits three twin/atlas walks, approximately 216.5 MiB in byte
allowances, plus actual archive import and localization work. `total_geometry_work_units`
reports this combined budget usage; `geometry_work_units` inside the candidate report records
only the localizer computation and remains identical under native replay. These deterministic
counters are not measured CPU time. Larger admitted inputs may require an explicit larger
execution allowance.

V1 retained localization requires an **unpartitioned source import**. Large imports whose
metadata has independent `part_roots` are refused before any native work or localization
publication. Flattening those independent publications into one localization root would
defeat their ledger and manifest bounds. Existing localization without `--retain-result yes`
continues to use its previous source admission rules.

An exact retry revalidates existing objects and resumes a root-to-ledger interruption without
creating a second completed publication. A visible root without its corresponding ledger
record cannot be read as a completed localization. Retrying a completed but damaged package
does not silently repair it. Cancellation before the final publication boundary may leave
staged, unreferenced package objects, which are not a completed result. The independent JPEG
derivative may already have been published before a later localization or publication refusal.

The retained archives contain all geometry and native descriptor inputs required for replay.
Their authoring scene and reference-photograph identities remain provenance pins; this package
does not claim to retain those original authoring files or independently authenticate their
contents. Reproducing a pose proposal also does not qualify it for calibration adoption or
replace the separate held-out evidence and operator adoption gates.

## Native contracts

The retained localization contracts in `recorded_twin_localization_contract` cover accurate
raw JPEG pose reproduction after cold reopen, mandatory native JPEG work despite cached luma,
AVC/HEVC coding-order selection, exact retry, missing archive and current privacy refusal,
fully ledgered rehashed candidate forgery, root-to-ledger interruption, cancellation and
zero-work partitioned-source refusal. `retained_localization_cli` exercises separate CLI
processes after the loose recording/twin/atlas files have been removed, exact receipt/report
equality, wrong pins, explicit execution, bounded refusal and unchanged authority journal.
