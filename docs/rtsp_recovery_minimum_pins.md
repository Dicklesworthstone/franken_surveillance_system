# Recover against an independently retained journal prefix

Ordinary, progress-supervised and reconnect captures accept an optional rollback fence
with either `--recover yes` or `--recover index`:

```sh
fss-capture-rtsp [ORIGINAL CAPTURE OPTIONS] \
  --recover yes \
  --minimum-pin-anchors "1:${SAVED_SEQUENCE}:${SAVED_ROOT}"
```

`SAVED_ROOT` is the complete `sha256:HEX` journal root and `SAVED_SEQUENCE` is its
one-based record sequence, saved independently from an earlier native capture or
recovery report. These are the `journal.sequence` and `journal.root` coordinates,
not the work root, recording window root, or capture approval. The first number is
the one-based attempt ordinal: single capture permits only `1`.

For a reconnect capture, retain the original `reconnect` subcommand and all original
attempt/backoff/supervision options, and supply each independently known attempt:

```sh
fss-capture-rtsp reconnect [ORIGINAL RECONNECT OPTIONS] \
  --recover yes \
  --minimum-pin-anchors "1:${FIRST_SEQUENCE}:${FIRST_ROOT},2:${SECOND_SEQUENCE}:${SECOND_ROOT}"
```

Do not renumber attempts or copy one attempt's prefix to another. The journal scope
binds each original generation, namespace and clock. All listed prefixes must pass
before any attempt's original work is read or restored. Unlisted attempts keep their
existing semantics and gain no independent rollback guarantee; in particular, two
missing stores for an unlisted attempt remain unknown. A missing listed attempt is
a refusal. The same map works with the separately approved `--recover index` mode.

Remove the old `--approve` argument, review the new preview, and repeat with that
preview's exact approval. After pending work settles, repeat the original capture
options with `--recover index` and the same minimum, review its own preview, and
approve it separately. A capture or work-restoration approval never authorizes
catalog publication. See [single-capture recovery](rtsp_single_capture_recovery.md)
for the original scope, directory, native-limit, and import requirements.

## What the fence checks

The native archive-pin owner must find the exact saved sequence/root pair in the
current complete journal under its original scope and record/byte limits. A later
valid descendant is accepted, including a confirmation whose reply was lost.
A shorter journal, different history, or missing stores refuses before any source
read or recovery/catalog publication. All journal locks stay held through the
existing all-selected-source preflight and publication protocol. No old candidate
is substituted when newer protected work is damaged.

The minimum changes only the recovery approval. Original capture paths, source
identity, receive/decode clocks, generations, codec, supervision and native work
ceilings do not change. The actual current tip and directory identities remain
bound to the approval. A legitimate newer tip therefore needs a fresh preview even
when the same independent minimum still passes. A previously unpinned approval
cannot be reused after adding a minimum. Omitting the option preserves the existing
capture and recovery identities and preview output.

Previews add `minimum_pin_anchors`, `minimum_prefixes_verified`, and
`minimum_prefix_scope`. Verification is of the named journal prefixes only. It is
not proof that media exists, that a camera session completed, that every other
attempt is protected, or that physical absence is certifiable. Source custody
remains a separate native verification step.

## Bounds and limitations

The shared representation is a comma-separated map of unique
`ATTEMPT:SEQUENCE:sha256:HEX` rows, bounded to 16 entries and 1,600 UTF-8 bytes.
Rows are canonically ordered by attempt; duplicate, empty, malformed, out-of-scope
and over-budget rows refuse. Supplying the option outside explicit recovery is an
argument error. Recovery creates neither an anchor store nor a signature service.

The operator must retain the minimum independently. Reading it back from the same
potentially rolled-back archive/journal does not provide independent protection.
Trusted directory ancestry and the existing exclusive-writer model still apply.
A hash-linked prefix is not authenticated server identity, encryption, a signature,
or proof against a hostile principal who controls both the journal and the saved
minimum. No camera connection, credential read, directory creation, tail truncation,
new recording, automatic retry, or authority expansion is introduced.

This is a reference slice of FSS-047/FSS-048/FSS-049 recovery semantics, not broad
adapter, camera, site, platform or release qualification. Rust test cases accompany
the implementation; their presence alone is not execution evidence.
