# Source-linked ONVIF lifecycle claims

The additive `parse_metadata_lifecycle_document` API interprets ObjectTree and
Behaviour declarations from original MetadataStream XML. It provides typed
rename, merge, split and delete claims, plus separate idle and removed flags.
These remain statements made by the vendor analytics module. They do not establish
physical identity, movement, departure, coverage or effect authority.

## Supported interpretation

The parser follows the bounded integer-reference subset of the official
[metadata stream schema](https://github.com/onvif/specs/blob/development/wsdl/ver10/schema/metadatastream.xsd),
schema version 25.12, exact source blob
`ba3726fef2d3424486883079f9a520ee069698f0`.

| Claim | Supported structure |
|---|---|
| Rename | One lowercase `from`, followed by one lowercase `to` |
| Merge | At least two `from` references, followed by one `to` |
| Split | One `from`, followed by at least two `to` references |
| Delete | An ObjectId reference on the Delete element |
| Idle / Removed | Separate optional Behaviour flags; neither deletes an ID |

The normative endpoint names are lowercase even though some prose examples use
uppercase. Namespace lookalikes and invalid known cardinalities cannot become
supported claims. Missing integer IDs and UUID references remain explicitly
unsupported; UUIDs are never used for matching. Unknown nodes and attributes are
counted and remain available in the original source.

Frames, objects and operations preserve their original order and exact XML child
positions. Integer and timestamp spellings are retained, and private values are
excluded from Debug output. Interpretation preserves repeated claims instead of
coalescing them. Geometry and class fields remain the separate analytics owner's
responsibility.

## Frozen compatibility

The independent generation is `gen:fss1:onvif-vendor-lifecycle-v1`. Existing
event-v1 and analytics-v2 parsing and canonical bytes remain unchanged. In
particular, analytics-v2 still records ObjectTree and Behaviour as uninterpreted
content. Existing retained roots and tracklets-v1 are not silently reinterpreted.
This parser accepts MetadataStream only; SOAP PullMessages is outside its subset.

## Cost and validation

The existing XML limits remain 256 KiB, 4096 nodes and depth 32. Additional
per-document ceilings are 128 frames, 512 objects, 1024 operations and 2048
references. `LifecycleParseLimits` can tighten each ceiling. The public
`lifecycle_parse_work_bound` quotes the full conservative reservation before XML
parsing: eight units per source byte, plus 128 per possible node, plus one. The
hard work ceiling is 4 Mi units. These units describe deterministic admission
accounting, not CPU time. Cooperative cancellation is checked before and after
XML parsing, throughout interpretation and before a successful return.

The actual production parser target passed 28 tests: 24 focused lifecycle cases
and four existing embedded wire tests. The focused cases include frozen-v1/v2
compatibility, normative cardinalities, unknown and missing references, private
diagnostics, all aggregate limits, exact work reservation and every cancellation
cut. Scoped Clippy also passed. These parser results do not establish native
retained-owner execution or physical-device/Profile M qualification.

```sh
cargo test --locked --offline -j1 -p fss-core --test onvif_lifecycle_wire_contract
```
