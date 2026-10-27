# Frozen ONVIF metadata v1 custody fixtures

These fixtures independently encode the v1 recipe, projection and object manifest
defined at commit `8a6195debaa425a1e82e369379e1e8379b50b229`. They were assembled
from the inspected CanonicalEncoder and v1 record layouts, without invoking the
new parser or import writer. Tests publish their exact bytes through the normal
publication owner and exercise cold verification against hard-coded digests.

The `.hex` files contain lowercase hexadecimal with one trailing newline; their
decoded bytes are the historical canonical objects. XML has no appended newline.
`goldens.json` records the decoded byte lengths, hashes and exact owner bindings.

- `legacy_analytics` omits CenterOfGravity, which v1 never interpreted.
- `legacy_opaque_invalid_time` also contains a vendor timestamp outside the v2
  supported grammar. It must remain readable under v1 without fallback parsing.
- `legacy_supported_analytics` is interpretable by both generations. V1 must keep
  its VideoAnalytics section opaque; a new v2 import has a distinct projection
  and custody identity while preserving the same original source digest.

All labels and generations are synthetic. These fixtures establish no camera,
Profile M, capture-time, recognition-quality, coverage or effect-authority claim.
