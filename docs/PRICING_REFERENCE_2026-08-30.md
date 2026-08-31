# Object-storage pricing reference — 2026-08-30

This is a dated research input, not executable configuration. Re-check provider documentation
before implementation, deployment, or a cost claim.

## Cloudflare R2

The official pricing page consulted for this design lists Standard storage at **$0.015 per GB-month**,
Class A operations at **$4.50 per million**, Class B operations at **$0.36 per million**, and no
Internet egress charge from R2 itself, subject to the provider's current definitions and free tier.
R2 exposes an S3-compatible API with documented differences.

## Backblaze B2

The official pricing material consulted for this design lists pay-as-you-go storage at
**$6.95 per TB-month**, with free egress up to three times average monthly stored data and additional
provider/partner terms that must be evaluated for the actual access pattern.

## FSS rule

Provider prices, request classes, minimum-storage rules, retrieval/egress policies, and effective
dates belong in a signed runtime pricing manifest. The archive planner reports storage, request,
retrieval/egress, and local-compute costs separately. This document must never be imported as a
permanent constant.

See [`REFERENCES.md`](REFERENCES.md) for official source URLs.
