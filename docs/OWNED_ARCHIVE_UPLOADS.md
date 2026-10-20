# Owned multipart upload and reconciliation

`fss-object::uploader::StagedUpload` prepares and retains the actual `ObjectStore` child authority,
its reserved budget, a pending drain obligation and its multipart session. Preparation performs no
provider I/O. The first `start` or `upload_chunks` call initiates a stable intent binding the operation,
exact resource, full canonical chunk plan and final manifest root.

Every transport call receives an admitted `TransportCx` for that same child. Admission verifies the
canonical region tree and operation, resource-scoped object/network grants, caller time, deadline,
cancellation and available budget. Payload and requests are charged before dispatch; adapters can
charge framing/response I/O through the same context. The parent retains the full reservation until
terminal child quiescence, after which only unused allowance is returned.

Provider ETags are opaque tokens. Each part receipt separately binds its exact index and SHA-256
content digest. A replay with changed bytes, plan, cost row, root or resource cannot silently replace
the original intent. Complete publication requires every part, in canonical order, and the exact
root selected at preparation.

## Lost acknowledgements remain owned

Initiation, part upload, completion and abort failures leave an explicit `Uncertain` phase. The
caller retains its session and upload owner; these methods borrow rather than consume them. New
effects are refused until a read-only, intent-bound reconciliation produces a conclusive observation.

| Provider observation | Permitted outcome |
|---|---|
| `Unknown` | Keep uncertainty, owner and pending obligation |
| `NotStarted` after uncertain initiation | Retry only the same stable intent |
| Exact `Active` inventory | Resume the same upload, retaining all acknowledged part identities |
| Exact `Completed` after uncertain completion | Return the bound completion receipt and settle the child |
| Exact `Aborted` after uncertain abort | Return the abort receipt and settle the child |

An eventually consistent listing, partial inventory, missing object or timeout does not establish a
terminal outcome. It must remain `Unknown`. A lost completion acknowledgement never authorizes a
blind abort. A cancellation request is explicitly nonterminal until staging is conclusively released.

New work preserves an operation for cleanup. Bounded abort and reconciliation remain possible after
cancellation or deadline expiry, subject to the same scoped grants and remaining allowance. Read-only
reconciliation may use the final request to establish the outcome of a prior effect. The published
minimum budget covers the payload and initiation, completion, reconciliation, abort and a final
reconciliation; real adapters must separately reserve wire framing and any additional retries.
Exhausted allowance leaves visible pending work and never fabricates a successful drain receipt.

Only a conclusive terminal receipt resolves the child's obligation, drains/finalizes that actual
child and refunds its exact parent's unused reservation. Dropping an unfinished handle leaves a
pending canonical child obligation that prevents a false parent shutdown claim.

## Scope and verification

This implements the injected multipart protocol and **in-process** ownership/recovery boundary for
FSS-063/FSS-064/FSS-130. It does not implement a native network S3 transport, durable upload restart
journal, byte encryption or independent archive retrievability verification. A real provider adapter
must enforce intent idempotency and checksum conditions, use the admitted context at its actual I/O
boundary, and return `Unknown` when its consistency guarantees cannot resolve an uncertain effect.

```sh
cargo test --locked --offline -p fss-object --test multipart_family --test uploader_family
```

The focused fault-injection targets cover lost acknowledgements at all four effect boundaries,
opaque ETags, altered bytes/root/plan, incomplete or forged reconciliation, actual child authority,
grant revocation, cancellation, deadlines, minimum cleanup allowance, framing I/O, exact refunds,
duplicate preparation, wrong trees and parent quiescence.
