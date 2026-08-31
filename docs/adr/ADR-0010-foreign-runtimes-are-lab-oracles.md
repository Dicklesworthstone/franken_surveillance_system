# ADR-0010 — Foreign runtimes and incumbent implementations are laboratory oracles only

**Status:** Accepted

## Decision

FFmpeg/ffprobe, PyTorch/ONNX Runtime, NetworkX, C SQLite, Tantivy, browsers, and owner-authorized
vendor applications/SDKs may run in pinned isolated qualification environments. Their outputs are
untrusted comparator inputs. They do not ship, provide a production fallback, or define FSS
authority.

## Rationale

Incumbents are invaluable for differential conformance and reverse-engineering exact behavior. They
are not needed in the production closure once focused first-party implementations exist. Keeping
oracles outside production preserves independence while making compatibility claims measurable.

## Consequences

Conformance accounting distinguishes agreement, divergence, error-only agreement, unexercised, and
intentional unsupported behavior. Oracle outage cannot affect production operation.
