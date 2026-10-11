#!/usr/bin/env python3
"""scripts/sibling_closure.py — exact sibling-closure digest (FSS-185, bead fss-x4a.26.5).

The qualification receipt's siblingClosureDigest binds the run to the exact
sibling revision closure: the franken-import registry, the dependency
allowlist, and the pinned toolchain file. The computation is deterministic,
order-fixed, and fails closed on an unreadable input. qualify.sh calls this
module (the digest was previously computed by an inline heredoc — identical
output, now independently testable).

DSR transports may instead supply FSS_DSR_SIBLING_CLOSURE_DIGEST; qualify.sh
prefers that override when set, and this module is the local default.
"""

import hashlib
import pathlib
import sys

# The exact sibling-closure input set (order pinned).
SIBLING_INPUTS = ["architecture/franken_imports.json", "architecture/dependency_allowlist.toml", "rust-toolchain.toml"]


def compute_sibling_digest(root: pathlib.Path) -> str:
    """SHA-256 over name\0bytes pairs in pinned order. Fails closed on a
    missing/unreadable input (no partial-closure digest is ever produced)."""
    parts = []
    for name in SIBLING_INPUTS:
        path = root / name
        data = path.read_bytes()  # raises FileNotFoundError/OSError on failure
        parts.append(name.encode() + b"\0" + data)
    return "sha256:" + hashlib.sha256(b"\0".join(parts)).hexdigest()


def main() -> int:
    root = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path(".")
    try:
        print(compute_sibling_digest(root))
    except (FileNotFoundError, OSError) as exc:
        print(f"sibling closure inputs unreadable: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
