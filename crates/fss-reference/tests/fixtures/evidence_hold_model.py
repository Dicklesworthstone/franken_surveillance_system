#!/usr/bin/env python3
"""Independent abstract hold/deletion model, not execution of the Rust implementation."""
from itertools import permutations
import hashlib
import json


def dag_cases() -> int:
    # Three imports, then three derivative nodes, each referencing any earlier node.
    # An independent recursive ancestry oracle is compared with iterative closure intersection.
    choices = [(dst, src) for dst in range(3, 6) for src in range(dst)]
    count = 0
    for mask in range(1 << len(choices)):
        edges = {node: set() for node in range(6)}
        for bit, (dst, src) in enumerate(choices):
            if mask & (1 << bit):
                edges[dst].add(src)

        def depends(node: int, source: int) -> bool:
            return node == source or any(depends(parent, source) for parent in edges[node])

        closures = []
        for source in range(3):
            closure = {source}
            while True:
                extended = closure | {n for n in range(3, 6) if edges[n] & closure}
                if extended == closure:
                    break
                closure = extended
            closures.append(closure)
        for target in range(3):
            for held_mask in range(8):
                held = {n for n in range(3) if held_mask & (1 << n)}
                actual = target in held or any(closures[target] & closures[h] for h in held)
                expected = any(depends(node, target) and any(depends(node, h) for h in held) for node in range(6))
                assert actual == expected, (mask, target, held_mask)
                count += 1
    return count


class Store:
    def __init__(self):
        self.head = 0
        self.state = None
        self.last = None
        self.deletion = False
        self.removed = False

    def preview(self, state):
        if self.last is not None and self.last[0] == state:
            return self.last
        if self.deletion or self.removed or self.state == "released":
            raise ValueError("mutation refused")
        if (self.state, state) not in ((None, "held"), ("held", "released")):
            raise ValueError("transition refused")
        return (state, self.head, hashlib.sha256(f"{state}:{self.head}:owner:import".encode()).hexdigest())

    def hold_commit(self, proposed):
        if self.preview(proposed[0]) != proposed:
            raise ValueError("stale")
        if self.last == proposed:
            return
        self.state = proposed[0]
        self.last = proposed
        self.head += 1

    def deletion_preview(self):
        return self.head, self.state

    def delete_commit(self, proposed):
        if proposed != self.deletion_preview() or self.state == "held":
            raise ValueError("stale or blocked")
        self.deletion = True
        self.head += 1
        self.removed = True


def concurrency_cases() -> int:
    count = 0
    for order in permutations(("hp", "hc", "dp", "dc")):
        if order.index("hp") > order.index("hc") or order.index("dp") > order.index("dc"):
            continue
        store = Store()
        hold = delete = None
        for step in order:
            try:
                if step == "hp":
                    hold = store.preview("held")
                elif step == "hc" and hold is not None:
                    store.hold_commit(hold)
                elif step == "dp":
                    delete = store.deletion_preview()
                elif step == "dc" and delete is not None:
                    store.delete_commit(delete)
            except ValueError:
                pass
            assert not (store.state == "held" and store.removed)
        count += 1
    store = Store()
    hold = store.preview("held")
    store.hold_commit(hold)
    store.hold_commit(hold)
    assert store.head == 1
    release = store.preview("released")
    assert release != hold
    store.hold_commit(release)
    store.hold_commit(release)
    assert store.head == 2
    try:
        store.hold_commit(hold)
    except ValueError:
        pass
    else:
        raise AssertionError("old placement reactivated released identity")
    store.delete_commit(store.deletion_preview())
    assert store.removed
    return count


if __name__ == "__main__":
    print(json.dumps({"dag_cases": dag_cases(), "concurrent_prepare_commit_orders": concurrency_cases(),
                      "result": "passed", "rust_executed": False}, sort_keys=True))
