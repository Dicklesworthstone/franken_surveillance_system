#!/usr/bin/env python3
"""Independent finite model of review approval, commit ordering and retry.

This is NOT execution of Rust. It models only lifecycle, expected-revision and
provenance/event publication ordering; it cannot qualify filesystem durability.
"""
from dataclasses import dataclass, field
from itertools import permutations, product

STATES = ("hypothesized", "witnessed", "corroborated", "adjudicated",
          "alert_delivered", "indeterminate", "resolved", "rejected")
TARGET = {"investigate": "indeterminate", "resolve": "resolved", "reject": "rejected"}
ALLOWED = {
    "hypothesized": {"indeterminate", "rejected"},
    "witnessed": {"indeterminate", "rejected"},
    "corroborated": {"indeterminate", "rejected"},
    "adjudicated": {"indeterminate", "resolved", "rejected"},
    "alert_delivered": {"indeterminate", "resolved", "rejected"},
    "indeterminate": {"indeterminate", "resolved", "rejected"},
    "resolved": set(), "rejected": set(),
}

@dataclass(frozen=True)
class Approval:
    base: tuple
    action: str
    actor: str
    reason: str

@dataclass
class Model:
    state: str
    revision: tuple = ("genesis",)
    head: int = 1
    effects: bool = False
    roots: set = field(default_factory=set)
    proposals: dict = field(default_factory=dict)
    # Protected state is deliberately orthogonal to operator lifecycle decisions.
    sources: tuple = ("sensor-evidence", "model-receipt", "uncertain-time", "open-tamper")
    appends: list = field(default_factory=list)

    def preview(self, owner, action):
        if self.effects or TARGET[action] not in ALLOWED[self.state]:
            return False
        self.proposals[owner] = Approval(self.revision, action, owner, "review rationale")
        return True

    def commit(self, owner, cut=False, changed_actor=False):
        p = self.proposals.get(owner)
        if p is None or changed_actor:
            return "refused"
        successor = ("review", p)
        if self.revision == successor:
            assert p in self.roots
            return "retry"
        if self.revision != p.base or self.effects or TARGET[p.action] not in ALLOWED[self.state]:
            return "refused"
        if p not in self.roots:
            self.roots.add(p)
            self.head += 1
        if cut:
            return "provenance_only"
        self.state = TARGET[p.action]
        self.revision = successor
        self.appends.append(successor)
        self.head += 1
        return "published"


def main():
    orders = [p for p in permutations(("pA", "cA", "pB", "cB"))
              if p.index("pA") < p.index("cA") and p.index("pB") < p.index("cB")]
    cases = 0
    for state, a, b, order, initial_effect, cut_owner, unrelated in product(
        STATES, TARGET, TARGET, orders, (False, True), (None, "A", "B"), (False, True)
    ):
        m = Model(state=state, effects=initial_effect)
        original = m.sources
        for op in order:
            owner = op[1]
            action = a if owner == "A" else b
            if op[0] == "p":
                before = (m.revision, m.state, m.head, frozenset(m.roots))
                m.preview(owner, action)
                assert (m.revision, m.state, m.head, frozenset(m.roots)) == before
            else:
                if unrelated:
                    m.head += 1  # another event/ledger append is not this event's basis
                before = (m.revision, m.state, m.head, frozenset(m.roots))
                outcome = m.commit(owner, cut=(owner == cut_owner))
                if outcome in ("refused", "retry"):
                    assert (m.revision, m.state, m.head, frozenset(m.roots)) == before
                if outcome == "provenance_only":
                    assert (m.revision, m.state) == before[:2]
                    head = m.head
                    assert m.commit(owner) == "published"
                    assert m.head == head + 1  # no duplicate provenance append
                if outcome in ("published", "provenance_only"):
                    head = m.head
                    assert m.commit(owner) == "retry"
                    assert m.head == head
                head = m.head
                assert m.commit(owner, changed_actor=True) == "refused"
                assert m.head == head
            assert m.sources == original
            assert len(m.appends) == len(set(m.appends))
            assert m.effects == initial_effect  # a review never reconciles an effect
        cases += 1
    # Preparing new effect work invalidates admission even though event revision is unchanged.
    m = Model("indeterminate")
    assert m.preview("A", "resolve")
    m.effects = True
    assert m.commit("A") == "refused"
    assert not m.roots and m.state == "indeterminate"
    print(f"PASS: {cases} state/action/interleaving/cut/effect/foreign-append cases; late effect guard")

if __name__ == "__main__":
    main()
