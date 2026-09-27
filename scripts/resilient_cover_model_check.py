#!/usr/bin/env python3
"""Finite model of resilient set-cover reduction, NOT a native Rust validation receipt."""
from __future__ import annotations

import itertools
import json
import random


def reduced(supports: list[set[int]], zones: set[int], failures: list[set[int]],
            mandatory: set[int], excluded: set[int], maximum: int) -> tuple[int, ...] | None:
    ordered_zones = sorted(zones)
    scenarios = [set(), *failures]
    expanded = [sum(1 << (case * len(zones) + index)
                    for case, failed in enumerate(scenarios)
                    for index, zone in enumerate(ordered_zones)
                    if sensor not in failed and zone in support)
                for sensor, support in enumerate(supports)]
    objective = (1 << (len(scenarios) * len(zones))) - 1
    optional = sorted(set(range(len(supports))) - mandatory - excluded)
    for size in range(maximum - len(mandatory) + 1):
        for extra in itertools.combinations(optional, size):
            selected = tuple(sorted(mandatory | set(extra)))
            mask = 0
            for sensor in selected:
                mask |= expanded[sensor]
            if mask == objective:
                return selected
    return None


def direct(supports: list[set[int]], zones: set[int], failures: list[set[int]],
           mandatory: set[int], excluded: set[int], maximum: int) -> tuple[int, ...] | None:
    feasible = []
    for bits in itertools.product((False, True), repeat=len(supports)):
        chosen = {index for index, keep in enumerate(bits) if keep}
        if len(chosen) > maximum or not mandatory <= chosen or excluded & chosen:
            continue
        valid = True
        for failed in [set(), *failures]:
            actual = set()
            for sensor in chosen - failed:
                actual.update(supports[sensor])
            if not zones <= actual:
                valid = False
                break
        if valid:
            feasible.append(tuple(sorted(chosen)))
    return min(feasible, key=lambda selected: (len(selected), selected), default=None)


def check(*args) -> None:
    assert reduced(*args) == direct(*args), args


def main() -> None:
    exhaustive = 0
    for incidence in range(64):
        supports = [{zone for zone in range(2) if incidence & (1 << (sensor * 2 + zone))}
                    for sensor in range(3)]
        for a in range(1, 8):
            for b in range(1, 8):
                failures = [{s for s in range(3) if a & (1 << s)},
                            {s for s in range(3) if b & (1 << s)}]
                for maximum in range(4):
                    check(supports, {0, 1}, failures, set(), set(), maximum)
                    exhaustive += 1
    rng = random.Random(0xF55C0A7)
    for _ in range(5000):
        n, m, count = rng.randrange(1, 8), rng.randrange(1, 5), rng.randrange(1, 4),
        supports = [{z for z in range(m) if rng.randrange(2)} for _ in range(n)]
        failures = [set(rng.sample(range(n), rng.randrange(1, n + 1))) for _ in range(count)]
        constraints = [rng.randrange(3) for _ in range(n)]
        mandatory = {s for s, value in enumerate(constraints) if value == 1}
        excluded = {s for s, value in enumerate(constraints) if value == 2}
        check(supports, set(range(m)), failures, mandatory, excluded, rng.randrange(len(mandatory), n + 1))
    check([set(range(32)), set(range(32))], set(range(32)), [{0}], set(), set(), 1)
    # Separate overlapping scenarios admit a,c, whereas the undeclared joint loss does not.
    assert reduced([{0}, {0}, {0}], {0}, [{0, 1}, {1, 2}], set(), set(), 2) == (0, 2)
    assert direct([{0}, {0}, {0}], {0}, [{0, 1, 2}], set(), set(), 3) is None
    print(json.dumps({"scope": "independent Python finite model only; Rust NOT executed",
                      "status": "passed", "exhaustive_cases": exhaustive,
                      "seeded_constraint_cases": 5000, "full_word_cases": 1,
                      "overlap_vs_joint_failure_cases": 2}, indent=2))


if __name__ == "__main__":
    main()
