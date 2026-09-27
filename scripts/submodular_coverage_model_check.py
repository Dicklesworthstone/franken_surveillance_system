#!/usr/bin/env python3
"""Finite laboratory cross-check of weighted coverage; NOT execution of the Rust source."""
from __future__ import annotations
import itertools
import json
import random
from fractions import Fraction


def masked(weights, masks, costs, mandatory, excluded, slots, budget):
    chosen = set(mandatory)
    covered = 0
    spent = sum(costs[i] for i in mandatory)
    for i in mandatory:
        covered |= masks[i]
    score = lambda bits: sum(w for i, w in enumerate(weights) if bits >> i & 1)
    utility = score(covered)
    order = []
    while covered != (1 << len(weights)) - 1 and len(chosen) < slots:
        best, gain, cost = None, 0, 1
        for i, mask in enumerate(masks):
            if i in chosen or i in excluded or costs[i] > budget - spent:
                continue
            delta = score(mask & ~covered)
            if delta * cost > gain * costs[i]:
                best, gain, cost = i, delta, costs[i]
        if best is None:
            break
        chosen.add(best)
        order.append(best)
        covered |= masks[best]
        spent += cost
        utility += gain
    return sorted(chosen), order, utility, spent


def direct(weights, masks, costs, mandatory, excluded, slots, budget):
    supports = [{i for i in range(len(weights)) if mask >> i & 1} for mask in masks]
    chosen = set(mandatory)
    covered = set().union(*(supports[i] for i in chosen))
    spent = sum(costs[i] for i in chosen)
    order = []
    while len(chosen) < slots:
        ranked = []
        for i, targets in enumerate(supports):
            if i in chosen or i in excluded or costs[i] + spent > budget:
                continue
            gain = sum(weights[t] for t in targets - covered)
            if gain:
                ranked.append((-Fraction(gain, costs[i]), i))
        if not ranked:
            break
        _, i = min(ranked)
        order.append(i)
        chosen.add(i)
        covered |= supports[i]
        spent += costs[i]
    return sorted(chosen), order, sum(weights[t] for t in covered), spent


def check(weights, masks, costs, mandatory, excluded, slots, budget):
    actual = masked(weights, masks, costs, mandatory, excluded, slots, budget)
    assert actual == direct(weights, masks, costs, mandatory, excluded, slots, budget)
    selected, order, utility, spent = actual
    assert mandatory <= set(selected) and not excluded & set(selected)
    assert len(selected) <= slots and spent <= budget
    assert len(order) <= len(weights) and len(set(order)) == len(order)
    assert 0 <= utility <= sum(weights)
    return actual


def main():
    if not __debug__:
        raise SystemExit("model checks require assertions; no python -O")
    exhaustive = 0
    for weights in itertools.product((1, 3), repeat=2):
        for masks in itertools.product(range(4), repeat=3):
            for costs in itertools.product((1, 2), repeat=3):
                for slots in range(4):
                    for budget in range(7):
                        check(weights, masks, costs, set(), set(), slots, budget)
                        exhaustive += 1
    rng = random.Random(0x75BA2D38)
    for _ in range(10000):
        e, n = rng.randrange(0, 9), rng.randrange(0, 10)
        weights = [rng.randrange(1, 100) for _ in range(e)]
        costs = [rng.randrange(1, 30) for _ in range(n)]
        masks = [rng.randrange(1 << e) for _ in range(n)]
        mandatory, excluded = set(), set()
        for i in range(n):
            status = rng.randrange(6)
            if status == 0:
                mandatory.add(i)
            elif status == 1:
                excluded.add(i)
        slots = rng.randrange(len(mandatory), n + 1)
        budget = sum(costs[i] for i in mandatory) + rng.randrange(60)
        check(weights, masks, costs, mandatory, excluded, slots, budget)
    largest = check([1] * 64, [1 << (i % 64) for i in range(1024)], [1] * 1024, set(), set(), 64, 64)
    assert largest[2] == 64 and len(largest[0]) == 64
    maximum = (1 << 64) - 1
    extreme = check([maximum // 2, maximum // 2 + 1], [1, 2], [maximum - 1, maximum], set(), set(), 1, maximum)
    assert extreme[0] == [1]
    counterexample = check([3, 2, 2], [1, 6], [2, 3], set(), set(), 2, 4)
    assert counterexample[2] == 3 < 4  # Feasible b alone beats greedy. No optimality claim.
    print(json.dumps({"kind": "independent_python_model_only", "exhaustive_cases": exhaustive,
        "seeded_constrained_cases": 10000, "full_word_and_1024_candidates": "passed",
        "u64_ratio_extremes": "passed", "greedy_nonoptimality_counterexample": "passed",
        "native_rust_execution": "not_run"}, indent=2))


if __name__ == "__main__":
    main()
