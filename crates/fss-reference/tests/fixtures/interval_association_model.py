#!/usr/bin/env python3
"""Independent finite oracle for interval admission and globally stable assignments.

This is not a Rust execution receipt. Enumerates actual capture instants and every
optional one-to-one assignment, including the unmatched choice and rounding guard.
"""
from itertools import product
from math import floor

SCALE = 1_000_000


def bounds(a, b):
    return max(0, a[0] - b[1], b[0] - a[1]), max(abs(a[1] - b[0]), abs(b[1] - a[0]))


def midpoint(a):
    return a[0] + (a[1] - a[0]) // 2


def score(a, b, x, y, gate):
    dt = abs(midpoint(a) - midpoint(b))
    distance = abs(x - y)
    if dt > gate or distance > 10:
        return None
    return floor((1 - dt / gate) * (1 - distance / 10) * SCALE + 0.5)


def assignments(edges, rows=2, columns=2):
    solutions = []
    for selection in product(range(-1, columns), repeat=rows):
        chosen = [c for c in selection if c >= 0]
        if len(set(chosen)) != len(chosen):
            continue
        if any(c >= 0 and edges[r][c] is None for r, c in enumerate(selection)):
            continue
        cost = sum(SCALE if c < 0 else SCALE - edges[r][c] for r, c in enumerate(selection))
        solutions.append((cost, selection))
    best = min(cost for cost, _ in solutions)
    contenders = [selection for cost, selection in solutions if cost <= best + rows]
    stable = set.intersection(*(set((r, c) for r, c in enumerate(s) if c >= 0) for s in contenders))
    return best, stable


def main():
    intervals = [(-3, -3), (-3, 0), (-3, 3), (-1, 1), (0, 0), (0, 3), (1, 3), (3, 3)]
    layouts = [((0, 5), (1, 6)), ((0, 1), (1, 0)), ((0, 0), (0, 0))]
    cases = 0
    for a0, a1, b0, b1 in product(intervals, repeat=4):
        left, right = (a0, a1), (b0, b1)
        for gate, (xs, ys) in product((1, 3, 5), layouts):
            numeric, exhaustive = [], []
            for row, a in enumerate(left):
                nrow, erow = [], []
                for column, b in enumerate(right):
                    low, high = bounds(a, b)
                    actual = [abs(x - y) for x in range(a[0], a[1] + 1) for y in range(b[0], b[1] + 1)]
                    assert (low, high) == (min(actual), max(actual))
                    ranking = score(a, b, xs[row], ys[column], gate)
                    nrow.append(ranking if high <= gate else None)
                    erow.append(ranking if all(d <= gate for d in actual) else None)
                numeric.append(nrow)
                exhaustive.append(erow)
            assert assignments(numeric) == assignments(exhaustive)
            best, stable = assignments(numeric)
            for row, column in stable:
                assert bounds(left[row], right[column])[1] <= gate
            cases += 1

    # Reproduce the actual defect: post-filtering the highest midpoint-ranked edge
    # returns no match even though the lower-ranked, fully admissible edge exists.
    left, right = [(0, 0)], [(-20, 20), (0, 0)]
    midpoint_graph = [[score(left[0], b, 0, x, 10) for b, x in zip(right, (0, 1))]]
    _, legacy = assignments(midpoint_graph, 1, 2)
    postfiltered = {(r, c) for r, c in legacy if bounds(left[r], right[c])[1] <= 10}
    interval_graph = [[None, midpoint_graph[0][1]]]
    _, corrected = assignments(interval_graph, 1, 2)
    assert legacy == {(0, 0)} and not postfiltered and corrected == {(0, 1)}

    minimum, maximum = -(1 << 127), (1 << 127) - 1
    assert midpoint((minimum, maximum)) == -1
    assert bounds((minimum, minimum), (maximum, maximum)) == ((1 << 128) - 1,) * 2
    for shift in (minimum + 100, (1 << 63) + 100, maximum - 100):
        assert bounds((shift - 2, shift + 2), (shift, shift + 4)) == (0, 6)
        assert abs(midpoint((shift - 2, shift + 2)) - midpoint((shift, shift + 4))) == 2
    print(f"PASS: {cases:,} interval/geometry/global-assignment cases; post-filter counterexample; i128 extremes")


if __name__ == '__main__':
    main()
