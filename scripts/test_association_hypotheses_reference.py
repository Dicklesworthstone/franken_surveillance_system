#!/usr/bin/env python3
"""Independent finite-graph controls. Does not execute native Rust."""
import itertools
import unittest


def partial_matchings(tracks, detections, edges, limit):
    output = []
    def visit(i, used, selected):
        if i == len(tracks):
            if len(output) == limit:
                return False
            output.append(tuple(selected))
            return True
        t = tracks[i]
        if not visit(i + 1, used, selected):
            return False
        for d in detections:
            if d not in used and (t, d) in edges:
                if not visit(i + 1, used | {d}, selected + [(t, d)]):
                    return False
        return True
    return output if visit(0, set(), []) else None


def components(n, m, edges):
    remaining = set(range(n + m))
    out = []
    while remaining:
        seed = min(remaining)
        remaining.remove(seed)
        nodes, pending = {seed}, [seed]
        while pending:
            node = pending.pop()
            adjacent = ({n + d for t, d in edges if t == node} if node < n
                        else {t for t, d in edges if n + d == node})
            for other in sorted(adjacent & remaining):
                remaining.remove(other)
                nodes.add(other)
                pending.append(other)
        out.append((sorted(x for x in nodes if x < n), sorted(x - n for x in nodes if x >= n)))
    return out


def subset_oracle(edges):
    edges = sorted(edges)
    expected = set()
    for mask in range(1 << len(edges)):
        subset = tuple(edge for i, edge in enumerate(edges) if mask & (1 << i))
        if len({e[0] for e in subset}) == len(subset) == len({e[1] for e in subset}):
            expected.add(subset)
    return expected


class Reference(unittest.TestCase):
    def test_all_three_by_three_graphs_against_subset_oracle(self):
        for mask in range(512):
            edges = {(i // 3, i % 3) for i in range(9) if mask & (1 << i)}
            expected = subset_oracle(edges)
            whole = partial_matchings(list(range(3)), list(range(3)), edges, 34)
            self.assertEqual(set(whole), expected)
            self.assertEqual(len(whole), len(expected))
            factors = [partial_matchings(ts, ds, edges, 34) for ts, ds in components(3, 3, edges)]
            expanded = {tuple(sorted(itertools.chain.from_iterable(parts))) for parts in itertools.product(*factors)}
            self.assertEqual(expanded, expected)

    def test_list_boundary_retains_implicit_family_not_prefix(self):
        edges = set(itertools.product(range(3), repeat=2))
        self.assertEqual(len(partial_matchings(list(range(3)), list(range(3)), edges, 34)), 34)
        self.assertIsNone(partial_matchings(list(range(3)), list(range(3)), edges, 33))

    def test_independent_thirty_two_pairs_represent_billions_of_worlds(self):
        edges = {(i, i) for i in range(32)}
        factors = [partial_matchings(ts, ds, edges, 2) for ts, ds in components(32, 32, edges)]
        self.assertEqual(len(factors), 32)
        self.assertEqual(sum(map(len, factors)), 64)
        product = 1
        for factor in factors:
            product *= len(factor)
        self.assertEqual(product, 1 << 32)

    def test_crossing_has_all_seven_not_only_two_maximal_assignments(self):
        edges = set(itertools.product(range(2), repeat=2))
        all_options = partial_matchings([0, 1], [0, 1], edges, 7)
        self.assertEqual([sum(len(v) == n for v in all_options) for n in range(3)], [1, 4, 2])
        self.assertIn((), all_options)

    def test_restoring_an_unknown_edge_never_erases_a_matching(self):
        for mask in range(512):
            edges = {(i // 3, i % 3) for i in range(9) if mask & (1 << i)}
            old = set(partial_matchings([0, 1, 2], [0, 1, 2], edges, 34))
            expanded = set(partial_matchings([0, 1, 2], [0, 1, 2], edges | {(0, 2)}, 34))
            self.assertLessEqual(old, expanded)

    def test_isolated_inputs_remain_unmatched_without_new_identities(self):
        factors = [partial_matchings(ts, ds, set(), 1) for ts, ds in components(2, 3, set())]
        self.assertEqual(factors, [[()]] * 5)
        self.assertEqual(list(itertools.product(*[])), [()])


if __name__ == "__main__":
    unittest.main()
