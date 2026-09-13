#!/usr/bin/env python3
"""Independent descriptor-decision arithmetic checks; does not execute Rust."""
import itertools
import json
import random


def streaming(matrix, ceiling, ratio):
    rows, cols = len(matrix), len(matrix[0])
    reverse = [None] * cols
    for p in range(cols):
        best = 257
        for q in range(rows):
            d = matrix[q][p]
            if d < best:
                best, reverse[p] = d, q
            elif d == best:
                reverse[p] = None
    result = []
    for q, row in enumerate(matrix):
        first, index, second = 257, 0, 257
        for p, d in enumerate(row):
            if d < first:
                first, index, second = d, p, first
            else:
                second = min(second, d)
        reason = 'distance' if first > ceiling else 'ambiguous' if second == 257 or first == second or first * 100 >= second * ratio else 'mutual' if reverse[index] != q else None
        result.append((index if reason is None else None, reason))
    return result


def independent(matrix, ceiling, ratio):
    result = []
    for q, row in enumerate(matrix):
        ranked = sorted(enumerate(row), key=lambda item: item[1])
        p, best = ranked[0]
        if best > ceiling:
            result.append((None, 'distance'))
        elif len(ranked) < 2 or best * 100 >= ranked[1][1] * ratio:
            result.append((None, 'ambiguous'))
        else:
            column = [r[p] for r in matrix]
            winners = [i for i, d in enumerate(column) if d == min(column)]
            result.append((p, None) if winners == [q] else (None, 'mutual'))
    return result


def main():
    count = 0
    for rows, cols, values in [(2, 3, range(4)), (3, 2, range(4)), (3, 3, range(2))]:
        for flat in itertools.product(values, repeat=rows * cols):
            matrix = [flat[q * cols:(q + 1) * cols] for q in range(rows)]
            for ceiling, ratio in [(0, 80), (2, 80), (256, 99)]:
                assert streaming(matrix, ceiling, ratio) == independent(matrix, ceiling, ratio)
                count += 1
    rng = random.Random(192837)
    for _ in range(10000):
        matrix = [[rng.randrange(257) for _ in range(5)] for _ in range(4)]
        ceiling, ratio = rng.randrange(257), rng.randrange(1, 100)
        assert streaming(matrix, ceiling, ratio) == independent(matrix, ceiling, ratio)
        count += 1
    print(json.dumps({'status': 'PASS', 'scope': 'Python matching arithmetic only', 'cases': count, 'rust_executed': False}))


if __name__ == '__main__':
    main()
