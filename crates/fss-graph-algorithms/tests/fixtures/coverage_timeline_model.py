#!/usr/bin/env python3
"""Laboratory-only interval model; not execution or qualification of the Rust implementation."""
from itertools import product
from random import Random


def partition(rows, first, last):
    assert first <= last
    starts = {first}
    for _, intervals in rows:
        for lo, hi in intervals:
            assert lo <= hi
            lo, hi = max(lo, first), min(hi, last)
            if lo <= hi:
                starts.add(lo)
                if hi < last:
                    starts.add(hi + 1)
    starts = sorted(starts)
    result = []
    for index, lo in enumerate(starts):
        hi = starts[index + 1] - 1 if index + 1 < len(starts) else last
        observers = sorted({sensor for sensor, intervals in rows
                            if any(a <= lo and hi <= b for a, b in intervals)})
        result.append((lo, hi, observers))
    return result


def check(rows, first, last):
    result = partition(rows, first, last)
    for time in range(first, last + 1):
        matches = [observers for a, b, observers in result if a <= time <= b]
        expected = sorted({sensor for sensor, intervals in rows
                           if any(a <= time <= b for a, b in intervals)})
        assert matches == [expected], (rows, time, result, expected)
    assert result == partition([(sensor, list(reversed(intervals)))
                                for sensor, intervals in reversed(rows)], first, last)


def main():
    intervals = [None] + [(a, b) for a in range(-3, 4) for b in range(a, 4)]
    exhaustive = 0
    for a, b, c in product(intervals, repeat=3):
        rows = [(sensor, [] if interval is None else [interval])
                for sensor, interval in zip("abc", (a, b, c))]
        check(rows, -4, 4)
        exhaustive += 1
    rng = Random(0x465353)
    for _ in range(4096):
        rows = [(str(sensor), [tuple(sorted((rng.randrange(-20, 21), rng.randrange(-20, 21))))
                               for _ in range(rng.randrange(5))]) for sensor in range(6)]
        check(rows, -12, 12)
    lo, hi = -(1 << 127), (1 << 127) - 1
    assert partition([("a", [(lo, lo)]), ("b", [(hi, hi)])], lo, hi) == [
        (lo, lo, ["a"]), (lo + 1, hi - 1, []), (hi, hi, ["b"])]
    print(f"PASS: {exhaustive} exhaustive + 4096 seeded interval models; i128 extremes")
    print("Rust compiler/tests/formatting/Clippy/full qualification: NOT EXECUTED by this model")


if __name__ == "__main__":
    main()
