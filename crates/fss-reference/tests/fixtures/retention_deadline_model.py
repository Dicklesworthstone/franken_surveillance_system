#!/usr/bin/env python3
"""Independent finite-domain oracle for retention deadlines, not native Rust execution."""
from itertools import product


def classify(deadline: int, earliest: int, latest: int) -> str:
    if earliest > latest:
        raise ValueError("inverted time assertion")
    if earliest >= deadline:
        return "eligible_for_expiry"
    if latest < deadline:
        return "not_due"
    return "time_uncertain"


def transition(prior: tuple, desired: tuple) -> bool:
    if prior == ("held",) and desired == ("released",):
        return True
    if prior[0] != "until" or desired[0] != "expired":
        return False
    _, deadline, earliest, latest = desired
    return deadline == prior[1] and earliest <= latest and earliest >= deadline


def main() -> None:
    values = range(-32, 33)
    intervals = [(a, b) for a in values for b in values if a <= b]
    clock_cases = 0
    for deadline, (earliest, latest) in product(values, intervals):
        instants = range(earliest, latest + 1)
        all_elapsed = all(instant >= deadline for instant in instants)
        none_elapsed = all(instant < deadline for instant in instants)
        expected = "eligible_for_expiry" if all_elapsed else "not_due" if none_elapsed else "time_uncertain"
        assert classify(deadline, earliest, latest) == expected
        assert transition(("until", deadline), ("expired", deadline, earliest, latest)) == all_elapsed
        # Time never changes active authority: querying eligibility is not an expiry transition.
        assert not transition(("until", deadline), ("released",))
        clock_cases += 1
    lifecycle_cases = 0
    states = [("held",), ("released",)] + [("until", n) for n in (-1, 0, 1)]
    states += [("expired", d, a, b) for d, a, b in product((-1, 0, 1), repeat=3)]
    for prior, desired in product(states, repeat=2):
        permitted = prior == ("held",) and desired == ("released",)
        if prior[0] == "until" and desired[0] == "expired":
            permitted = desired[1] == prior[1] and desired[2] <= desired[3]
            permitted = permitted and all(t >= prior[1] for t in range(desired[2], desired[3] + 1))
        assert transition(prior, desired) == permitted
        lifecycle_cases += 1
    low, high = -(1 << 127), (1 << 127) - 1
    assert classify(low, low, high) == "eligible_for_expiry"
    assert classify(high, low, high) == "time_uncertain"
    assert classify(high, high, high) == "eligible_for_expiry"
    try:
        classify(0, 1, -1)
    except ValueError:
        pass
    else:
        raise AssertionError("inverted bounds accepted")
    print(f"PASS: {clock_cases} interval cases; {lifecycle_cases} lifecycle pairs; timestamp extremes")


if __name__ == "__main__":
    main()
