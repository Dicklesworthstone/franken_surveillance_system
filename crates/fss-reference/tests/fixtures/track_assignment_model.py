"""Independent counterexample model, not execution of the Rust implementation."""
from itertools import permutations


def iou(x, y, width=20):
    overlap = max(0, min(x + width, y + width) - max(x, y))
    return overlap / (2 * width - overlap)


def main():
    prior = [0.0, 8.0]
    detections = [2.0, 20.0]
    feasible = [assignment for assignment in permutations(range(2))
                if all(iou(x, detections[d]) >= .1 for x, d in zip(prior, assignment))]
    assert feasible == [(0, 1)], feasible
    gain = 111 / (111 + 10000)
    filtered = [x + gain * (detections[d] - x) for x, d in zip(prior, feasible[0])]
    reconstructed = [max(range(2), key=lambda d: iou(x, detections[d])) for x in filtered]
    assert reconstructed == [0, 0], reconstructed
    assert len(set(feasible[0])) == 2
    print('PASS: unique global assignment (0,1); post-filter nearest-IoU wrongly reconstructs (0,0)')
    cases = 0
    for n in range(7):
        for order in permutations(range(n)):
            receipts = sorted((track + 1, row) for track, row in enumerate(order))
            assert {row for _, row in receipts} == set(range(n))
            assert len({track for track, _ in receipts}) == n
            cases += 1
    print(f'PASS: {cases} original-row permutation/bijection model cases (not Rust execution)')


if __name__ == '__main__':
    main()
