"""Independent source-epoch confirmation model; does not execute Rust."""
from itertools import permutations


def tracker_epochs(size, gaps, threshold):
    tracks = []
    observations = []
    hits = 0
    track_id = 0
    for segment in range(size):
        if segment == 0 or segment in gaps:
            if observations:
                tracks.append((track_id, hits >= threshold, tuple(observations)))
            track_id += 1
            hits = 0
            observations = []
        hits += 1
        observations.append(segment)
    if observations:
        tracks.append((track_id, hits >= threshold, tuple(observations)))
    return tracks


def main():
    cases = 0
    for size in range(1, 11):
        for bits in range(1 << (size - 1)):
            gaps = {segment for segment in range(1, size) if bits & (1 << (segment - 1))}
            starts = [0] + sorted(gaps)
            ends = sorted(gaps) + [size]
            for threshold in range(1, 9):
                expected = [(index + 1, end - start >= threshold, tuple(range(start, end)))
                            for index, (start, end) in enumerate(zip(starts, ends))]
                actual = tracker_epochs(size, gaps, threshold)
                assert actual == expected
                assert len({track_id for track_id, _, _ in actual}) == len(actual)
                for _, confirmed, segments in actual:
                    assert not any(segments[0] < gap <= segments[-1] for gap in gaps)
                    if confirmed:
                        assert len(segments) >= threshold
                cases += 1
    assert all(not confirmed for _, confirmed, _ in tracker_epochs(4, {2}, 3))
    assert [confirmed for _, confirmed, _ in tracker_epochs(6, {3}, 3)] == [True, True]
    print(f'PASS: {cases} source-epoch/confirmation cases (not Rust execution)')
    orders = 0
    for count in range(1, 8):
        for order in permutations(range(count)):
            for boundary in range(1, count):
                epochs = [int(segment >= boundary) for segment in order]
                accepted = all(a <= b for a, b in zip(epochs, epochs[1:]))
                expected = max(order.index(i) for i in range(boundary)) < min(
                    order.index(i) for i in range(boundary, count))
                assert accepted == expected
                orders += 1
    print(f'PASS: {orders} display-order/discontinuity cases (not Rust execution)')


if __name__ == '__main__':
    main()
