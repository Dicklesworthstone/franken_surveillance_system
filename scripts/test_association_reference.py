#!/usr/bin/env python3
"""Independent association arithmetic controls; this does not execute Rust."""
from fractions import Fraction as Q
import itertools
import random
import unittest


def overlap(a, b):
    result = [(max(x[0], y[0]), min(x[1], y[1])) for x, y in zip(a, b)]
    return None if any(lo > hi for lo, hi in result) else result


def predict(previous, current, span, future, acceleration):
    out = []
    for a, b, bound in zip(previous, current, acceleration):
        velocity = ((b[0] - a[1]) / span, (b[1] - a[0]) / span)
        growth = bound * (future * future + future * span) / 2
        out.append((b[0] + velocity[0] * future - growth,
                    b[1] + velocity[1] * future + growth))
    return out


def candidate(predictions, supports):
    if not predictions or not supports:
        return True
    return any(a is None or b is None or overlap(a, b) is not None
               for a in predictions for b in supports)


class Reference(unittest.TestCase):
    def test_exact_closed_interval_intersections(self):
        intervals = [(Q(a), Q(b)) for a in range(-3, 4) for b in range(a, 4)]
        probes = [Q(x, 2) for x in range(-6, 7)]
        for a, b in itertools.product(intervals, repeat=2):
            result = overlap([a] * 3, [b] * 3)
            truth = [x for x in probes if a[0] <= x <= a[1] and b[0] <= x <= b[1]]
            self.assertEqual(result is not None, bool(truth))
            if result is not None:
                self.assertTrue(all(result[0][0] <= x <= result[0][1] for x in truth))

    def test_shared_error_acceleration_does_not_remove_true_matches(self):
        rng = random.Random(9917)
        for _ in range(10000):
            span, future = Q(rng.randrange(1, 20), 10), Q(rng.randrange(1, 60), 10)
            actual_previous, actual_current, actual_future, limits = [], [], [], []
            for _axis in range(3):
                start, speed = Q(rng.randrange(-50, 50), 10), Q(rng.randrange(-30, 30), 10)
                acceleration = Q(rng.randrange(-10, 11), 10)
                common_bias, error = Q(rng.randrange(-10, 11), 100), Q(1, 10)
                end = start + speed * span + acceleration * span**2 / 2
                next_position = start + speed * (span + future) + acceleration * (span + future)**2 / 2
                actual_previous.append((start + common_bias - error, start + common_bias + error))
                actual_current.append((end + common_bias - error, end + common_bias + error))
                actual_future.append((next_position, next_position))
                limits.append(abs(acceleration))
            predicted = predict(actual_previous, actual_current, span, future, limits)
            self.assertTrue(candidate([predicted], [actual_future]))

    def test_crossing_preserves_all_pairs(self):
        center = [(Q(3, 2), Q(3, 2)), (Q(2), Q(2)), (Q(0), Q(0))]
        self.assertEqual([[candidate([a], [b]) for b in [center, center]]
                          for a in [center, center]], [[True, True], [True, True]])

    def test_unknown_mode_is_not_discarded_by_known_disjoint_modes(self):
        left, right = [(Q(0), Q(1))] * 3, [(Q(4), Q(5))] * 3
        self.assertFalse(candidate([left], [right]))
        self.assertTrue(candidate([left, None], [right]))
        self.assertTrue(candidate([left], [right, None]))
        self.assertTrue(candidate([], [right]))
        self.assertTrue(candidate([left], []))

    def test_increasing_acceleration_only_broadens_candidates(self):
        previous, current = [(Q(0), Q(0))] * 3, [(Q(1), Q(1))] * 3
        narrow = predict(previous, current, Q(1), Q(1), [Q(0)] * 3)
        broad = predict(previous, current, Q(1), Q(1), [Q(1)] * 3)
        for xyz in itertools.product([Q(n, 2) for n in range(-2, 9)], repeat=3):
            point = [(x, x) for x in xyz]
            if candidate([narrow], [point]):
                self.assertTrue(candidate([broad], [point]))

    def test_every_retained_support_layer_is_considered(self):
        upper, lower = [(Q(0), Q(1)), (Q(0), Q(1)), (Q(2), Q(2))], [(Q(0), Q(1))] * 3
        self.assertFalse(candidate([upper], [lower]))
        self.assertTrue(candidate([upper, lower], [lower]))

    def test_large_epoch_differences_are_taken_before_conversion(self):
        for epoch in [0, 2**53, 2**63, 2**64 - 10000000000]:
            before, now, query = epoch + 10, epoch + 30, epoch + 80
            self.assertEqual(Q(query - now, now - before), Q(5, 2))


if __name__ == "__main__":
    unittest.main()
