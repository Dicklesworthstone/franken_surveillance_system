#!/usr/bin/env python3
"""Independent transaction reference, not execution of the Rust implementation."""
import copy
import hashlib
import itertools
import unittest

class Refusal(Exception):
    pass

class Model:
    def __init__(self, capacity=2):
        self.state = (2, 2, 2)
        self.sequence = 0
        self.watermark = 2
        self.receipts = {}
        self.capacity = capacity
        self.invalidated = False

    def apply(self, sequence, frame, selected, decision, fail_at=None):
        if self.invalidated:
            raise Refusal('invalidated')
        signature = hashlib.sha256(repr((sequence, frame, selected, decision)).encode()).digest()
        if sequence <= self.sequence:
            if sequence not in self.receipts:
                raise Refusal('expired')
            old = self.receipts[sequence]
            if signature != old[0]:
                raise Refusal('conflict')
            return old
        if sequence != self.sequence + 1 or frame <= self.watermark:
            raise Refusal('order')
        candidate = list(self.state)
        for step, target in enumerate(selected):
            if fail_at == step:
                raise Refusal('staging')
            candidate[target] += 1
        receipt = (signature, self.state, tuple(candidate), tuple(i for i in range(3) if i not in selected))
        if fail_at == len(selected):
            raise Refusal('publication barrier')
        self.state, self.sequence, self.watermark = tuple(candidate), sequence, frame
        self.receipts[sequence] = receipt
        while len(self.receipts) > self.capacity:
            del self.receipts[min(self.receipts)]
        return receipt

class Contracts(unittest.TestCase):
    def test_every_partial_assignment_and_staging_failure_is_atomic(self):
        for size in range(4):
            for selected in itertools.combinations(range(3), size):
                for fail in range(size + 1):
                    m = Model(); baseline = copy.deepcopy(m.__dict__)
                    with self.assertRaises(Refusal):
                        m.apply(1, 3, selected, 'owner-record', fail)
                    self.assertEqual(m.__dict__, baseline)
                    receipt = m.apply(1, 3, selected, 'owner-record')
                    self.assertEqual(receipt[2], tuple(2 + (i in selected) for i in range(3)))
    def test_old_retry_never_rolls_back(self):
        m = Model(); old = m.apply(1, 3, (0, 1), 'a'); m.apply(2, 4, (1, 2), 'b')
        baseline = copy.deepcopy(m.__dict__)
        self.assertEqual(m.apply(1, 3, (0, 1), 'a'), old)
        self.assertEqual(m.__dict__, baseline)
    def test_conflicting_decision_or_selection_fails(self):
        m = Model(); m.apply(1, 3, (0,), 'a')
        for selected, decision in [((0,), 'changed'), ((1,), 'a')]:
            with self.assertRaisesRegex(Refusal, 'conflict'):
                m.apply(1, 3, selected, decision)
        self.assertEqual(m.state, (3, 2, 2))
    def test_eviction_and_sequence_gaps_fail(self):
        m = Model(1); m.apply(1, 3, (0,), 'a'); m.apply(2, 4, (1,), 'b')
        for args in [(1, 3, (0,), 'a'), (4, 5, (0,), 'c')]:
            with self.assertRaises(Refusal):
                m.apply(*args)
        self.assertEqual(m.sequence, 2)
    def test_unmatched_is_not_deletion_or_a_reusable_frame(self):
        m = Model(); r = m.apply(1, 3, (), 'a')
        self.assertEqual(m.state, (2, 2, 2)); self.assertEqual(r[3], (0, 1, 2))
        with self.assertRaises(Refusal):
            m.apply(2, 3, (0, 1), 'b')
    def test_invalidation_keeps_receipts_but_disables_retry(self):
        m = Model(); m.apply(1, 3, (0,), 'a'); m.invalidated = True
        baseline = copy.deepcopy(m.__dict__)
        with self.assertRaises(Refusal):
            m.apply(1, 3, (0,), 'a')
        self.assertEqual(m.__dict__, baseline)

if __name__ == '__main__':
    unittest.main()
