"""Independent schedule-model check; does not compile or execute the Rust implementation."""

def schedule(first, count, every, burst, budget):
    selected = set()
    skipped = []
    remaining = budget
    for offset in range(0, count, every):
        if burst > count - offset:
            break
        if remaining >= burst:
            selected.update(range(first + offset, first + offset + burst))
            remaining -= burst
        else:
            skipped.append((first + offset, burst))
    return selected, skipped


def verify():
    cases = 0
    for count in range(1, 65):
        for every in range(1, 17):
            for burst in range(1, min(8, every, count) + 1):
                for budget in range(burst, 65):
                    selected, skipped = schedule(37, count, every, burst, budget)
                    expected = {
                        37 + offset for offset in range(count)
                        if offset % every < burst
                        and (offset // every) * every + burst <= count
                        and (offset // every + 1) * burst <= budget
                    }
                    assert selected == expected
                    assert len(selected) <= budget
                    assert len(selected) % burst == 0
                    assert all(start >= 37 and start + size <= 37 + count
                               for start, size in skipped)
                    cases += 1
    print(f"PASS: {cases} schedule/model cases (not Rust execution)")


if __name__ == '__main__':
    verify()
