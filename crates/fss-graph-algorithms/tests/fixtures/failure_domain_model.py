"""Independent executable model check; this does NOT compile or execute Rust."""

def reach(nodes, edges, removed):
    adj = {n: set() for n in nodes if n not in removed}
    for a, b in edges:
        if a in adj and b in adj:
            adj[a].add(b); adj[b].add(a)
    todo = ['root']; seen = {'root'}
    while todo:
        for other in adj[todo.pop()] - seen:
            seen.add(other); todo.append(other)
    return seen

sensors = ['a', 'b', 'c']
zones = ['x', 'y', 'z']
nodes = {'root', *sensors, *zones}
cases = 0
for bits in range(512):
    original = {('root', s) for s in sensors}
    original |= {(s, z) for i,s in enumerate(sensors) for j,z in enumerate(zones) if bits & (1 << (i*3+j))}
    before = reach(nodes, original, set()) & set(zones)
    for mask in range(1, 8):
        members = {s for i,s in enumerate(sensors) if mask & (1 << i)}
        edges = {('root', 'domain')}
        edges |= {('domain' if s in members else 'root', s) for s in sensors}
        edges |= {('domain' if s in members else s, z) for s,z in original if s != 'root'}
        after = reach(nodes, original, members) & set(zones)
        contracted = reach(nodes | {'domain'}, edges, {'domain'}) & set(zones)
        assert before - after == before - contracted, (bits, mask)
        separated = reach(nodes | {'domain'}, edges, set()) - reach(nodes | {'domain'}, edges, {'domain'}) - {'domain'}
        assert separated == members | (before - after), (bits, mask)
        cases += 1
print(f'PASS: {cases} graph/domain pairs; simultaneous-removal and contracted-cut models agree.')
print('Rust compilation and Rust contract tests: NOT RUN (toolchain unavailable).')
