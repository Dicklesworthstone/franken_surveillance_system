#!/usr/bin/env python3
"""Deterministic dependency DAG checker (fss-x4a.6.10 / FSS-010).

Validates:
1. The beads issue-tracker dependency graph (.beads/issues.jsonl), covering every
   dependency kind br defines.  Ordering kinds (blocks, conditional-blocks,
   waits-for, parent-child) form the wait-for graph that must be acyclic.  br stores
   parent-child rows as child -> parent but treats them as parent -> child in its
   blocking graph (a parent waits for its children); the checker orients them the
   same way, so cycles that mix kinds are found and an epic blocked by its own
   children is not a false positive.  Non-ordering kinds (related, discovered-from,
   ...) are checked for self and dangling references.  Unknown kinds fail closed.
2. The crate topology (architecture/crate_topology.json) against every crate
   manifest on disk: every dependency table (normal, build, dev, target-specific),
   renamed dependencies, undeclared crates, dangling internal dependencies, cycles,
   and upward layer inversions.  An inversion may only be waived by an explicit
   `layerWaivers` registry entry; a waived inversion is still reported (warning), and
   a waiver that no longer matches an upward edge is an error.
3. Generic DAG files (--file): JSONL records, a JSON array of records, or a JSON
   object with an explicit "nodes" key (arbitrary JSON objects are rejected).

Every elementary cycle is enumerated (Tarjan SCC + Johnson), rotated to start at its
least node, and reported in (length, path) order.  Enumeration is bounded; when the
bound is hit the run fails with ERR-DAG-CYCLE-ENUMERATION-INCOMPLETE-001 naming each
cyclic component instead of implying the reported cycles are all of them.

Fails closed on:
- Directed cycles (ERR-DAG-CYCLE-001)
- Self-dependencies, i.e. length-1 cycles (ERR-DAG-SELF-DEPENDENCY-001)
- Dangling references (ERR-DAG-DANGLING-REFERENCE-001)
- Duplicate node definitions or duplicate JSON keys (ERR-DAG-DUPLICATE-ID-001)
- Missing files (ERR-DAG-MISSING-FILE-001)
- Files that exist but cannot be read (ERR-DAG-UNREADABLE-FILE-001)
- Corrupt, partial, non-UTF-8, or schema-violating input (ERR-DAG-CORRUPT-FILE-001)
- Empty/vacuous graphs or hierarchies (ERR-DAG-EMPTY-INPUT-001)
- Crate layer inversions (ERR-DAG-LAYER-INVERSION-001)
- Tombstone references (ERR-DAG-TOMBSTONE-REFERENCE-001)
- Unknown dependency kinds (ERR-DAG-UNKNOWN-EDGE-KIND-001)
- Crates on disk that the topology does not declare (ERR-DAG-UNDECLARED-NODE-001)
- Layer waivers that match no upward edge (ERR-DAG-STALE-WAIVER-001)
- Cycle enumeration stopped at its bound (ERR-DAG-CYCLE-ENUMERATION-INCOMPLETE-001)

Exit codes: 0 only when every input was fully read and checked with zero errors
(and, with --strict, zero warnings); 1 on any error or incomplete input; 2 on usage
error.
"""
from __future__ import annotations

import argparse
import json
import re
import stat
import sys
import tomllib
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import stable_id_audit

# Stable diagnostic error codes
ERR_DAG_CYCLE = "ERR-DAG-CYCLE-001"
ERR_DAG_SELF_DEPENDENCY = "ERR-DAG-SELF-DEPENDENCY-001"
ERR_DAG_DANGLING_REFERENCE = "ERR-DAG-DANGLING-REFERENCE-001"
ERR_DAG_DUPLICATE_ID = "ERR-DAG-DUPLICATE-ID-001"
ERR_DAG_MISSING_FILE = "ERR-DAG-MISSING-FILE-001"
ERR_DAG_UNREADABLE_FILE = "ERR-DAG-UNREADABLE-FILE-001"
ERR_DAG_CORRUPT_FILE = "ERR-DAG-CORRUPT-FILE-001"
ERR_DAG_EMPTY_INPUT = "ERR-DAG-EMPTY-INPUT-001"
ERR_DAG_LAYER_INVERSION = "ERR-DAG-LAYER-INVERSION-001"
ERR_DAG_TOMBSTONE_REFERENCE = "ERR-DAG-TOMBSTONE-REFERENCE-001"
ERR_DAG_UNKNOWN_EDGE_KIND = "ERR-DAG-UNKNOWN-EDGE-KIND-001"
ERR_DAG_UNDECLARED_NODE = "ERR-DAG-UNDECLARED-NODE-001"
ERR_DAG_STALE_WAIVER = "ERR-DAG-STALE-WAIVER-001"
ERR_DAG_CYCLE_ENUMERATION_INCOMPLETE = "ERR-DAG-CYCLE-ENUMERATION-INCOMPLETE-001"
WARN_DAG_LAYER_INVERSION_WAIVED = "WARN-DAG-LAYER-INVERSION-WAIVED-001"

REPORT_SCHEMA = "fss.dependency_dag_report.v1"

# Status values that retire an ID/issue
TOMBSTONE_STATES = stable_id_audit.TOMBSTONE_STATES

# Upper bound on enumerated elementary cycles per graph.  Hitting it is reported as
# an error; it never turns into a pass.
DEFAULT_CYCLE_LIMIT = 10_000

# br DependencyType kinds.  Ordering kinds participate in cycle detection; the value
# says whether the stored row (issue -> depends_on) is reversed in the wait-for graph.
ORDERING_EDGE_KINDS: dict[str, bool] = {
    "blocks": False,
    "conditional-blocks": False,
    "waits-for": False,
    "parent-child": True,  # stored child -> parent; the parent waits for the child
}
NON_ORDERING_EDGE_KINDS = frozenset(
    {"related", "discovered-from", "replies-to", "relates-to", "duplicates", "supersedes", "caused-by"}
)
UNTYPED_EDGE_LABEL = "depends-on"

LAYER_ID_PATTERN = re.compile(r"^L(0|[1-9][0-9]*)$")
CARGO_DEPENDENCY_TABLES = (
    "dependencies",
    "build-dependencies",
    "dev-dependencies",
    "build_dependencies",
    "dev_dependencies",
)

Edge = tuple[str, str, "str | None"]  # (from, to, kind)


@dataclass(frozen=True)
class DagFinding:
    code: str
    severity: str  # "error" | "warning"
    message: str
    source: str
    node_id: str | None = None
    target_id: str | None = None
    cycle_path: list[str] | None = None


def _finding(
    code: str,
    message: str,
    source: str,
    *,
    node_id: str | None = None,
    target_id: str | None = None,
    cycle_path: list[str] | None = None,
    severity: str = "error",
) -> DagFinding:
    return DagFinding(
        code=code,
        severity=severity,
        message=message,
        source=source,
        node_id=node_id,
        target_id=target_id,
        cycle_path=cycle_path,
    )


def _finish(findings: list[DagFinding], summary: dict[str, Any]) -> tuple[bool, list[DagFinding], dict[str, Any]]:
    """Derive status from findings.  A pass requires zero errors AND complete input."""
    errors = sum(1 for f in findings if f.severity == "error")
    warnings = sum(1 for f in findings if f.severity == "warning")
    complete = bool(summary.get("complete", True))
    ok = errors == 0 and complete
    summary.update(
        status="pass" if ok else "fail",
        error_count=errors,
        warning_count=warnings,
        complete=complete,
    )
    return ok, findings, summary


def _input_failure(findings: list[DagFinding], **summary: Any) -> tuple[bool, list[DagFinding], dict[str, Any]]:
    base: dict[str, Any] = {"node_count": 0, "edge_count": 0}
    base.update(summary)
    base["complete"] = False
    return _finish(findings, base)


# --------------------------------------------------------------------------- input


class _DuplicateJsonKey(ValueError):
    def __init__(self, key: str) -> None:
        super().__init__(f"duplicate JSON object key {key!r}")
        self.key = key


def _object_pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise _DuplicateJsonKey(key)
        obj[key] = value
    return obj


def _read_utf8(path: Path, what: str) -> tuple[str | None, DagFinding | None]:
    """Read a whole file as UTF-8, classifying every failure with a typed code."""
    source = str(path)
    try:
        st = path.stat()
    except (FileNotFoundError, NotADirectoryError):
        return None, _finding(ERR_DAG_MISSING_FILE, f"Missing {what}: {path}", source)
    except OSError as exc:
        return None, _finding(ERR_DAG_UNREADABLE_FILE, f"Cannot stat {what} {path}: {exc}", source)
    if not stat.S_ISREG(st.st_mode):
        return None, _finding(ERR_DAG_MISSING_FILE, f"{what} is not a regular file: {path}", source)
    try:
        data = path.read_bytes()
    except OSError as exc:
        return None, _finding(ERR_DAG_UNREADABLE_FILE, f"Cannot read {what} {path}: {exc}", source)
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError as exc:
        return None, _finding(ERR_DAG_CORRUPT_FILE, f"{what} {path} is not valid UTF-8: {exc}", source)


def _loads_json(text: str, where: str, source: str) -> tuple[Any, DagFinding | None]:
    try:
        return json.loads(text, object_pairs_hook=_object_pairs_no_duplicates), None
    except _DuplicateJsonKey as exc:
        return None, _finding(
            ERR_DAG_DUPLICATE_ID,
            f"{where}: {exc}; a later definition would silently shadow the earlier one",
            source,
            node_id=exc.key,
        )
    except json.JSONDecodeError as exc:
        return None, _finding(ERR_DAG_CORRUPT_FILE, f"Malformed JSON at {where}: {exc}", source)
    except RecursionError:
        return None, _finding(ERR_DAG_CORRUPT_FILE, f"JSON at {where} exceeds the parser nesting depth", source)


# --------------------------------------------------------------------------- graph core


def _adjacency(graph: dict[str, list[str]]) -> dict[str, list[str]]:
    """Sorted, de-duplicated adjacency restricted to defined nodes (dangling edges are
    reported separately and cannot be part of a cycle)."""
    node_set = set(graph)
    return {u: sorted({v for v in graph[u] if v in node_set}) for u in sorted(graph)}


def strongly_connected_components(graph: dict[str, list[str]]) -> list[list[str]]:
    """Iterative Tarjan SCC.  Each component is sorted; components are ordered by
    their least member."""
    adj = _adjacency(graph)
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    components: list[list[str]] = []
    counter = 0
    for root in adj:
        if root in index:
            continue
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        work: list[tuple[str, int]] = [(root, 0)]
        while work:
            node, i = work[-1]
            neighbours = adj[node]
            if i < len(neighbours):
                work[-1] = (node, i + 1)
                nxt = neighbours[i]
                if nxt not in index:
                    index[nxt] = low[nxt] = counter
                    counter += 1
                    stack.append(nxt)
                    on_stack.add(nxt)
                    work.append((nxt, 0))
                elif nxt in on_stack:
                    low[node] = min(low[node], index[nxt])
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index[node]:
                component: list[str] = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    component.append(member)
                    if member == node:
                        break
                components.append(sorted(component))
    return sorted(components)


def _canonical_cycle(body: list[str]) -> list[str]:
    start = body.index(min(body))
    rotated = body[start:] + body[:start]
    return rotated + [rotated[0]]


def _sorted_cycles(cycles: list[list[str]]) -> list[list[str]]:
    return sorted(cycles, key=lambda c: (len(c), c))


def _unblock(node: str, blocked: set[str], blocked_by: dict[str, set[str]]) -> None:
    work = [node]
    while work:
        current = work.pop()
        if current in blocked:
            blocked.discard(current)
            work.extend(sorted(blocked_by.pop(current, set())))


def _johnson_circuits(sub: dict[str, list[str]], start: str, out: list[list[str]], limit: int | None) -> bool:
    """Johnson's CIRCUIT search from `start` inside one strongly connected subgraph,
    iteratively (no recursion limit).  Returns False if `limit` stopped it."""
    blocked = {start}
    blocked_by: dict[str, set[str]] = {}
    path = [start]
    stack: list[list[Any]] = [[start, iter(sub[start]), False]]
    while stack:
        frame = stack[-1]
        node, neighbours = frame[0], frame[1]
        descended = False
        for nxt in neighbours:
            if nxt == start:
                if limit is not None and len(out) >= limit:
                    return False
                out.append(_canonical_cycle(path))
                frame[2] = True
            elif nxt not in blocked:
                blocked.add(nxt)
                path.append(nxt)
                stack.append([nxt, iter(sub[nxt]), False])
                descended = True
                break
        if descended:
            continue
        stack.pop()
        path.pop()
        if frame[2]:
            _unblock(node, blocked, blocked_by)
            if stack:
                stack[-1][2] = True
        else:
            for nxt in sub[node]:
                blocked_by.setdefault(nxt, set()).add(node)
    return True


def enumerate_cycles(graph: dict[str, list[str]], limit: int | None = None) -> tuple[list[list[str]], bool]:
    """Enumerate every elementary directed cycle (self-loops included as [v, v]).

    Returns (cycles, complete).  Cycles are rotated to begin at their least node,
    closed by repeating it, and sorted by (length, path).  `complete` is False only
    when `limit` stopped enumeration early.
    """
    adj = _adjacency(graph)
    cycles: list[list[str]] = []
    for node in adj:
        if node in adj[node]:
            if limit is not None and len(cycles) >= limit:
                return _sorted_cycles(cycles), False
            cycles.append([node, node])
    pending = [c for c in strongly_connected_components(adj) if len(c) > 1]
    while pending:
        component = pending.pop()
        members = set(component)
        sub = {v: [w for w in adj[v] if w in members and w != v] for v in component}
        start = component[0]
        if not _johnson_circuits(sub, start, cycles, limit):
            return _sorted_cycles(cycles), False
        rest = {v: [w for w in sub[v] if w != start] for v in component if v != start}
        pending.extend(c for c in strongly_connected_components(rest) if len(c) > 1)
    return _sorted_cycles(cycles), True


def find_cycles(graph: dict[str, list[str]]) -> list[list[str]]:
    """Exact, unbounded enumeration of every elementary directed cycle, including
    self-loops ([v, v]).  Deterministic: independent of dict and list order."""
    return enumerate_cycles(graph, limit=None)[0]


def _status_of(node_metadata: dict[str, Any], node: str) -> str:
    meta = node_metadata.get(node)
    if not isinstance(meta, dict):
        return ""
    return str(meta.get("status", "")).strip().lower()


def _reference_findings(
    node_ids: set[str],
    edges: list[Edge],
    node_metadata: dict[str, Any] | None,
    source: str,
    missing_note: Callable[[str], str] | None = None,
) -> tuple[list[DagFinding], int]:
    """Self, dangling, and tombstone references over every edge of every kind."""
    pairs: dict[tuple[str, str], set[str]] = {}
    for u, v, kind in edges:
        pairs.setdefault((u, v), set()).add(kind or UNTYPED_EDGE_LABEL)
    findings: list[DagFinding] = []
    self_count = 0

    def kinds_suffix(pair: tuple[str, str]) -> str:
        kinds = sorted(pairs[pair])
        return "" if kinds == [UNTYPED_EDGE_LABEL] else f" [{', '.join(kinds)}]"

    for u, v in sorted(pairs):
        if u == v:
            self_count += 1
            findings.append(
                _finding(
                    ERR_DAG_SELF_DEPENDENCY,
                    f"Node '{u}' has a direct self-dependency{kinds_suffix((u, v))}",
                    source,
                    node_id=u,
                    target_id=v,
                    cycle_path=[u, u],
                )
            )
        elif v not in node_ids:
            note = missing_note(v) if missing_note else ""
            findings.append(
                _finding(
                    ERR_DAG_DANGLING_REFERENCE,
                    f"Node '{u}' references undefined dependency '{v}'{kinds_suffix((u, v))}{note}",
                    source,
                    node_id=u,
                    target_id=v,
                )
            )
    if node_metadata:
        for u, v in sorted(pairs):
            if u == v or v not in node_ids:
                continue
            u_status = _status_of(node_metadata, u)
            v_status = _status_of(node_metadata, v)
            if u_status not in TOMBSTONE_STATES and v_status in TOMBSTONE_STATES:
                findings.append(
                    _finding(
                        ERR_DAG_TOMBSTONE_REFERENCE,
                        f"Active node '{u}' (status='{u_status}') references "
                        f"tombstoned dependency '{v}' (status='{v_status}'){kinds_suffix((u, v))}",
                        source,
                        node_id=u,
                        target_id=v,
                    )
                )
    return findings, self_count


def _render_cycle(cycle: list[str], labels: dict[tuple[str, str], set[str]] | None) -> str:
    if not labels:
        return " -> ".join(cycle)
    parts = [cycle[0]]
    for a, b in zip(cycle, cycle[1:]):
        parts.append(f" -[{'|'.join(sorted(labels.get((a, b), {UNTYPED_EDGE_LABEL})))}]-> {b}")
    return "".join(parts)


def _cycle_findings(
    cycle_graph: dict[str, list[str]],
    source: str,
    limit: int | None,
    labels: dict[tuple[str, str], set[str]] | None = None,
) -> tuple[list[DagFinding], dict[str, Any]]:
    cycles, complete = enumerate_cycles(cycle_graph, limit)
    findings: list[DagFinding] = []
    for cycle in cycles:
        if len(cycle) == 2:
            continue  # length-1 cycle: reported once, as ERR_DAG_SELF_DEPENDENCY
        findings.append(
            _finding(
                ERR_DAG_CYCLE,
                f"Directed cycle detected: {_render_cycle(cycle, labels)}",
                source,
                node_id=cycle[0],
                cycle_path=cycle,
            )
        )
    components = [c for c in strongly_connected_components(cycle_graph) if len(c) > 1]
    if not complete:
        for component in components:
            findings.append(
                _finding(
                    ERR_DAG_CYCLE_ENUMERATION_INCOMPLETE,
                    f"Cycle enumeration stopped at its {limit}-cycle bound; this cyclic component "
                    f"of {len(component)} node(s) may contain further unreported cycles: "
                    f"{', '.join(component)}",
                    source,
                    node_id=component[0],
                    cycle_path=component,
                )
            )
    return findings, {
        "cycle_count": len(cycles),
        "cycle_enumeration_complete": complete,
        "cyclic_component_count": len(components),
    }


def _orient_typed(kind: str | None) -> str | None:
    """Orientation of an edge in the wait-for graph: 'forward', 'reverse', or None
    (not an ordering edge)."""
    if kind is None:
        return "forward"
    if kind in ORDERING_EDGE_KINDS:
        return "reverse" if ORDERING_EDGE_KINDS[kind] else "forward"
    return None


def _graph_checks(
    node_ids: list[str],
    edges: list[Edge],
    node_metadata: dict[str, Any] | None,
    source: str,
    cycle_limit: int | None,
    orient: Callable[[str | None], str | None] = _orient_typed,
    missing_note: Callable[[str], str] | None = None,
) -> tuple[list[DagFinding], dict[str, Any]]:
    id_set = set(node_ids)
    ref_findings, self_count = _reference_findings(id_set, edges, node_metadata, source, missing_note)
    cycle_graph: dict[str, list[str]] = {n: [] for n in sorted(id_set)}
    labels: dict[tuple[str, str], set[str]] = {}
    ordering_edges = 0
    for u, v, kind in edges:
        direction = orient(kind)
        if direction is None:
            continue
        ordering_edges += 1
        a, b = (v, u) if direction == "reverse" else (u, v)
        if a in cycle_graph and b in cycle_graph:
            cycle_graph[a].append(b)
            labels.setdefault((a, b), set()).add(kind or UNTYPED_EDGE_LABEL)
    typed = any(k is not None for _, _, k in edges)
    cyc_findings, cyc_summary = _cycle_findings(cycle_graph, source, cycle_limit, labels if typed else None)
    kind_counts = Counter(k or UNTYPED_EDGE_LABEL for _, _, k in edges)
    summary: dict[str, Any] = {
        "node_count": len(id_set),
        "edge_count": len(edges),
        "edge_kind_counts": dict(sorted(kind_counts.items())),
        "ordering_edge_count": ordering_edges,
        "self_dependency_count": self_count,
    }
    summary.update(cyc_summary)
    return ref_findings + cyc_findings, summary


def validate_generic_graph(
    nodes: dict[str, list[str]],
    node_metadata: dict[str, Any] | None = None,
    source: str = "graph",
    cycle_limit: int | None = DEFAULT_CYCLE_LIMIT,
) -> tuple[bool, list[DagFinding], dict[str, Any]]:
    """Validates a dependency graph for cycles, self-dependencies, dangling refs,
    tombstones, and empty input."""
    if len(nodes) == 0:
        finding = _finding(
            ERR_DAG_EMPTY_INPUT, "Dependency graph has 0 nodes; vacuous consistency rejected", source
        )
        return _finish([finding], {"node_count": 0, "edge_count": 0, "cycle_count": 0})
    edges: list[Edge] = [(u, v, None) for u in sorted(nodes) for v in nodes[u]]
    findings, summary = _graph_checks(list(nodes), edges, node_metadata, source, cycle_limit)
    return _finish(findings, summary)


# --------------------------------------------------------------------------- records


_Record = tuple[str, list[Edge], dict[str, Any], str]  # (id, edges, metadata, location)


def _parse_record(obj: Any, where: str, source: str, *, beads: bool) -> tuple[_Record | None, list[DagFinding]]:
    """Parse one node record.  beads=True applies the br JSONL export contract:
    dependency entries are objects carrying a string depends_on_id and type."""
    if not isinstance(obj, dict):
        return None, [_finding(ERR_DAG_CORRUPT_FILE, f"{where}: record is not a JSON object", source)]
    node_id = obj.get("id")
    if not isinstance(node_id, str) or not node_id:
        return None, [_finding(ERR_DAG_CORRUPT_FILE, f"{where}: missing, empty, or non-string 'id'", source)]
    errors: list[DagFinding] = []
    raw_deps = obj.get("dependencies", [])
    if not isinstance(raw_deps, list):
        return None, [
            _finding(ERR_DAG_CORRUPT_FILE, f"{where}: 'dependencies' of '{node_id}' must be a list", source, node_id=node_id)
        ]
    edges: list[Edge] = []
    for i, entry in enumerate(raw_deps):
        at = f"{where} ('{node_id}') dependencies[{i}]"
        if isinstance(entry, str) and not beads:
            if not entry:
                errors.append(_finding(ERR_DAG_CORRUPT_FILE, f"{at}: empty dependency id", source, node_id=node_id))
            else:
                edges.append((node_id, entry, None))
            continue
        if not isinstance(entry, dict):
            expected = "an object" if beads else "an object or string"
            errors.append(_finding(ERR_DAG_CORRUPT_FILE, f"{at}: dependency entry must be {expected}", source, node_id=node_id))
            continue
        target = entry.get("depends_on_id") if (beads or "depends_on_id" in entry) else entry.get("id")
        if not isinstance(target, str) or not target:
            errors.append(
                _finding(ERR_DAG_CORRUPT_FILE, f"{at}: missing, empty, or non-string 'depends_on_id'", source, node_id=node_id)
            )
            continue
        owner = entry.get("issue_id", node_id)
        if owner != node_id:
            errors.append(
                _finding(
                    ERR_DAG_CORRUPT_FILE,
                    f"{at}: issue_id {owner!r} does not match the owning record",
                    source,
                    node_id=node_id,
                    target_id=target,
                )
            )
            continue
        if beads or "type" in entry:
            kind = entry.get("type")
            if not isinstance(kind, str) or not kind:
                errors.append(
                    _finding(ERR_DAG_CORRUPT_FILE, f"{at}: missing or non-string dependency 'type'", source, node_id=node_id, target_id=target)
                )
                continue
            if kind not in ORDERING_EDGE_KINDS and kind not in NON_ORDERING_EDGE_KINDS:
                errors.append(
                    _finding(
                        ERR_DAG_UNKNOWN_EDGE_KIND,
                        f"{at}: unknown dependency kind {kind!r}; its ordering semantics are undefined, "
                        f"so the graph cannot be checked",
                        source,
                        node_id=node_id,
                        target_id=target,
                    )
                )
                continue
            edges.append((node_id, target, kind))
        else:
            edges.append((node_id, target, None))
    return (node_id, edges, {"status": obj.get("status", "")}, where), errors


def _parse_jsonl(text: str, source: str, *, beads: bool) -> tuple[list[_Record], list[DagFinding]]:
    records: list[_Record] = []
    errors: list[DagFinding] = []
    # split("\n"), not splitlines(): U+2028/U+2029 may legally appear inside JSON strings.
    for line_no, line in enumerate(text.split("\n"), start=1):
        if not line.strip():
            continue
        where = f"line {line_no}"
        obj, err = _loads_json(line, where, source)
        if err is not None:
            errors.append(err)
            continue
        record, rec_errors = _parse_record(obj, where, source, beads=beads)
        errors.extend(rec_errors)
        if record is not None:
            records.append(record)
    return records, errors


def _records_from_json(doc: Any, source: str) -> tuple[list[_Record], list[DagFinding]]:
    records: list[_Record] = []
    errors: list[DagFinding] = []
    if isinstance(doc, dict):
        if "nodes" not in doc:
            return [], [
                _finding(
                    ERR_DAG_CORRUPT_FILE,
                    "JSON object has no 'nodes' key; refusing to interpret an arbitrary object as a dependency graph",
                    source,
                )
            ]
        raw = doc["nodes"]
        if isinstance(raw, list):
            items = [(f"nodes[{i}]", item) for i, item in enumerate(raw)]
        elif isinstance(raw, dict):
            for key, deps in raw.items():
                where = f"nodes[{key!r}]"
                if not key:
                    errors.append(_finding(ERR_DAG_CORRUPT_FILE, f"{where}: empty node id", source))
                elif not isinstance(deps, list) or not all(isinstance(d, str) and d for d in deps):
                    errors.append(
                        _finding(
                            ERR_DAG_CORRUPT_FILE,
                            f"{where}: dependencies must be a list of non-empty strings",
                            source,
                            node_id=key,
                        )
                    )
                else:
                    records.append((key, [(key, d, None) for d in deps], {"status": ""}, where))
            return records, errors
        else:
            return [], [_finding(ERR_DAG_CORRUPT_FILE, "Invalid 'nodes' property in JSON (must be array or object)", source)]
    elif isinstance(doc, list):
        items = [(f"index {i}", item) for i, item in enumerate(doc)]
    else:
        return [], [
            _finding(ERR_DAG_CORRUPT_FILE, "JSON root must be an object with a 'nodes' key or an array of node records", source)
        ]
    for where, item in items:
        record, rec_errors = _parse_record(item, where, source, beads=False)
        errors.extend(rec_errors)
        if record is not None:
            records.append(record)
    return records, errors


def _assemble(records: list[_Record], source: str) -> tuple[list[str], list[Edge], dict[str, Any], list[DagFinding]]:
    """Merge records.  A duplicate ID is an error, and the edges of every definition
    are kept so a cycle through a shadowed definition is still found."""
    first_seen: dict[str, str] = {}
    metadata: dict[str, Any] = {}
    edges: list[Edge] = []
    findings: list[DagFinding] = []
    for node_id, rec_edges, meta, where in records:
        if node_id in first_seen:
            findings.append(
                _finding(
                    ERR_DAG_DUPLICATE_ID,
                    f"Duplicate node ID '{node_id}' at {where} (first defined at {first_seen[node_id]})",
                    source,
                    node_id=node_id,
                )
            )
        else:
            first_seen[node_id] = where
            metadata[node_id] = meta
        edges.extend(rec_edges)
    return list(first_seen), edges, metadata, findings


def _validate_records(
    records: list[_Record], parse_errors: list[DagFinding], source: str, cycle_limit: int | None
) -> tuple[bool, list[DagFinding], dict[str, Any]]:
    if parse_errors:
        # A partially parsed graph cannot certify anything: report every record defect
        # and mark the check incomplete rather than validating the surviving subset.
        return _input_failure(parse_errors, node_count=len(records), graph_checks_run=False)
    if not records:
        finding = _finding(ERR_DAG_EMPTY_INPUT, "Dependency graph has 0 nodes; vacuous consistency rejected", source)
        return _finish([finding], {"node_count": 0, "edge_count": 0, "cycle_count": 0})
    node_ids, edges, metadata, dup_findings = _assemble(records, source)
    findings, summary = _graph_checks(node_ids, edges, metadata, source, cycle_limit)
    summary["record_count"] = len(records)
    return _finish(dup_findings + findings, summary)


def validate_beads_dag(
    repo_root: Path, cycle_limit: int | None = DEFAULT_CYCLE_LIMIT
) -> tuple[bool, list[DagFinding], dict[str, Any]]:
    """Validates the beads issue tracker dependency graph (.beads/issues.jsonl)."""
    issues_path = repo_root / ".beads/issues.jsonl"
    source = str(issues_path)
    text, err = _read_utf8(issues_path, "beads issues file")
    if err is not None:
        return _input_failure([err])
    if not text.strip():
        finding = _finding(ERR_DAG_EMPTY_INPUT, "Beads issues file contains no records", source)
        return _finish([finding], {"node_count": 0, "edge_count": 0, "cycle_count": 0})
    records, errors = _parse_jsonl(text, source, beads=True)
    if not text.endswith("\n"):
        errors.append(
            _finding(
                ERR_DAG_CORRUPT_FILE,
                "Final record lacks its terminating newline; the file may be truncated mid-write",
                source,
            )
        )
    return _validate_records(records, errors, source, cycle_limit)


def validate_dag_file(path: Path, cycle_limit: int | None = DEFAULT_CYCLE_LIMIT) -> tuple[bool, list[DagFinding], dict[str, Any]]:
    """Validates a DAG file: JSONL records, a JSON array of records, or a JSON object
    with an explicit 'nodes' key (array of records or id -> [dependency ids])."""
    source = str(path)
    text, err = _read_utf8(path, "DAG file")
    if err is not None:
        return _input_failure([err])
    if not text.strip():
        finding = _finding(ERR_DAG_EMPTY_INPUT, f"DAG file is empty: {path}", source)
        return _finish([finding], {"node_count": 0, "edge_count": 0, "cycle_count": 0})
    if path.suffix == ".jsonl":
        records, errors = _parse_jsonl(text, source, beads=False)
    else:
        doc, err = _loads_json(text, source, source)
        if err is not None:
            return _input_failure([err])
        records, errors = _records_from_json(doc, source)
    return _validate_records(records, errors, source, cycle_limit)


# --------------------------------------------------------------------------- crates


def _layer_index(layer_id: Any) -> int | None:
    if not isinstance(layer_id, str):
        return None
    match = LAYER_ID_PATTERN.match(layer_id)
    return int(match.group(1)) if match else None


def check_crate_layer_inversions(
    layers: list[dict[str, Any]],
    crate_deps: dict[str, list[str]],
    source: str = "architecture/crate_topology.json",
    waivers: list[tuple[str, str]] | None = None,
) -> list[DagFinding]:
    """Validates downward dependency rules across crate topology layers.

    Crates in lower layers (e.g. L0 foundation) cannot depend on higher layers (e.g.
    L2 storage).  A (from, to) pair in `waivers` downgrades that inversion to a
    warning that is still reported; a waiver matching no upward edge is an error.
    Crates missing from the topology are the caller's responsibility
    (ERR_DAG_UNDECLARED_NODE / ERR_DAG_DANGLING_REFERENCE).
    """
    findings: list[DagFinding] = []
    crate_to_layer: dict[str, tuple[int, str]] = {}
    for i, layer in enumerate(layers):
        layer_id = layer.get("id") if isinstance(layer, dict) else None
        layer_idx = _layer_index(layer_id)
        if layer_idx is None:
            findings.append(
                _finding(
                    ERR_DAG_CORRUPT_FILE,
                    f"layers[{i}]: layer id {layer_id!r} is not of the form L<n>; its position is unknown",
                    source,
                )
            )
            continue
        crates = layer.get("crates")
        for crate in crates if isinstance(crates, list) else []:
            if isinstance(crate, dict) and isinstance(crate.get("name"), str):
                crate_to_layer[crate["name"]] = (layer_idx, layer_id)

    waiver_set = set(waivers or [])
    used_waivers: set[tuple[str, str]] = set()
    for src in sorted(crate_deps):
        if src not in crate_to_layer:
            continue
        src_idx, src_id = crate_to_layer[src]
        for dst in sorted(set(crate_deps[src])):
            if dst not in crate_to_layer:
                continue
            dst_idx, dst_id = crate_to_layer[dst]
            if src_idx >= dst_idx:
                continue
            if (src, dst) in waiver_set:
                used_waivers.add((src, dst))
                findings.append(
                    _finding(
                        WARN_DAG_LAYER_INVERSION_WAIVED,
                        f"Waived layer inversion: crate '{src}' in {src_id} depends upward on crate "
                        f"'{dst}' in {dst_id} (explicit layerWaivers entry in the crate topology)",
                        source,
                        node_id=src,
                        target_id=dst,
                        severity="warning",
                    )
                )
                continue
            findings.append(
                _finding(
                    ERR_DAG_LAYER_INVERSION,
                    f"Layer inversion detected: crate '{src}' in {src_id} "
                    f"depends upward on crate '{dst}' in {dst_id} (rules require downward dependencies)",
                    source,
                    node_id=src,
                    target_id=dst,
                )
            )
    for src, dst in sorted(waiver_set - used_waivers):
        findings.append(
            _finding(
                ERR_DAG_STALE_WAIVER,
                f"Layer waiver '{src}' -> '{dst}' matches no upward dependency edge; remove it or restore the edge",
                source,
                node_id=src,
                target_id=dst,
            )
        )
    return findings


def _parse_topology(
    doc: Any, source: str
) -> tuple[list[dict[str, Any]], dict[str, tuple[int, str]], list[tuple[str, str]], list[DagFinding]]:
    findings: list[DagFinding] = []
    declared: dict[str, tuple[int, str]] = {}
    waivers: list[tuple[str, str]] = []
    if not isinstance(doc, dict) or not isinstance(doc.get("layers"), list):
        return [], declared, waivers, [
            _finding(ERR_DAG_CORRUPT_FILE, "Missing or invalid 'layers' root array in crate topology", source)
        ]
    layers = doc["layers"]
    if not layers:
        return [], declared, waivers, [
            _finding(ERR_DAG_EMPTY_INPUT, "Crate topology declares no layers; vacuous hierarchy rejected", source)
        ]
    seen_index: dict[int, str] = {}
    for i, layer in enumerate(layers):
        at = f"layers[{i}]"
        if not isinstance(layer, dict):
            findings.append(_finding(ERR_DAG_CORRUPT_FILE, f"{at}: layer is not an object", source))
            continue
        layer_id = layer.get("id")
        idx = _layer_index(layer_id)
        if idx is None:
            findings.append(
                _finding(
                    ERR_DAG_CORRUPT_FILE,
                    f"{at}: layer id {layer_id!r} is not of the form L<n>; its position in the hierarchy is unknown",
                    source,
                )
            )
            continue
        if idx in seen_index:
            findings.append(
                _finding(
                    ERR_DAG_DUPLICATE_ID,
                    f"{at}: layer '{layer_id}' duplicates the index of layer '{seen_index[idx]}'",
                    source,
                    node_id=layer_id,
                )
            )
            continue
        seen_index[idx] = layer_id
        crates = layer.get("crates")
        if not isinstance(crates, list):
            findings.append(_finding(ERR_DAG_CORRUPT_FILE, f"{at} ('{layer_id}'): 'crates' must be a list", source))
            continue
        for j, crate in enumerate(crates):
            name = crate.get("name") if isinstance(crate, dict) else None
            if not isinstance(name, str) or not name:
                findings.append(
                    _finding(
                        ERR_DAG_CORRUPT_FILE,
                        f"{at}.crates[{j}] ('{layer_id}'): crate entry must be an object with a non-empty string 'name'",
                        source,
                    )
                )
                continue
            if name in declared:
                findings.append(
                    _finding(
                        ERR_DAG_DUPLICATE_ID,
                        f"Duplicate crate declaration '{name}' in topology ({declared[name][1]} and {layer_id})",
                        source,
                        node_id=name,
                    )
                )
                continue
            declared[name] = (idx, layer_id)
    if not findings and not declared:
        findings.append(_finding(ERR_DAG_EMPTY_INPUT, "Crate topology declares no crates; vacuous hierarchy rejected", source))

    if "layerWaivers" in doc:
        raw_waivers = doc["layerWaivers"]
        if not isinstance(raw_waivers, list):
            findings.append(_finding(ERR_DAG_CORRUPT_FILE, "'layerWaivers' must be an array", source))
        else:
            for k, waiver in enumerate(raw_waivers):
                fields = [waiver.get(f) if isinstance(waiver, dict) else None for f in ("from", "to", "reason")]
                if not all(isinstance(v, str) and v.strip() for v in fields):
                    findings.append(
                        _finding(
                            ERR_DAG_CORRUPT_FILE,
                            f"layerWaivers[{k}]: waiver must be an object with non-empty string 'from', 'to', and 'reason'",
                            source,
                        )
                    )
                    continue
                pair = (fields[0], fields[1])
                if pair in waivers:
                    findings.append(
                        _finding(ERR_DAG_DUPLICATE_ID, f"layerWaivers[{k}]: duplicate waiver {pair[0]} -> {pair[1]}", source, node_id=pair[0], target_id=pair[1])
                    )
                    continue
                waivers.append(pair)
    return layers, declared, waivers, findings


def _load_toml(path: Path, what: str) -> tuple[dict[str, Any] | None, DagFinding | None]:
    text, err = _read_utf8(path, what)
    if err is not None:
        return None, err
    try:
        return tomllib.loads(text), None
    except tomllib.TOMLDecodeError as exc:
        return None, _finding(ERR_DAG_CORRUPT_FILE, f"Cannot parse {path}: {exc}", str(path))


def _is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _manifest_dependencies(
    cargo: dict[str, Any], manifest: Path, repo_root: Path, workspace_deps: dict[str, Any]
) -> tuple[list[tuple[str, str, bool]], list[DagFinding]]:
    """Every dependency in every table as (package name, table label, path-in-repo)."""
    source = str(manifest)
    findings: list[DagFinding] = []
    tables: list[tuple[str, Any]] = [(t, cargo[t]) for t in CARGO_DEPENDENCY_TABLES if t in cargo]
    target = cargo.get("target", {})
    if not isinstance(target, dict):
        findings.append(_finding(ERR_DAG_CORRUPT_FILE, f"{manifest}: [target] is not a table", source))
    else:
        for cfg in sorted(target):
            cfg_table = target[cfg]
            if not isinstance(cfg_table, dict):
                findings.append(_finding(ERR_DAG_CORRUPT_FILE, f"{manifest}: [target.{cfg}] is not a table", source))
                continue
            tables.extend((f"target.{cfg}.{t}", cfg_table[t]) for t in CARGO_DEPENDENCY_TABLES if t in cfg_table)
    resolved_root = repo_root.resolve()
    deps: list[tuple[str, str, bool]] = []
    for label, table in tables:
        if not isinstance(table, dict):
            findings.append(_finding(ERR_DAG_CORRUPT_FILE, f"{manifest}: [{label}] is not a table", source))
            continue
        for key in sorted(table):
            spec = table[key]
            package: Any = key
            dep_path: Any = None
            base_dir = manifest.parent
            if isinstance(spec, dict):
                if spec.get("workspace") is True:
                    inherited = workspace_deps.get(key)
                    if inherited is None:
                        findings.append(
                            _finding(
                                ERR_DAG_DANGLING_REFERENCE,
                                f"{manifest}: [{label}] '{key}' inherits a workspace dependency that "
                                f"[workspace.dependencies] does not define",
                                source,
                                target_id=key,
                            )
                        )
                        continue
                    if isinstance(inherited, dict):
                        package = inherited.get("package", key)
                        dep_path = inherited.get("path")
                    base_dir = repo_root
                else:
                    package = spec.get("package", key)
                    dep_path = spec.get("path")
            elif not isinstance(spec, str):
                findings.append(
                    _finding(ERR_DAG_CORRUPT_FILE, f"{manifest}: [{label}] '{key}' must be a version string or table", source)
                )
                continue
            if not isinstance(package, str) or not package or (dep_path is not None and not isinstance(dep_path, str)):
                findings.append(
                    _finding(ERR_DAG_CORRUPT_FILE, f"{manifest}: [{label}] '{key}' has a non-string package or path", source)
                )
                continue
            in_repo = dep_path is not None and _is_within((base_dir / dep_path).resolve(), resolved_root)
            deps.append((package, label, in_repo))
    return deps, findings


def _discover_manifests(repo_root: Path) -> tuple[list[Path], dict[str, Any], list[DagFinding]]:
    """crates/*/Cargo.toml plus every workspace member (and a root [package])."""
    findings: list[DagFinding] = []
    manifests: set[Path] = set()
    workspace_deps: dict[str, Any] = {}
    crates_dir = repo_root / "crates"
    try:
        if crates_dir.is_dir():
            for entry in sorted(crates_dir.iterdir()):
                if (entry / "Cargo.toml").is_file():
                    manifests.add(entry / "Cargo.toml")
    except OSError as exc:
        findings.append(_finding(ERR_DAG_UNREADABLE_FILE, f"Cannot enumerate {crates_dir}: {exc}", str(crates_dir)))

    root_manifest = repo_root / "Cargo.toml"
    try:
        root_exists = root_manifest.exists()
    except OSError as exc:
        findings.append(_finding(ERR_DAG_UNREADABLE_FILE, f"Cannot stat {root_manifest}: {exc}", str(root_manifest)))
        root_exists = False
    if root_exists:
        root_doc, err = _load_toml(root_manifest, "workspace manifest")
        if err is not None:
            findings.append(err)
        else:
            if "package" in root_doc:
                manifests.add(root_manifest)
            workspace = root_doc.get("workspace", {})
            members = workspace.get("members", []) if isinstance(workspace, dict) else None
            ws_deps = workspace.get("dependencies", {}) if isinstance(workspace, dict) else None
            if not isinstance(members, list) or not isinstance(ws_deps, dict):
                findings.append(
                    _finding(ERR_DAG_CORRUPT_FILE, f"{root_manifest}: [workspace] members/dependencies malformed", str(root_manifest))
                )
            else:
                workspace_deps = ws_deps
                for member in members:
                    if not isinstance(member, str) or not member:
                        findings.append(
                            _finding(ERR_DAG_CORRUPT_FILE, f"{root_manifest}: non-string workspace member {member!r}", str(root_manifest))
                        )
                        continue
                    member_dirs = sorted(repo_root.glob(member)) if any(ch in member for ch in "*?[") else [repo_root / member]
                    for member_dir in member_dirs:
                        member_manifest = member_dir / "Cargo.toml"
                        if member_manifest.is_file():
                            manifests.add(member_manifest)
                        elif not any(ch in member for ch in "*?["):
                            findings.append(
                                _finding(
                                    ERR_DAG_MISSING_FILE,
                                    f"Workspace member '{member}' has no manifest at {member_manifest}",
                                    str(root_manifest),
                                    node_id=member,
                                )
                            )
    return sorted(manifests), workspace_deps, findings


def validate_crate_topology_dag(
    repo_root: Path, cycle_limit: int | None = DEFAULT_CYCLE_LIMIT
) -> tuple[bool, list[DagFinding], dict[str, Any]]:
    """Validates the crate topology layers and every workspace crate dependency."""
    topo_path = repo_root / "architecture/crate_topology.json"
    source = str(topo_path)
    text, err = _read_utf8(topo_path, "crate topology file")
    if err is not None:
        return _input_failure([err], crate_count=0)
    doc, err = _loads_json(text, source, source)
    if err is not None:
        return _input_failure([err], crate_count=0)
    layers, declared, waivers, topo_findings = _parse_topology(doc, source)
    if topo_findings:
        return _input_failure(topo_findings, crate_count=0, declared_crate_count=len(declared))

    manifests, workspace_deps, findings = _discover_manifests(repo_root)
    complete = not findings
    crates: dict[str, tuple[Path, list[tuple[str, str, bool]]]] = {}
    for manifest in manifests:
        cargo, err = _load_toml(manifest, "crate manifest")
        if err is not None:
            findings.append(err)
            complete = False
            continue
        package = cargo.get("package")
        name = package.get("name") if isinstance(package, dict) else None
        if not isinstance(name, str) or not name:
            findings.append(_finding(ERR_DAG_CORRUPT_FILE, f"{manifest}: missing or non-string [package].name", str(manifest)))
            complete = False
            continue
        if name in crates:
            findings.append(
                _finding(
                    ERR_DAG_DUPLICATE_ID,
                    f"Crate name '{name}' is defined by both {crates[name][0]} and {manifest}",
                    str(manifest),
                    node_id=name,
                )
            )
            continue
        deps, dep_findings = _manifest_dependencies(cargo, manifest, repo_root, workspace_deps)
        if dep_findings:
            findings.extend(dep_findings)
            complete = False
        crates[name] = (manifest, deps)

    if not crates and complete:
        findings.append(_finding(ERR_DAG_EMPTY_INPUT, "No crate manifests found; vacuous topology check rejected", source))

    on_disk = set(crates)
    for name in sorted(on_disk - set(declared)):
        findings.append(
            _finding(
                ERR_DAG_UNDECLARED_NODE,
                f"Crate '{name}' ({crates[name][0]}) is not declared in any topology layer; its layer is unknown, "
                f"so its dependencies cannot be checked for inversions",
                source,
                node_id=name,
            )
        )

    edges: list[Edge] = []
    for name in sorted(crates):
        for dep, label, in_repo in crates[name][1]:
            if dep in declared or dep in on_disk or dep.startswith("fss-") or in_repo:
                edges.append((name, dep, label))

    def missing_note(dep: str) -> str:
        if dep in declared:
            return f" (declared in {declared[dep][1]} but no crate manifest exists on disk)"
        return " (not declared in the crate topology and no crate manifest exists on disk)"

    graph_findings, graph_summary = _graph_checks(
        sorted(on_disk), edges, None, "crates/*/Cargo.toml", cycle_limit, orient=lambda _kind: "forward", missing_note=missing_note
    )
    crate_deps: dict[str, list[str]] = {name: [] for name in sorted(on_disk)}
    for src, dst, _label in edges:
        if dst in on_disk:
            crate_deps[src].append(dst)
    layer_findings = check_crate_layer_inversions(layers, crate_deps, source=source, waivers=waivers)
    waived = sorted([f.node_id, f.target_id] for f in layer_findings if f.code == WARN_DAG_LAYER_INVERSION_WAIVED)

    summary: dict[str, Any] = {
        "crate_count": len(on_disk),
        "declared_crate_count": len(declared),
        "internal_edge_count": len(edges),
        "edge_kind_counts": graph_summary["edge_kind_counts"],
        "cycle_count": graph_summary["cycle_count"],
        "cycle_enumeration_complete": graph_summary["cycle_enumeration_complete"],
        "waived_inversions": waived,
        "complete": complete,
    }
    return _finish(findings + graph_findings + layer_findings, summary)


def validate_all(repo_root: Path) -> tuple[bool, list[DagFinding], dict[str, Any]]:
    """Runs all repository dependency DAG checks (beads issues + crate topology)."""
    beads_valid, beads_findings, beads_summary = validate_beads_dag(repo_root)
    topo_valid, topo_findings, topo_summary = validate_crate_topology_dag(repo_root)
    all_findings = beads_findings + topo_findings
    summary: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "beads_summary": beads_summary,
        "crate_topology_summary": topo_summary,
        "complete": bool(beads_summary["complete"] and topo_summary["complete"]),
    }
    is_valid, findings, summary = _finish(all_findings, summary)
    return is_valid and beads_valid and topo_valid, findings, summary


def _describe(summary: dict[str, Any]) -> list[str]:
    lines: list[str] = []

    def kinds(s: dict[str, Any]) -> str:
        counts = s.get("edge_kind_counts") or {}
        return ", ".join(f"{k}={v}" for k, v in counts.items()) or "none"

    if "beads_summary" in summary:
        b = summary["beads_summary"]
        lines.append(
            f"  beads: {b.get('node_count', 0)} issues, {b.get('edge_count', 0)} edges ({kinds(b)}), "
            f"{b.get('cycle_count', 0)} cycle(s), complete={b.get('complete')}"
        )
        c = summary["crate_topology_summary"]
        lines.append(
            f"  crates: {c.get('crate_count', 0)} on disk / {c.get('declared_crate_count', 0)} declared, "
            f"{c.get('internal_edge_count', 0)} internal edges ({kinds(c)}), {c.get('cycle_count', 0)} cycle(s), "
            f"{len(c.get('waived_inversions', []))} waived inversion(s), complete={c.get('complete')}"
        )
    else:
        lines.append(
            f"  file: {summary.get('node_count', 0)} nodes, {summary.get('edge_count', 0)} edges ({kinds(summary)}), "
            f"{summary.get('cycle_count', 0)} cycle(s), complete={summary.get('complete')}"
        )
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Deterministic dependency DAG checker for Franken Surveillance System"
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help=f"Path to repository root (defaults to {ROOT})",
    )
    parser.add_argument(
        "--file",
        type=Path,
        default=None,
        help="Validate a specific DAG file (JSON or JSONL) instead of the repository",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output structured JSON report conforming to fss.dependency_dag_report.v1",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings (including waived layer inversions) as errors",
    )
    args = parser.parse_args(argv)
    if args.file is not None and args.repo_root is not None:
        parser.error("--file and --repo-root are mutually exclusive")

    if args.file is not None:
        is_valid, findings, summary = validate_dag_file(args.file)
    else:
        is_valid, findings, summary = validate_all(args.repo_root or ROOT)

    full_summary = {
        "schema": REPORT_SCHEMA,
        "status": summary["status"],
        "complete": summary["complete"],
        "error_count": summary["error_count"],
        "warning_count": summary["warning_count"],
        "findings": [asdict(f) for f in findings],
        "summary": summary,
    }
    if args.strict and full_summary["warning_count"] > 0:
        is_valid = False
        full_summary["status"] = "fail"

    if args.json:
        print(json.dumps(full_summary, indent=2))
    else:
        if is_valid:
            print(
                f"[PASS] Dependency DAG checks passed: 0 errors, "
                f"{full_summary['warning_count']} warning(s)."
            )
        else:
            print(
                f"[FAIL] Dependency DAG checks failed: {full_summary['error_count']} error(s), "
                f"{full_summary['warning_count']} warning(s), complete={full_summary['complete']}:"
            )
        for line in _describe(summary):
            print(line)
        for f in findings:
            print(f"  - [{f.code}] {f.source}: {f.message}")

    return 0 if is_valid else 1


if __name__ == "__main__":
    sys.exit(main())
