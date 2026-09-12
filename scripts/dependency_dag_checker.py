#!/usr/bin/env python3
"""Deterministic dependency DAG checker (fss-x4a.6.10 / FSS-010).

Validates:
1. Beads issue tracker dependency DAG (.beads/issues.jsonl).
2. Crate topology layer hierarchy (architecture/crate_topology.json + crates/*/Cargo.toml).
3. Generic arbitrary DAG files (.json, .jsonl).

Fails closed on:
- Directed cycles (ERR-DAG-CYCLE-001)
- Self-dependencies (ERR-DAG-SELF-DEPENDENCY-001)
- Dangling references (ERR-DAG-DANGLING-REFERENCE-001)
- Duplicate node definitions (ERR-DAG-DUPLICATE-ID-001)
- Missing files (ERR-DAG-MISSING-FILE-001)
- Corrupt/unparseable files (ERR-DAG-CORRUPT-FILE-001)
- Empty/vacuous graphs (ERR-DAG-EMPTY-INPUT-001)
- Crate layer inversions (ERR-DAG-LAYER-INVERSION-001)
- Tombstone references (ERR-DAG-TOMBSTONE-REFERENCE-001)
"""
from __future__ import annotations

import argparse
import json
import sys
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import stable_id_audit

# Stable diagnostic error codes
ERR_DAG_CYCLE = "ERR-DAG-CYCLE-001"
ERR_DAG_SELF_DEPENDENCY = "ERR-DAG-SELF-DEPENDENCY-001"
ERR_DAG_DANGLING_REFERENCE = "ERR-DAG-DANGLING-REFERENCE-001"
ERR_DAG_DUPLICATE_ID = "ERR-DAG-DUPLICATE-ID-001"
ERR_DAG_MISSING_FILE = "ERR-DAG-MISSING-FILE-001"
ERR_DAG_CORRUPT_FILE = "ERR-DAG-CORRUPT-FILE-001"
ERR_DAG_EMPTY_INPUT = "ERR-DAG-EMPTY-INPUT-001"
ERR_DAG_LAYER_INVERSION = "ERR-DAG-LAYER-INVERSION-001"
ERR_DAG_TOMBSTONE_REFERENCE = "ERR-DAG-TOMBSTONE-REFERENCE-001"

REPORT_SCHEMA = "fss.dependency_dag_report.v1"

# Status values that retire an ID/issue
TOMBSTONE_STATES = stable_id_audit.TOMBSTONE_STATES


@dataclass(frozen=True)
class DagFinding:
    code: str
    severity: str  # "error" | "warning"
    message: str
    source: str
    node_id: str | None = None
    target_id: str | None = None
    cycle_path: list[str] | None = None


def find_cycles(graph: dict[str, list[str]]) -> list[list[str]]:
    """Detects all elementary directed cycles deterministically using 3-color DFS.
    
    Returns a sorted list of canonical cycle paths [node1, node2, ..., node1].
    """
    color: dict[str, int] = {}  # 0: white, 1: grey (visiting), 2: black (done)
    found_cycles: list[list[str]] = []
    seen_cycle_signatures: set[tuple[str, ...]] = set()

    for start_node in sorted(graph.keys()):
        if color.get(start_node, 0) != 0:
            continue

        stack: list[tuple[str, int]] = [(start_node, 0)]
        path: list[str] = [start_node]
        color[start_node] = 1

        while stack:
            u, neighbor_idx = stack[-1]
            neighbors = sorted(graph.get(u, []))

            if neighbor_idx < len(neighbors):
                stack[-1] = (u, neighbor_idx + 1)
                v = neighbors[neighbor_idx]
                if v not in graph:
                    continue  # Dangling reference handled separately

                v_color = color.get(v, 0)
                if v_color == 1:
                    # Found a cycle back to a node in path
                    if v in path:
                        cycle_start_idx = path.index(v)
                        cycle_body = path[cycle_start_idx:]
                        # Self dependency length-1 cycles handled separately
                        if len(cycle_body) >= 2:
                            min_elem = min(cycle_body)
                            min_idx = cycle_body.index(min_elem)
                            canon_body = cycle_body[min_idx:] + cycle_body[:min_idx]
                            sig = tuple(canon_body)
                            if sig not in seen_cycle_signatures:
                                seen_cycle_signatures.add(sig)
                                found_cycles.append(canon_body + [min_elem])
                elif v_color == 0:
                    color[v] = 1
                    path.append(v)
                    stack.append((v, 0))
            else:
                color[u] = 2
                path.pop()
                stack.pop()

    return sorted(found_cycles, key=lambda c: (len(c), c))


def validate_generic_graph(
    nodes: dict[str, list[str]],
    node_metadata: dict[str, Any] | None = None,
    source: str = "graph",
) -> tuple[bool, list[DagFinding], dict[str, Any]]:
    """Validates a dependency graph for cycles, self-dependencies, dangling refs,
    tombstones, and empty input.
    """
    findings: list[DagFinding] = []

    # 1. Vacuous / empty graph check
    if len(nodes) == 0:
        findings.append(
            DagFinding(
                code=ERR_DAG_EMPTY_INPUT,
                severity="error",
                message="Dependency graph has 0 nodes; vacuous consistency rejected",
                source=source,
            )
        )
        return False, findings, {
            "status": "fail",
            "node_count": 0,
            "edge_count": 0,
            "error_count": 1,
            "warning_count": 0,
        }

    total_edges = 0
    all_node_ids = set(nodes.keys())

    # 2. Self-dependencies and Dangling references
    for u in sorted(nodes.keys()):
        deps = nodes[u]
        total_edges += len(deps)
        for v in sorted(deps):
            if u == v:
                findings.append(
                    DagFinding(
                        code=ERR_DAG_SELF_DEPENDENCY,
                        severity="error",
                        message=f"Node '{u}' has a direct self-dependency",
                        source=source,
                        node_id=u,
                        target_id=v,
                        cycle_path=[u, u],
                    )
                )
            elif v not in all_node_ids:
                findings.append(
                    DagFinding(
                        code=ERR_DAG_DANGLING_REFERENCE,
                        severity="error",
                        message=f"Node '{u}' references undefined dependency '{v}'",
                        source=source,
                        node_id=u,
                        target_id=v,
                    )
                )

    # 3. Tombstone references (active node referencing a tombstoned dependency)
    if node_metadata:
        for u in sorted(nodes.keys()):
            u_meta = node_metadata.get(u, {})
            u_status = str(u_meta.get("status", "")).strip().lower()
            if u_status not in TOMBSTONE_STATES:
                for v in sorted(nodes[u]):
                    if v in node_metadata:
                        v_meta = node_metadata[v]
                        v_status = str(v_meta.get("status", "")).strip().lower()
                        if v_status in TOMBSTONE_STATES:
                            findings.append(
                                DagFinding(
                                    code=ERR_DAG_TOMBSTONE_REFERENCE,
                                    severity="error",
                                    message=(
                                        f"Active node '{u}' (status='{u_status}') references "
                                        f"tombstoned dependency '{v}' (status='{v_status}')"
                                    ),
                                    source=source,
                                    node_id=u,
                                    target_id=v,
                                )
                            )

    # 4. Cycle detection
    cycles = find_cycles(nodes)
    for cycle in cycles:
        cycle_str = " -> ".join(cycle)
        findings.append(
            DagFinding(
                code=ERR_DAG_CYCLE,
                severity="error",
                message=f"Directed cycle detected: {cycle_str}",
                source=source,
                node_id=cycle[0],
                cycle_path=cycle,
            )
        )

    error_count = sum(1 for f in findings if f.severity == "error")
    warning_count = sum(1 for f in findings if f.severity == "warning")
    is_valid = error_count == 0

    summary = {
        "status": "pass" if is_valid else "fail",
        "node_count": len(nodes),
        "edge_count": total_edges,
        "cycle_count": len(cycles),
        "error_count": error_count,
        "warning_count": warning_count,
    }
    return is_valid, findings, summary


def check_crate_layer_inversions(
    layers: list[dict[str, Any]],
    crate_deps: dict[str, list[str]],
    source: str = "architecture/crate_topology.json",
) -> list[DagFinding]:
    """Validates downward dependency rules across crate topology layers.
    
    Crates in lower layers (e.g. L0 foundation) cannot depend on higher layers (e.g. L2 storage).
    """
    findings: list[DagFinding] = []
    crate_to_layer: dict[str, tuple[int, str]] = {}
    for layer in layers:
        layer_id = layer.get("id", "")
        try:
            layer_idx = int(layer_id[1:]) if layer_id.startswith("L") else int(layer_id)
        except ValueError:
            layer_idx = 999
        for c in layer.get("crates", []):
            cname = c.get("name")
            if cname:
                crate_to_layer[cname] = (layer_idx, layer_id)

    # Permitted development rehearsal harness edge
    ALLOWED_REHEARSAL_EDGES = {("fss-cli", "fss-reference")}

    for src in sorted(crate_deps.keys()):
        if src not in crate_to_layer:
            continue
        src_idx, src_id = crate_to_layer[src]
        for dst in sorted(crate_deps[src]):
            if (src, dst) in ALLOWED_REHEARSAL_EDGES:
                continue
            if dst not in crate_to_layer:
                continue
            dst_idx, dst_id = crate_to_layer[dst]
            # Upward layer dependency
            if src_idx < dst_idx:
                findings.append(
                    DagFinding(
                        code=ERR_DAG_LAYER_INVERSION,
                        severity="error",
                        message=(
                            f"Layer inversion detected: crate '{src}' in {src_id} "
                            f"depends upward on crate '{dst}' in {dst_id} (rules require downward dependencies)"
                        ),
                        source=source,
                        node_id=src,
                        target_id=dst,
                    )
                )
    return findings


def validate_beads_dag(repo_root: Path) -> tuple[bool, list[DagFinding], dict[str, Any]]:
    """Validates the beads issue tracker dependency graph (.beads/issues.jsonl)."""
    issues_path = repo_root / ".beads/issues.jsonl"
    if not issues_path.is_file():
        finding = DagFinding(
            code=ERR_DAG_MISSING_FILE,
            severity="error",
            message=f"Missing beads issues file: {issues_path}",
            source=str(issues_path),
        )
        return False, [finding], {
            "status": "fail",
            "node_count": 0,
            "edge_count": 0,
            "error_count": 1,
            "warning_count": 0,
        }

    seen_ids: set[str] = set()
    duplicate_findings: list[DagFinding] = []
    nodes: dict[str, list[str]] = {}
    node_metadata: dict[str, Any] = {}

    try:
        with open(issues_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception as e:
                    finding = DagFinding(
                        code=ERR_DAG_CORRUPT_FILE,
                        severity="error",
                        message=f"Malformed JSON at line {line_num}: {e}",
                        source=str(issues_path),
                    )
                    return False, [finding], {
                        "status": "fail",
                        "node_count": 0,
                        "edge_count": 0,
                        "error_count": 1,
                        "warning_count": 0,
                    }

                if not isinstance(obj, dict) or "id" not in obj or not isinstance(obj["id"], str):
                    finding = DagFinding(
                        code=ERR_DAG_CORRUPT_FILE,
                        severity="error",
                        message=f"Missing or non-string 'id' at line {line_num}",
                        source=str(issues_path),
                    )
                    return False, [finding], {
                        "status": "fail",
                        "node_count": 0,
                        "edge_count": 0,
                        "error_count": 1,
                        "warning_count": 0,
                    }

                issue_id = obj["id"]
                if issue_id in seen_ids:
                    duplicate_findings.append(
                        DagFinding(
                            code=ERR_DAG_DUPLICATE_ID,
                            severity="error",
                            message=f"Duplicate issue ID '{issue_id}' at line {line_num}",
                            source=str(issues_path),
                            node_id=issue_id,
                        )
                    )
                seen_ids.add(issue_id)
                node_metadata[issue_id] = {"status": obj.get("status", "")}

                # Extract blocking dependencies
                deps: list[str] = []
                for d in obj.get("dependencies", []):
                    if isinstance(d, dict):
                        dep_id = d.get("depends_on_id")
                        dep_type = d.get("type", "blocks")
                        if dep_id and dep_type == "blocks":
                            deps.append(dep_id)
                    elif isinstance(d, str):
                        deps.append(d)
                nodes[issue_id] = deps
    except OSError as e:
        finding = DagFinding(
            code=ERR_DAG_MISSING_FILE,
            severity="error",
            message=f"Cannot read beads issues file: {e}",
            source=str(issues_path),
        )
        return False, [finding], {
            "status": "fail",
            "node_count": 0,
            "edge_count": 0,
            "error_count": 1,
            "warning_count": 0,
        }

    is_valid, findings, summary = validate_generic_graph(
        nodes, node_metadata=node_metadata, source=str(issues_path)
    )
    all_findings = duplicate_findings + findings
    err_count = sum(1 for f in all_findings if f.severity == "error")
    warn_count = sum(1 for f in all_findings if f.severity == "warning")
    summary["error_count"] = err_count
    summary["warning_count"] = warn_count
    summary["status"] = "pass" if err_count == 0 else "fail"
    return err_count == 0, all_findings, summary


def validate_crate_topology_dag(repo_root: Path) -> tuple[bool, list[DagFinding], dict[str, Any]]:
    """Validates the crate topology layers and workspace dependencies."""
    topo_path = repo_root / "architecture/crate_topology.json"
    if not topo_path.is_file():
        finding = DagFinding(
            code=ERR_DAG_MISSING_FILE,
            severity="error",
            message=f"Missing crate topology file: {topo_path}",
            source=str(topo_path),
        )
        return False, [finding], {
            "status": "fail",
            "crate_count": 0,
            "error_count": 1,
            "warning_count": 0,
        }

    try:
        topo_doc = json.loads(topo_path.read_text(encoding="utf-8"))
    except Exception as e:
        finding = DagFinding(
            code=ERR_DAG_CORRUPT_FILE,
            severity="error",
            message=f"Cannot parse crate topology JSON: {e}",
            source=str(topo_path),
        )
        return False, [finding], {
            "status": "fail",
            "crate_count": 0,
            "error_count": 1,
            "warning_count": 0,
        }

    if "layers" not in topo_doc or not isinstance(topo_doc["layers"], list):
        finding = DagFinding(
            code=ERR_DAG_CORRUPT_FILE,
            severity="error",
            message="Missing or invalid 'layers' root array in crate topology",
            source=str(topo_path),
        )
        return False, [finding], {
            "status": "fail",
            "crate_count": 0,
            "error_count": 1,
            "warning_count": 0,
        }

    layers = topo_doc["layers"]
    declared_crates: dict[str, str] = {}
    duplicate_findings: list[DagFinding] = []

    for layer in layers:
        for c in layer.get("crates", []):
            cname = c.get("name")
            if cname:
                if cname in declared_crates:
                    duplicate_findings.append(
                        DagFinding(
                            code=ERR_DAG_DUPLICATE_ID,
                            severity="error",
                            message=f"Duplicate crate declaration '{cname}' in topology",
                            source=str(topo_path),
                            node_id=cname,
                        )
                    )
                declared_crates[cname] = layer.get("id", "")

    # Read actual crate Cargo.toml manifests
    crates_dir = repo_root / "crates"
    crate_deps: dict[str, list[str]] = {}
    if crates_dir.is_dir():
        for p in sorted(crates_dir.iterdir()):
            cargo_file = p / "Cargo.toml"
            if p.is_dir() and cargo_file.is_file():
                try:
                    cargo_doc = tomllib.loads(cargo_file.read_text(encoding="utf-8"))
                    direct_deps = cargo_doc.get("dependencies", {})
                    cdeps = [
                        dname for dname in direct_deps.keys()
                        if dname in declared_crates
                    ]
                    crate_deps[p.name] = cdeps
                except Exception as e:
                    finding = DagFinding(
                        code=ERR_DAG_CORRUPT_FILE,
                        severity="error",
                        message=f"Cannot parse {cargo_file}: {e}",
                        source=str(cargo_file),
                        node_id=p.name,
                    )
                    duplicate_findings.append(finding)

    # Check for cycles among crates on disk
    is_valid_graph, graph_findings, _ = validate_generic_graph(
        crate_deps, source="crates/*/Cargo.toml"
    )

    # Check for layer inversions
    inversion_findings = check_crate_layer_inversions(
        layers, crate_deps, source=str(topo_path)
    )

    all_findings = duplicate_findings + graph_findings + inversion_findings
    err_count = sum(1 for f in all_findings if f.severity == "error")
    warn_count = sum(1 for f in all_findings if f.severity == "warning")
    is_clean = err_count == 0

    summary = {
        "status": "pass" if is_clean else "fail",
        "crate_count": len(crate_deps),
        "declared_crate_count": len(declared_crates),
        "error_count": err_count,
        "warning_count": warn_count,
    }
    return is_clean, all_findings, summary


def validate_dag_file(path: Path) -> tuple[bool, list[DagFinding], dict[str, Any]]:
    """Validates an arbitrary DAG file (JSON or JSONL)."""
    if not path.is_file():
        finding = DagFinding(
            code=ERR_DAG_MISSING_FILE,
            severity="error",
            message=f"File not found: {path}",
            source=str(path),
        )
        return False, [finding], {
            "status": "fail",
            "node_count": 0,
            "edge_count": 0,
            "error_count": 1,
            "warning_count": 0,
        }

    nodes: dict[str, list[str]] = {}
    node_metadata: dict[str, Any] = {}
    seen_ids: set[str] = set()
    duplicate_findings: list[DagFinding] = []

    if path.suffix == ".jsonl":
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception as e:
                        finding = DagFinding(
                            code=ERR_DAG_CORRUPT_FILE,
                            severity="error",
                            message=f"Malformed JSONL line {line_num}: {e}",
                            source=str(path),
                        )
                        return False, [finding], {
                            "status": "fail",
                            "node_count": 0,
                            "edge_count": 0,
                            "error_count": 1,
                            "warning_count": 0,
                        }

                    if not isinstance(obj, dict) or "id" not in obj:
                        finding = DagFinding(
                            code=ERR_DAG_CORRUPT_FILE,
                            severity="error",
                            message=f"Missing 'id' at line {line_num}",
                            source=str(path),
                        )
                        return False, [finding], {
                            "status": "fail",
                            "node_count": 0,
                            "edge_count": 0,
                            "error_count": 1,
                            "warning_count": 0,
                        }

                    node_id = str(obj["id"])
                    if node_id in seen_ids:
                        duplicate_findings.append(
                            DagFinding(
                                code=ERR_DAG_DUPLICATE_ID,
                                severity="error",
                                message=f"Duplicate node ID '{node_id}' at line {line_num}",
                                source=str(path),
                                node_id=node_id,
                            )
                        )
                    seen_ids.add(node_id)
                    node_metadata[node_id] = {"status": obj.get("status", "")}

                    raw_deps = obj.get("dependencies", [])
                    deps: list[str] = []
                    if isinstance(raw_deps, list):
                        for d in raw_deps:
                            if isinstance(d, dict):
                                dep_id = d.get("depends_on_id") or d.get("id")
                                if dep_id:
                                    deps.append(str(dep_id))
                            elif isinstance(d, str):
                                deps.append(d)
                    nodes[node_id] = deps
        except OSError as e:
            finding = DagFinding(
                code=ERR_DAG_MISSING_FILE,
                severity="error",
                message=f"Cannot read file: {e}",
                source=str(path),
            )
            return False, [finding], {
                "status": "fail",
                "node_count": 0,
                "edge_count": 0,
                "error_count": 1,
                "warning_count": 0,
            }
    else:
        # JSON file
        try:
            content = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            finding = DagFinding(
                code=ERR_DAG_CORRUPT_FILE,
                severity="error",
                message=f"Malformed JSON in {path}: {e}",
                source=str(path),
            )
            return False, [finding], {
                "status": "fail",
                "node_count": 0,
                "edge_count": 0,
                "error_count": 1,
                "warning_count": 0,
            }

        if isinstance(content, dict) and "nodes" in content:
            raw_nodes = content["nodes"]
            if isinstance(raw_nodes, list):
                for idx, item in enumerate(raw_nodes):
                    if not isinstance(item, dict) or "id" not in item:
                        finding = DagFinding(
                            code=ERR_DAG_CORRUPT_FILE,
                            severity="error",
                            message=f"Node at index {idx} lacks 'id' field",
                            source=str(path),
                        )
                        return False, [finding], {
                            "status": "fail",
                            "node_count": 0,
                            "edge_count": 0,
                            "error_count": 1,
                            "warning_count": 0,
                        }
                    nid = str(item["id"])
                    if nid in seen_ids:
                        duplicate_findings.append(
                            DagFinding(
                                code=ERR_DAG_DUPLICATE_ID,
                                severity="error",
                                message=f"Duplicate node ID '{nid}' at index {idx}",
                                source=str(path),
                                node_id=nid,
                            )
                        )
                    seen_ids.add(nid)
                    node_metadata[nid] = {"status": item.get("status", "")}
                    deps_list = item.get("dependencies", [])
                    nodes[nid] = [str(x) for x in deps_list] if isinstance(deps_list, list) else []
            elif isinstance(raw_nodes, dict):
                for k, v in raw_nodes.items():
                    nid = str(k)
                    nodes[nid] = [str(x) for x in v] if isinstance(v, list) else []
            else:
                finding = DagFinding(
                    code=ERR_DAG_CORRUPT_FILE,
                    severity="error",
                    message="Invalid 'nodes' property in JSON",
                    source=str(path),
                )
                return False, [finding], {
                    "status": "fail",
                    "node_count": 0,
                    "edge_count": 0,
                    "error_count": 1,
                    "warning_count": 0,
                }
        elif isinstance(content, dict):
            # Direct mapping of id -> [deps]
            for k, v in content.items():
                nid = str(k)
                nodes[nid] = [str(x) for x in v] if isinstance(v, list) else []
        elif isinstance(content, list):
            for idx, item in enumerate(content):
                if not isinstance(item, dict) or "id" not in item:
                    finding = DagFinding(
                        code=ERR_DAG_CORRUPT_FILE,
                        severity="error",
                        message=f"Item at index {idx} lacks 'id' field",
                        source=str(path),
                    )
                    return False, [finding], {
                        "status": "fail",
                        "node_count": 0,
                        "edge_count": 0,
                        "error_count": 1,
                        "warning_count": 0,
                    }
                nid = str(item["id"])
                if nid in seen_ids:
                    duplicate_findings.append(
                        DagFinding(
                            code=ERR_DAG_DUPLICATE_ID,
                            severity="error",
                            message=f"Duplicate node ID '{nid}' at index {idx}",
                            source=str(path),
                            node_id=nid,
                        )
                    )
                seen_ids.add(nid)
                node_metadata[nid] = {"status": item.get("status", "")}
                deps_list = item.get("dependencies", [])
                nodes[nid] = [str(x) for x in deps_list] if isinstance(deps_list, list) else []
        else:
            finding = DagFinding(
                code=ERR_DAG_CORRUPT_FILE,
                severity="error",
                message="JSON root must be an object or array",
                source=str(path),
            )
            return False, [finding], {
                "status": "fail",
                "node_count": 0,
                "edge_count": 0,
                "error_count": 1,
                "warning_count": 0,
            }

    is_valid, findings, summary = validate_generic_graph(
        nodes, node_metadata=node_metadata, source=str(path)
    )
    all_findings = duplicate_findings + findings
    err_count = sum(1 for f in all_findings if f.severity == "error")
    warn_count = sum(1 for f in all_findings if f.severity == "warning")
    summary["error_count"] = err_count
    summary["warning_count"] = warn_count
    summary["status"] = "pass" if err_count == 0 else "fail"
    return err_count == 0, all_findings, summary


def validate_all(repo_root: Path) -> tuple[bool, list[DagFinding], dict[str, Any]]:
    """Runs all repository dependency DAG checks (beads issues + crate topology)."""
    all_findings: list[DagFinding] = []
    
    # 1. Beads issues DAG
    beads_valid, beads_findings, beads_summary = validate_beads_dag(repo_root)
    all_findings.extend(beads_findings)
    
    # 2. Crate topology DAG
    topo_valid, topo_findings, topo_summary = validate_crate_topology_dag(repo_root)
    all_findings.extend(topo_findings)

    err_count = sum(1 for f in all_findings if f.severity == "error")
    warn_count = sum(1 for f in all_findings if f.severity == "warning")
    is_valid = err_count == 0

    summary = {
        "schema": REPORT_SCHEMA,
        "status": "pass" if is_valid else "fail",
        "error_count": err_count,
        "warning_count": warn_count,
        "beads_summary": beads_summary,
        "crate_topology_summary": topo_summary,
    }
    return is_valid, all_findings, summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deterministic dependency DAG checker for Franken Surveillance System"
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=ROOT,
        help="Path to repository root (defaults to %(default)s)",
    )
    parser.add_argument(
        "--file",
        type=Path,
        default=None,
        help="Validate a specific DAG file (JSON or JSONL)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output structured JSON report conforming to fss.dependency_dag_report.v1",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as errors",
    )
    args = parser.parse_args()

    if args.file:
        is_valid, findings, summary = validate_dag_file(args.file)
        full_summary = {
            "schema": REPORT_SCHEMA,
            "status": summary["status"],
            "error_count": summary["error_count"],
            "warning_count": summary["warning_count"],
            "findings": [asdict(f) for f in findings],
            "summary": summary,
        }
    else:
        is_valid, findings, summary = validate_all(args.repo_root)
        full_summary = {
            "schema": REPORT_SCHEMA,
            "status": summary["status"],
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
            print(f"[PASS] Dependency DAG checks passed: 0 errors ({len(findings)} findings).")
        else:
            print(f"[FAIL] Dependency DAG checks failed with {full_summary['error_count']} error(s):")
            for f in findings:
                if f.severity == "error" or (args.strict and f.severity == "warning"):
                    print(f"  - [{f.code}] {f.source}: {f.message}")

    return 0 if is_valid else 1


if __name__ == "__main__":
    sys.exit(main())
