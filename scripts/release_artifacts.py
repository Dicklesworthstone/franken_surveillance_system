#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import os
import stat
import subprocess
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
FIXED_ZIP_DATE = (1980, 1, 1, 0, 0, 0)


@dataclass(frozen=True)
class Context:
    version: str
    target: str
    stage: Path
    artifacts: Path
    receipts: Path
    source_date_epoch: int


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalized_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"symlink is forbidden in release input: {path}")
        if path.is_file():
            files.append(path)
    return files


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_checksum_file(paths: Iterable[Path], output: Path, relative_to: Path) -> None:
    rows = []
    for path in sorted(paths):
        rows.append(f"{sha256(path)}  {path.relative_to(relative_to).as_posix()}")
    output.write_text("\n".join(rows) + "\n", encoding="utf-8")


def verify_stage(ctx: Context) -> dict[str, Any]:
    files = normalized_files(ctx.stage)
    if not files:
        raise ValueError(f"release stage is empty: {ctx.stage}")
    inventory = [
        {
            "path": path.relative_to(ctx.stage).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": sha256(path),
            "executable": bool(path.stat().st_mode & stat.S_IXUSR),
        }
        for path in files
    ]
    receipt = {
        "schema": "fss.release_stage_verification.v1",
        "version": ctx.version,
        "target": ctx.target,
        "sourceDateEpoch": ctx.source_date_epoch,
        "fileCount": len(inventory),
        "files": inventory,
    }
    write_json(ctx.receipts / "verification.json", receipt)
    write_checksum_file(files, ctx.receipts / "STAGE_SHA256SUMS.txt", ctx.stage)
    return receipt


def add_tar_file(archive: tarfile.TarFile, source: Path, name: str, epoch: int) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = source.stat().st_size
    executable = bool(source.stat().st_mode & stat.S_IXUSR)
    info.mode = 0o755 if executable else 0o644
    info.mtime = epoch
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    with source.open("rb") as handle:
        archive.addfile(info, handle)


def deterministic_tar_xz(files: Iterable[tuple[Path, str]], output: Path, epoch: int) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with lzma.open(output, "wb", preset=9) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for source, name in sorted(files, key=lambda item: item[1]):
                add_tar_file(archive, source, name, epoch)


def deterministic_zip(files: Iterable[tuple[Path, str]], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for source, name in sorted(files, key=lambda item: item[1]):
            info = zipfile.ZipInfo(name, FIXED_ZIP_DATE)
            executable = bool(source.stat().st_mode & stat.S_IXUSR)
            info.external_attr = ((0o100755 if executable else 0o100644) << 16)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            archive.writestr(info, source.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def git_files() -> list[Path]:
    proc = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    result: list[Path] = []
    for raw in proc.stdout.split(b"\0"):
        if not raw:
            continue
        relative = Path(os.fsdecode(raw))
        path = ROOT / relative
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"tracked source is absent, non-file, or symlinked: {relative}")
        result.append(path)
    return sorted(result)


def cargo_sbom(metadata_path: Path, ctx: Context) -> dict[str, Any]:
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    packages = []
    for package in sorted(metadata.get("packages", []), key=lambda row: (row.get("name", ""), row.get("version", ""))):
        external_refs = []
        if package.get("source"):
            external_refs.append(
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": f"pkg:cargo/{package['name']}@{package['version']}",
                }
            )
        packages.append(
            {
                "SPDXID": f"SPDXRef-Package-{package['name'].replace('_', '-').replace('.', '-')}",
                "name": package.get("name"),
                "versionInfo": package.get("version"),
                "downloadLocation": package.get("source") or "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": package.get("license") or "NOASSERTION",
                "licenseDeclared": package.get("license") or "NOASSERTION",
                "externalRefs": external_refs,
            }
        )
    namespace_seed = f"{ctx.version}:{ctx.target}:{metadata_path.read_bytes()!r}".encode()
    namespace = hashlib.sha256(namespace_seed).hexdigest()
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"franken-surveillance-system-{ctx.version}-{ctx.target}",
        "documentNamespace": f"https://github.com/Dicklesworthstone/franken_surveillance_system/spdx/{namespace}",
        "creationInfo": {"created": "1970-01-01T00:00:00Z", "creators": ["Tool: fss-release-artifacts-v1"]},
        "packages": packages,
    }


def package(ctx: Context, metadata_path: Path, source_commit: str) -> None:
    verification = verify_stage(ctx)
    stage_files = [(path, path.relative_to(ctx.stage).as_posix()) for path in normalized_files(ctx.stage)]
    primary_base = f"fss-{ctx.version}-{ctx.target}"
    if "windows" in ctx.target:
        primary = ctx.artifacts / f"{primary_base}.zip"
        deterministic_zip(stage_files, primary)
    else:
        primary = ctx.artifacts / f"{primary_base}.tar.xz"
        deterministic_tar_xz(stage_files, primary, ctx.source_date_epoch)

    source_archive = ctx.artifacts / "fss-source.tar.xz"
    source_files = [(path, path.relative_to(ROOT).as_posix()) for path in git_files()]
    deterministic_tar_xz(source_files, source_archive, ctx.source_date_epoch)

    sbom_path = ctx.artifacts / "fss-sbom.spdx.json"
    write_json(sbom_path, cargo_sbom(metadata_path, ctx))

    build_receipt_path = ctx.receipts / "build.json"
    if not build_receipt_path.is_file():
        raise ValueError(f"build receipt missing: {build_receipt_path}")
    support = [primary, source_archive, sbom_path]
    qualification = {
        "schema": "fss.qualification_root.v1",
        "version": ctx.version,
        "target": ctx.target,
        "sourceCommit": source_commit,
        "sourceDateEpoch": ctx.source_date_epoch,
        "buildReceipt": {"path": build_receipt_path.name, "sha256": sha256(build_receipt_path)},
        "stageVerification": {"path": "verification.json", "sha256": sha256(ctx.receipts / "verification.json")},
        "primaryArtifact": {"name": primary.name, "bytes": primary.stat().st_size, "sha256": sha256(primary)},
        "supportArtifacts": [
            {"name": path.name, "bytes": path.stat().st_size, "sha256": sha256(path)} for path in support[1:]
        ],
        "stageFileCount": verification["fileCount"],
        "claimBoundary": "implementation-status-design-skeleton",
    }
    qualification_path = ctx.artifacts / "fss-qualification-root.json"
    write_json(qualification_path, qualification)

    # Copy the receipts needed to independently recompute the qualification root.
    for name in ("build.json", "verification.json", "STAGE_SHA256SUMS.txt"):
        source = ctx.receipts / name
        destination = ctx.artifacts / name
        destination.write_bytes(source.read_bytes())

    checksum_targets = [path for path in normalized_files(ctx.artifacts) if path.name != "SHA256SUMS.txt"]
    write_checksum_file(checksum_targets, ctx.artifacts / "SHA256SUMS.txt", ctx.artifacts)
    write_checksum_file(normalized_files(ctx.artifacts), ctx.receipts / "ARTIFACT_SHA256SUMS.txt", ctx.artifacts)


def parse_context(args: argparse.Namespace) -> Context:
    return Context(
        version=args.version,
        target=args.target,
        stage=args.stage.resolve(),
        artifacts=args.artifacts.resolve(),
        receipts=args.receipts.resolve(),
        source_date_epoch=args.source_date_epoch,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Create deterministic FSS release verification and archives")
    parser.add_argument("command", choices=("verify", "package"))
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--stage", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    parser.add_argument("--source-date-epoch", type=int, default=0)
    parser.add_argument("--metadata", type=Path)
    parser.add_argument("--source-commit")
    args = parser.parse_args()
    ctx = parse_context(args)
    ctx.artifacts.mkdir(parents=True, exist_ok=True)
    ctx.receipts.mkdir(parents=True, exist_ok=True)
    if args.command == "verify":
        verify_stage(ctx)
        return 0
    if args.metadata is None or args.source_commit is None:
        parser.error("package requires --metadata and --source-commit")
    package(ctx, args.metadata.resolve(), args.source_commit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
