#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
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

    @property
    def target_base(self) -> str:
        return f"fss-{self.target}"

    @property
    def source_base(self) -> str:
        return "fss-source"

    @property
    def common_asset_authority(self) -> bool:
        return self.target == "x86_64-unknown-linux-gnu"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iso8601_utc(epoch: int) -> str:
    return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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
    rows = [f"{sha256(path)}  {path.relative_to(relative_to).as_posix()}" for path in sorted(paths)]
    output.write_text("\n".join(rows) + "\n", encoding="utf-8")


def write_single_checksum(path: Path) -> Path:
    output = Path(f"{path}.sha256")
    output.write_text(f"{sha256(path)}  {path.name}\n", encoding="utf-8")
    return output


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
    info.mode = 0o755 if source.stat().st_mode & stat.S_IXUSR else 0o644
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
            info.external_attr = (0o100755 if executable else 0o100644) << 16
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


def load_metadata(metadata_path: Path) -> dict[str, Any]:
    value = json.loads(metadata_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("packages"), list):
        raise ValueError(f"invalid Cargo metadata document: {metadata_path}")
    return value


def package_rows(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted(metadata["packages"], key=lambda row: (row.get("name", ""), row.get("version", ""), row.get("id", "")))


def cargo_sbom(metadata: dict[str, Any], ctx: Context) -> dict[str, Any]:
    packages = []
    for index, package in enumerate(package_rows(metadata), start=1):
        external_refs = []
        if package.get("source"):
            external_refs.append(
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": f"pkg:cargo/{package['name']}@{package['version']}",
                }
            )
        safe_name = package["name"].replace("_", "-").replace(".", "-")
        safe_version = package["version"].replace("+", "-").replace(".", "-")
        packages.append(
            {
                "SPDXID": f"SPDXRef-Package-{index}-{safe_name}-{safe_version}",
                "name": package.get("name"),
                "versionInfo": package.get("version"),
                "downloadLocation": package.get("source") or "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": package.get("license") or "NOASSERTION",
                "licenseDeclared": package.get("license") or "NOASSERTION",
                "externalRefs": external_refs,
            }
        )
    metadata_digest = hashlib.sha256(json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    namespace_seed = f"{ctx.version}:{ctx.target}:{metadata_digest}".encode()
    namespace = hashlib.sha256(namespace_seed).hexdigest()
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"franken-surveillance-system-{ctx.version}-{ctx.target}",
        "documentNamespace": f"https://github.com/Dicklesworthstone/franken_surveillance_system/spdx/{namespace}",
        "creationInfo": {
            "created": iso8601_utc(ctx.source_date_epoch),
            "creators": ["Tool: fss-release-artifacts-v2"],
        },
        "packages": packages,
    }


def license_inventory(metadata: dict[str, Any], ctx: Context) -> dict[str, Any]:
    return {
        "schema": "fss.license_inventory.v1",
        "version": ctx.version,
        "target": ctx.target,
        "packages": [
            {
                "packageId": package.get("id"),
                "name": package.get("name"),
                "version": package.get("version"),
                "source": package.get("source") or "workspace",
                "license": package.get("license") or "NOASSERTION",
                "licenseFile": package.get("license_file"),
            }
            for package in package_rows(metadata)
        ],
    }


def source_manifest(ctx: Context, files: list[Path], source_commit: str) -> dict[str, Any]:
    return {
        "schema": "fss.source_manifest.v1",
        "version": ctx.version,
        "sourceCommit": source_commit,
        "sourceDateEpoch": ctx.source_date_epoch,
        "fileCount": len(files),
        "files": [
            {
                "path": path.relative_to(ROOT).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": sha256(path),
                "executable": bool(path.stat().st_mode & stat.S_IXUSR),
            }
            for path in files
        ],
    }


def slsa_provenance(
    ctx: Context,
    primary: Path,
    build_receipt: Path,
    metadata_path: Path,
    source_manifest_path: Path | None,
    source_commit: str,
) -> dict[str, Any]:
    invocation_seed = "\0".join(
        [ctx.version, ctx.target, source_commit, sha256(primary), sha256(build_receipt), sha256(metadata_path)]
    ).encode()
    invocation_id = hashlib.sha256(invocation_seed).hexdigest()
    resolved_dependencies = [
        {"uri": "git+https://github.com/Dicklesworthstone/franken_surveillance_system", "digest": {"gitCommit": source_commit}},
        {"uri": "file:Cargo.lock", "digest": {"sha256": sha256(ROOT / "Cargo.lock")}},
        {"uri": "file:MANIFEST.sha256", "digest": {"sha256": sha256(ROOT / "MANIFEST.sha256")}},
        {"uri": metadata_path.name, "digest": {"sha256": sha256(metadata_path)}},
    ]
    if source_manifest_path is not None:
        resolved_dependencies.append(
            {"uri": source_manifest_path.name, "digest": {"sha256": sha256(source_manifest_path)}}
        )
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": primary.name, "digest": {"sha256": sha256(primary)}}],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/Dicklesworthstone/franken_surveillance_system/buildtypes/dsr-native-v1",
                "externalParameters": {"version": ctx.version, "target": ctx.target},
                "internalParameters": {
                    "sourceDateEpoch": ctx.source_date_epoch,
                    "lockedOffline": True,
                    "nativeTargetRequired": True,
                },
                "resolvedDependencies": resolved_dependencies,
            },
            "runDetails": {
                "builder": {"id": "https://github.com/Dicklesworthstone/doodlestein_self_releaser"},
                "metadata": {
                    "invocationId": invocation_id,
                    "startedOn": iso8601_utc(ctx.source_date_epoch),
                    "finishedOn": iso8601_utc(ctx.source_date_epoch),
                },
                "byproducts": [
                    {"name": build_receipt.name, "digest": {"sha256": sha256(build_receipt)}},
                    *([] if source_manifest_path is None else [
                        {"name": source_manifest_path.name, "digest": {"sha256": sha256(source_manifest_path)}}
                    ]),
                ],
            },
        },
    }


def copy_receipt(source: Path, destination: Path) -> Path:
    if not source.is_file():
        raise ValueError(f"required receipt missing: {source}")
    destination.write_bytes(source.read_bytes())
    return destination


def artifact_row(path: Path) -> dict[str, Any]:
    return {"name": path.name, "bytes": path.stat().st_size, "sha256": sha256(path)}


def package(ctx: Context, metadata_path: Path, source_commit: str) -> None:
    verification = verify_stage(ctx)
    metadata = load_metadata(metadata_path)
    stage_files = [(path, path.relative_to(ctx.stage).as_posix()) for path in normalized_files(ctx.stage)]

    if "windows" in ctx.target:
        primary = ctx.artifacts / f"{ctx.target_base}.zip"
        deterministic_zip(stage_files, primary)
    else:
        primary = ctx.artifacts / f"{ctx.target_base}.tar.xz"
        deterministic_tar_xz(stage_files, primary, ctx.source_date_epoch)
    primary_checksum = write_single_checksum(primary)

    common_support: list[Path] = []
    source_manifest_path: Path | None = None
    if ctx.common_asset_authority:
        tracked_files = git_files()
        source_archive = ctx.artifacts / f"{ctx.source_base}.tar.xz"
        deterministic_tar_xz(
            [(path, path.relative_to(ROOT).as_posix()) for path in tracked_files],
            source_archive,
            ctx.source_date_epoch,
        )
        source_checksum = write_single_checksum(source_archive)
        source_manifest_path = ctx.artifacts / f"{ctx.source_base}.manifest.json"
        write_json(source_manifest_path, source_manifest(ctx, tracked_files, source_commit))
        common_support.extend([source_archive, source_checksum, source_manifest_path])

    sbom_path = ctx.artifacts / f"{ctx.target_base}.sbom.spdx.json"
    write_json(sbom_path, cargo_sbom(metadata, ctx))
    license_path = ctx.artifacts / f"{ctx.target_base}.license-inventory.json"
    write_json(license_path, license_inventory(metadata, ctx))

    build_source = ctx.receipts / "build.json"
    build_asset = copy_receipt(build_source, ctx.artifacts / f"{ctx.target_base}.build.json")
    verification_asset = copy_receipt(
        ctx.receipts / "verification.json", ctx.artifacts / f"{ctx.target_base}.verification.json"
    )
    stage_sums_asset = copy_receipt(
        ctx.receipts / "STAGE_SHA256SUMS.txt", ctx.artifacts / f"{ctx.target_base}.stage-sha256.txt"
    )

    provenance_path = ctx.artifacts / f"{ctx.target_base}.provenance.intoto.json"
    write_json(
        provenance_path,
        slsa_provenance(ctx, primary, build_source, metadata_path, source_manifest_path, source_commit),
    )

    support_paths = [
        primary_checksum,
        sbom_path,
        license_path,
        provenance_path,
        build_asset,
        verification_asset,
        stage_sums_asset,
        *common_support,
    ]
    qualification_path = ctx.artifacts / f"{ctx.target_base}.qualification.json"
    qualification = {
        "schema": "fss.qualification_root.v2",
        "version": ctx.version,
        "target": ctx.target,
        "sourceCommit": source_commit,
        "sourceDateEpoch": ctx.source_date_epoch,
        "primaryArtifact": artifact_row(primary),
        "supportArtifacts": [artifact_row(path) for path in support_paths],
        "stageFileCount": verification["fileCount"],
        "commonAssetAuthority": ctx.common_asset_authority,
        "claimBoundary": "implementation-status-design-skeleton",
        "signatureState": "unsigned-awaiting-separated-dsr-signing-authority",
    }
    write_json(qualification_path, qualification)

    target_checksums = ctx.artifacts / f"{ctx.target_base}.sha256sums.txt"
    checksum_targets = [path for path in normalized_files(ctx.artifacts) if path != target_checksums]
    write_checksum_file(checksum_targets, target_checksums, ctx.artifacts)
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
