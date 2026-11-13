#!/usr/bin/env python3
"""Create a disposable TLS research workspace without modifying the registry."""

import argparse
import ast
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import subprocess
import tarfile

EXPECTED = "48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf"
ROOT = Path(__file__).resolve().parent
COPY_FILES = (
    "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "snapshot_fixture.py", "trial_profile_fixture.py", "trial_auto_setup_fixture.py", "trial_live_media_probe.py", "trial_pin_discovery_fixture.py", "trial_media_fixture.py", "src/lib.rs",
    "src/server.rs", "src/owned.rs", "src/owned/client.rs", "src/owned/offload.rs", "src/client_handshake.rs",
    "src/camera_tls.rs", "src/camera_tls_owned.rs", "src/camera_tls_client.rs", "src/camera_setup.rs", "src/snapshot_auth.rs", "src/bin/live_tls_probe.rs", "src/bin/live_snapshot_probe.rs",
    "src/bin/unifi_scoped_direct_trial.rs", "src/bin/live_media_probe.rs", "src/bin/trial_checkpoint/mod.rs", "src/bin/trial_run_id/mod.rs", "src/bin/trial_setup_fence/mod.rs",
    "src/bin/trial_owned_archive/mod.rs", "src/bin/trial_owned_archive/video.rs", "src/bin/trial_owned_archive/still_export.rs",
    "src/fleet_transport.rs", "src/fleet_leased.rs", "src/prepared_setup.rs", "src/prepared_camera.rs", "src/camera_factory.rs", "src/setup_upgrade.rs",
    "tests/scoped_entropy.rs", "tests/owned_entropy.rs", "tests/client_scoped_entropy.rs",
    "tests/owned_client.rs", "tests/fleet_route.rs", "tests/pinned_client.rs", "tests/support/stream.rs", "tests/support/baseline.264", "tests/support/synthetic_g4_resolution.264",
)


def validate_copy_manifest(root, files):
    """Check local Rust and Python dependencies before creating a workspace."""
    if len(set(files)) != len(files):
        raise ValueError("duplicate workspace source")
    missing = [path for path in files if not (root / path).is_file()]
    if missing:
        raise ValueError("workspace source missing: " + ", ".join(missing))
    manifest = set(files)
    for source in files:
        if source.endswith(".py"):
            path = PurePosixPath(source)
            tree = ast.parse((root / source).read_text(), filename=source)
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    names = (node.module.split(".", 1)[0],)
                elif isinstance(node, ast.Import):
                    names = tuple(alias.name.split(".", 1)[0] for alias in node.names)
                else:
                    continue
                for name in names:
                    local = path.parent / (name + ".py")
                    if (root / local).is_file() and str(local) not in manifest:
                        raise ValueError("workspace Python import omitted in " + source + ": " + name)
            continue
        if not source.endswith(".rs"):
            continue
        path = PurePosixPath(source)
        lines = (root / source).read_text().splitlines()
        for index, line in enumerate(lines):
            module = re.fullmatch(r"\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;\s*", line)
            if module:
                attributes = []
                for previous in reversed(lines[:index]):
                    if not previous.strip() or previous.lstrip().startswith("#["):
                        attributes.append(previous)
                    else:
                        break
                explicit = [value for attr in attributes
                            for value in re.findall(r'#\[path\s*=\s*"([^"\n]+)"\]', attr)]
                if len(explicit) > 1:
                    raise ValueError("multiple module paths in " + source)
                if explicit:
                    options = [posixpath.normpath(str(path.parent / explicit[0]))]
                else:
                    directory = path.parent if path.name in ("lib.rs", "main.rs", "mod.rs") else path.with_suffix("")
                    options = [str(directory / (module.group(1) + ".rs")),
                               str(directory / module.group(1) / "mod.rs")]
                if not any(option in manifest for option in options):
                    raise ValueError("workspace module omitted in " + source + ": " + module.group(1))
            for include in re.findall(r'include_(?:bytes|str)!\s*\(\s*"([^"\n]+)"\s*\)', line):
                included = posixpath.normpath(str(path.parent / include))
                if included not in manifest:
                    raise ValueError("workspace include omitted in " + source + ": " + included)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("workspace", type=Path, help="new absolute directory")
    parser.add_argument("crate", type=Path, help="cached rustls-0.23.46.crate")
    args = parser.parse_args()
    if not args.workspace.is_absolute() or args.workspace.exists():
        raise ValueError("workspace must be a new absolute path")
    project = ROOT.parent.parent
    parent = args.workspace.parent.resolve()
    if parent == project or project in parent.parents:
        raise ValueError("workspace must be outside the project checkout")
    validate_copy_manifest(ROOT, COPY_FILES)
    with args.crate.open("rb") as source:
        data = source.read(4_000_001)
    if len(data) > 4_000_000 or hashlib.sha256(data).hexdigest() != EXPECTED:
        raise ValueError("unexpected upstream crate digest")
    os.umask(0o077)
    args.workspace.mkdir(mode=0o700)
    vendor = args.workspace / "vendor" / "rustls"
    vendor.mkdir(parents=True, mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) > 500:
            raise ValueError("unexpected archive size")
        for member in members:
            parts = PurePosixPath(member.name).parts
            if (not parts or parts[0] != "rustls-0.23.46" or
                    any(part in ("..", ".") for part in parts) or
                    not (member.isfile() or member.isdir())):
                raise ValueError("unexpected archive entry")
            if len(parts) == 1:
                continue
            destination = vendor.joinpath(*parts[1:])
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            content = archive.extractfile(member)
            if content is None or member.size > 4_000_000:
                raise ValueError("unexpected archive member")
            with destination.open("xb") as output:
                shutil.copyfileobj(content, output)
    for rel in COPY_FILES:
        destination = args.workspace / rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        content = (ROOT / rel).read_bytes()
        if rel == "Cargo.toml":
            manifest = content.decode("utf-8")
            for name in ("fss-core", "fss-geometry", "fss-codec-mjpeg", "fss-codec-h264", "fss-codec-jpeg-encode", "fss-container", "fss-packet", "fss-runtime", "fss-reference", "fss-object"):
                original = f'"../../crates/{name}"'
                if manifest.count(original) != 1:
                    raise ValueError("unexpected FSS dependency path")
                relative = os.path.relpath(project / "crates" / name, args.workspace)
                manifest = manifest.replace(original, json.dumps(relative))
            content = manifest.encode("utf-8")
        with destination.open("xb") as output:
            output.write(content)
    for patch in ("rustls-0.23.46-scoped-server.patch", "rustls-0.23.46-scoped-client.patch"):
        subprocess.run(["git", "apply", str(ROOT / patch)], cwd=args.workspace, check=True)
    fixtures = args.workspace / "tests" / "fixtures"
    fixtures.mkdir(mode=0o700)
    (fixtures / "leaf-ext.cnf").write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
    def run(*arguments):
        subprocess.run(["openssl", *map(str, arguments)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
        "-keyout", fixtures / "ca-key.pem", "-out", fixtures / "ca.pem", "-days", "2",
        "-subj", "/CN=FSS Test CA", "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    run("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
        "-keyout", fixtures / "key.pem", "-out", fixtures / "leaf.csr", "-subj", "/CN=localhost")
    run("x509", "-req", "-in", fixtures / "leaf.csr", "-CA", fixtures / "ca.pem",
        "-CAkey", fixtures / "ca-key.pem", "-CAcreateserial", "-days", "2", "-extfile",
        fixtures / "leaf-ext.cnf", "-out", fixtures / "cert.pem")
    run("x509", "-in", fixtures / "cert.pem", "-outform", "DER", "-out", fixtures / "cert.der")
    run("x509", "-in", fixtures / "ca.pem", "-outform", "DER", "-out", fixtures / "ca.der")
    run("pkcs8", "-topk8", "-nocrypt", "-in", fixtures / "key.pem", "-outform", "DER",
        "-out", fixtures / "key.der")
    print("Prepared a disposable research workspace:", args.workspace)


if __name__ == "__main__":
    main()
