#!/usr/bin/env python3
"""Strict UniFi bindings and site-policy JSON Schema contracts.

Bindings are complete input instances. Site policy tests isolate the published
conditional applicators so every combination of direct, JPEG and UniFi sources is
checked independently of codec-budget fixtures. Full emitted native/site plans
continue to belong to the Rust planner contracts; these tests make no runtime or
device qualification claim.
"""
from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DIGEST = "sha256:" + "1" * 64
DIRECT_POLICY = (
    "site-capture-plan:v1:manifest-and-probe-pinned:all-sources-or-none:"
    "existing-native-avc-hevc-planner:exact-ssrc-and-cadence:no-executor:no-rights-grant"
)
JPEG_POLICY = (
    "site-capture-plan:v1:manifest-and-probe-pinned:all-sources-or-none:"
    "existing-native-avc-hevc-jpeg-planners:exact-ssrc:receipt-bound-cadence:"
    "receipt-bound-jpeg-retention:reserved-journal-parent-bound:no-executor:no-rights-grant"
)
UNIFI_POLICY = (
    "site-capture-plan:v1:manifest-and-probe-pinned:all-sources-or-none:"
    "existing-native-avc-hevc-jpeg-and-unifi-planners:private-export-fingerprint-and-camera-bound:"
    "exact-selected-view-and-route:no-url-rewrite:no-quality-fallback:no-tls-downgrade:"
    "exact-ssrc:receipt-bound-cadence:receipt-bound-jpeg-retention:reserved-journal-parent-bound:"
    "no-executor:no-rights-grant"
)


def binding(source_id: str = "front-door") -> dict[str, Any]:
    return {
        "source_id": source_id,
        "source_file": "/private/protect-export.json",
        "source_digest": DIGEST,
        "quality": "high",
        "stream_transport": "operator-rtsp",
    }


def bindings() -> dict[str, Any]:
    return {
        "schema": "fss.site_unifi_bindings.v1",
        "manifest_digest": DIGEST,
        "sources": [binding()],
    }


class SiteUnifiSchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest("jsonschema Draft 2020-12 oracle unavailable")
        self.validator_type = Draft202012Validator
        self.bindings_schema = json.loads(
            (ROOT / "schemas" / "site_unifi_bindings.v1.json").read_text(encoding="utf-8")
        )
        self.plan_schema = json.loads(
            (ROOT / "schemas" / "site_capture_plan.v1.json").read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(self.bindings_schema)
        Draft202012Validator.check_schema(self.plan_schema)
        self.bindings_validator = Draft202012Validator(self.bindings_schema)

    def assert_binding_valid(self, document: Any) -> None:
        self.assertEqual(list(self.bindings_validator.iter_errors(document)), [])

    def assert_binding_refused(self, document: Any) -> None:
        self.assertNotEqual(list(self.bindings_validator.iter_errors(document)), [])

    def test_exact_complete_binding_choices_and_bounds(self) -> None:
        for quality in ("high", "medium", "low", "package"):
            for transport in ("published", "operator-rtsp"):
                document = bindings()
                document["sources"][0].update(quality=quality, stream_transport=transport)
                self.assert_binding_valid(document)
        for count in (0, 64):
            document = bindings()
            document["sources"] = [binding(f"camera-{index}") for index in range(count)]
            self.assert_binding_valid(document)
        document = bindings()
        document["sources"] = [binding(f"camera-{index}") for index in range(65)]
        self.assert_binding_refused(document)
        duplicate = bindings()
        duplicate["sources"].append(copy.deepcopy(duplicate["sources"][0]))
        self.assert_binding_refused(duplicate)

    def test_unknown_route_secret_and_authority_fields_are_refused(self) -> None:
        for key in ("api_key", "token", "peer", "authority", "presentation", "approval"):
            for in_row in (False, True):
                with self.subTest(key=key, in_row=in_row):
                    document = bindings()
                    target = document["sources"][0] if in_row else document
                    target[key] = "PRIVATE_CANARY"
                    self.assert_binding_refused(document)
        for key in ("source_id", "source_file", "source_digest", "quality", "stream_transport"):
            document = bindings()
            del document["sources"][0][key]
            self.assert_binding_refused(document)

    def test_no_default_quality_transport_digest_or_source_identity(self) -> None:
        for key, values in {
            "source_id": ("", "-camera", "camera with spaces", "camera\n", "x" * 129),
            "quality": ("auto", "main", "jpeg", ""),
            "stream_transport": ("auto", "rtsp", "rtsps", ""),
            "source_digest": (
                "sha256:" + "0" * 64,
                "sha256:" + "A" * 64,
                "blake3:" + "1" * 64,
                "sha256:" + "1" * 63,
                "sha256:" + "1" * 64 + "\n",
            ),
        }.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    document = bindings()
                    document["sources"][0][key] = value
                    self.assert_binding_refused(document)
        document = bindings()
        document["manifest_digest"] = "sha256:" + "0" * 64
        self.assert_binding_refused(document)

    def test_private_export_paths_reject_traversal_and_controls(self) -> None:
        for path in (
            "relative.json", "/", "///", "/../export.json", "/./export.json",
            "/private/../export.json", "/private/./export.json", "/private/..",
            "/private/export\n.json", "/private/export\x7f.json", "/private/export\x85.json",
            "/private/export.json\n",
            "/" + "x" * 4096,
        ):
            with self.subTest(path=repr(path)):
                document = bindings()
                document["sources"][0]["source_file"] = path
                self.assert_binding_refused(document)
        # The pure path shape does not canonicalize; the real private-file owner
        # separately refuses aliases. Literal dots inside names are ordinary data.
        for path in ("/private/protect..json", "/private//protect.json"):
            document = bindings()
            document["sources"][0]["source_file"] = path
            self.assert_binding_valid(document)

    def test_site_policy_and_reserved_parent_follow_exact_source_combinations(self) -> None:
        gate = self.validator_type({"allOf": self.plan_schema["allOf"]})
        direct = {"kind": "rtsp", "native_plan": {"schema": "fss.rtsp_capture_cli.v1"}}
        jpeg = {"kind": "nvr_channel", "native_plan": {"schema": "fss.rtsp_jpeg_capture_cli.v1"}}
        unifi = {"kind": "unifi_protect", "native_plan": {"schema": "fss.rtsp_from_unifi_plan.v1"}}
        for sources, policy, has_jpeg in (
            ([direct], DIRECT_POLICY, False),
            ([jpeg], JPEG_POLICY, True),
            ([direct, jpeg], JPEG_POLICY, True),
            ([unifi], UNIFI_POLICY, False),
            ([direct, unifi], UNIFI_POLICY, False),
            ([jpeg, unifi], UNIFI_POLICY, True),
            ([direct, jpeg, unifi], UNIFI_POLICY, True),
        ):
            document: dict[str, Any] = {"sources": sources, "policy": policy}
            if has_jpeg:
                document["reserved_pins_root"] = "/independent/pins"
            self.assertEqual(list(gate.iter_errors(document)), [])
            for wrong in {DIRECT_POLICY, JPEG_POLICY, UNIFI_POLICY} - {policy}:
                self.assertNotEqual(list(gate.iter_errors({**document, "policy": wrong})), [])
            changed = copy.deepcopy(document)
            if has_jpeg:
                del changed["reserved_pins_root"]
            else:
                changed["reserved_pins_root"] = "/unexpected/pins"
            self.assertNotEqual(list(gate.iter_errors(changed)), [])

    def test_private_native_preview_requires_both_redactions_and_digest_coordinates(self) -> None:
        gate = self.validator_type(
            self.plan_schema["$defs"]["private_unifi_capture"]["allOf"][1]
        )
        document = {
            "presentation_uri": "[redacted]",
            "control_root_uri": "[redacted]",
            "presentation_uri_digest": DIGEST,
            "control_root_uri_digest": DIGEST,
        }
        self.assertEqual(list(gate.iter_errors(document)), [])
        for field in ("presentation_uri", "control_root_uri"):
            changed = {**document, field: "rtsp://192.0.2.7/PRIVATE_STREAM_CANARY"}
            self.assertNotEqual(list(gate.iter_errors(changed)), [])
        for field in ("presentation_uri_digest", "control_root_uri_digest"):
            changed = copy.deepcopy(document)
            del changed[field]
            self.assertNotEqual(list(gate.iter_errors(changed)), [])


if __name__ == "__main__":
    unittest.main()
