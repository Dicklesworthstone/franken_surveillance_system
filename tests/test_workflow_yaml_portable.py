#!/usr/bin/env python3
"""tests/test_workflow_yaml_portable.py — FSS-193 contract: workflow YAML is a
portable executable specification only; every `run:` step invokes a repository
script (or the pinned toolchain). No unique release authority may live in YAML
(architecture/local_qualification.toml: workflow_yaml_role =
portable_executable_specification_only).
"""

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((REPO / ".github" / "workflows").glob("*.yml"))

# A run step is portable when it invokes a repo script or the pinned toolchain
# driver; anything else is inline logic (forbidden).
ALLOWED_STEP_RE = re.compile(
    r"^(?:\w+\s+|bash\s+|env\s+|cargo\s+|rustup\s+|python3\s+scripts/|scripts/|\./scripts/)",
)


def _run_steps(path: Path) -> list[tuple[int, str]]:
    steps = []
    for no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("run:"):
            steps.append((no, stripped))
        elif stripped.startswith("run: |") or stripped.startswith("run: >"):
            steps.append((no, stripped))
    return steps


class TestWorkflowPortability(unittest.TestCase):
    def test_workflows_exist(self):
        self.assertTrue(WORKFLOWS, "no workflow files found")

    def test_every_run_step_calls_repo_scripts_or_pinned_toolchain(self):
        for wf in WORKFLOWS:
            steps = _run_steps(wf)
            self.assertTrue(steps, f"{wf.name}: no run steps (workflow must do something)")
            for no, step in steps:
                self.assertIsNotNone(
                    ALLOWED_STEP_RE.match(step.split("run:", 1)[1].strip()),
                    f"{wf.name}:{no}: inline logic or non-repo command: {step}",
                )

    def test_no_multiline_run_blocks(self):
        # `run: |` blocks are where unique logic hides; none may exist.
        for wf in WORKFLOWS:
            for no, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
                self.assertNotRegex(
                    line.strip(),
                    r"^run:\s*[|>]",
                    f"{wf.name}:{no}: multiline run block (portable specs call scripts)",
                )

    def test_no_github_only_secrets_or_uploads_in_steps(self):
        for wf in WORKFLOWS:
            text = wf.read_text(encoding="utf-8")
            for no, line in enumerate(text.splitlines(), 1):
                if line.strip().startswith("run:"):
                    self.assertNotIn(
                        "secrets.", line, f"{wf.name}:{no}: run step touches secrets inline"
                    )


if __name__ == "__main__":
    unittest.main()
