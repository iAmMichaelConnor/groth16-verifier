"""Focused discovery tests; fake executables never compile or prove."""

from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[5]
sys.path.insert(0, str(ROOT))
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from groth16.toolchain import (
    ToolchainError,
    inspect_source,
    load_pins,
    resolve_nargo,
)

PINS = load_pins(ROOT)
COMMIT = PINS["noir"]["gitlink"]
VERSION = f"nargo version = 1.0.0-rc.3\nnoirc version = 1.0.0-rc.3+{COMMIT}\n(git version hash: {COMMIT}, is dirty: false)"


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="groth16 toolchain ")
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.env = {"PATH": str(self.root)}

    def tool(self, name, version=VERSION):
        path = self.root / name
        path.write_text(f"#!{sys.executable}\nprint({version!r})\n")
        path.chmod(0o755)
        return path

    def test_selection_precedence_and_separate_binary_provenance(self):
        path = self.tool("nargo")
        env = self.tool("env nargo")
        cli = self.tool("cli nargo")
        config = {**self.env, "G16_NARGO": str(env)}
        explicit = resolve_nargo(cli, environ=config)
        self.assertEqual(explicit.executable, cli)
        self.assertEqual(explicit.selection, "argument")
        self.assertFalse(explicit.pinned_binary_match)
        self.assertEqual(resolve_nargo(environ=config).executable, env)
        self.assertEqual(resolve_nargo(environ=self.env).executable, path)

    def test_explicit_invalid_tool_never_falls_back(self):
        self.tool("nargo")
        for bad in [
            self.root / "missing",
            self.tool("wrong", VERSION.replace(COMMIT, "a" * 40)),
        ]:
            with self.subTest(bad=bad), self.assertRaises(ToolchainError):
                resolve_nargo(bad, environ=self.env, allow_historical=True)

    def test_dirty_same_version_and_conflicting_metadata_rejected(self):
        for bad in [
            VERSION.replace("dirty: false", "dirty: true"),
            VERSION.replace("nargo version = 1.0.0-rc.3", "nargo version = 1.0.0-rc.4"),
            "nargo version = 1.0.0-rc.3",
            VERSION.replace(
                f"git version hash: {COMMIT}", f"git version hash: {'a' * 40}"
            ),
        ]:
            with self.subTest(bad=bad), self.assertRaises(ToolchainError):
                resolve_nargo(self.tool("bad", bad), environ=self.env)

    def test_historical_path_requires_opt_in_and_cannot_override_path(self):
        historical = self.tool("recorded compiler")
        pins = json.loads(json.dumps(PINS))
        pins["noir"]["binary"] = str(historical)
        (self.root / "toolchain-v6.json").write_text(json.dumps(pins))
        with self.assertRaises(ToolchainError):
            resolve_nargo(environ=self.env, project_root=self.root)
        result = resolve_nargo(
            environ=self.env, project_root=self.root, allow_historical=True
        )
        self.assertEqual(result.executable, historical)
        self.assertEqual(result.selection, "historical-local-fallback")
        self.tool("nargo", "wrong compiler")
        with self.assertRaises(ToolchainError):
            resolve_nargo(
                environ=self.env, project_root=self.root, allow_historical=True
            )

    def test_missing_source_is_not_a_compatibility_match(self):
        self.assertEqual(
            inspect_source(self.root / "absent", COMMIT)["status"], "missing"
        )
        self.assertEqual(
            inspect_source(ROOT / "scripts", COMMIT)["status"], "unavailable"
        )

    def doctor(self, *args):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/groth16-doctor.py"), "--json", *args],
            cwd=self.root,
            env={
                **os.environ,
                "G16_NARGO": str(self.tool("fake nargo")),
                "G16_BB": str(self.tool("fake bb", "0.0.0")),
            },
            text=True,
            capture_output=True,
            timeout=30,
        )
        self.assertEqual(result.stderr, "")
        return result, json.loads(result.stdout)

    def test_external_doctor_reports_bb_without_attesting_compatibility(self):
        result, report = self.doctor()
        self.assertEqual(result.returncode, 0)
        self.assertTrue(report["ok"])
        self.assertEqual(report["checks"]["bb"]["compatibility"], "unverified")

    def test_explicit_missing_aztec_source_fails(self):
        result, report = self.doctor("--aztec-source", str(self.root / "absent"))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(report["checks"]["aztec_source"]["status"], "missing")


if __name__ == "__main__":
    unittest.main()
