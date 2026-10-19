"""Tests for keymap. All key values below are FAKE fixtures."""

import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from keymap.cli import main
from keymap.report import render_human, render_json
from keymap.scan import scan, scan_paths

OPENAI_FAKE = "sk-proj-K7Q9X2M4P8R3T6W1Y5A0B9C2D7E4F6"
ANTHROPIC_FAKE = "sk-ant-api03-M3N8V2K5J9H4G7F1D6S0A3Q8W2E5R7T1"
GITHUB_FAKE = "ghp_M3N8V2K5J9H4G7F1D6S0A3Q8W2E5R7T1X9Y4"


class TestKeymap(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.home = self.tmp / "home"
        self.home.mkdir()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, rel, content, mode=None):
        path = self.home / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        if mode is not None:
            os.chmod(path, mode)
        return path

    def test_detects_known_providers(self):
        self._write(".env", f"OPENAI_API_KEY={OPENAI_FAKE}\n", mode=0o600)
        self._write(".codex/config.toml",
                     f'api_key = "{ANTHROPIC_FAKE}"\n', mode=0o600)
        result = scan(self.home)
        providers = {o.provider for o in result.occurrences}
        self.assertEqual(providers, {"openai", "anthropic"})
        self.assertEqual(len(result.occurrences), 2)

    def test_stripe_pattern(self):
        # Value assembled in parts so this file never contains a literal
        # live-secret-key string (push protection would flag it).
        stripe = "sk_" + "live_" + "K7Q9X2M4P8R3T6W1Y5A0B9C2D7E4F6"
        self._write(".config/billing.json",
                    '{"stripe_key": "%s"}\n' % stripe, mode=0o600)
        result = scan(self.home)
        self.assertEqual(len(result.occurrences), 1)
        self.assertEqual(result.occurrences[0].provider, "stripe")

    def test_stripe_pattern_detected(self):
        # The Stripe value is built from parts so this test file itself
        # never contains a contiguous live-key-looking literal.
        value = "sk_" + "live_" + "K7Q9X2M4P8R3T6W1Y5A0B9C2D7E4F6"
        self._write(".config/billing.json",
                    '{"stripe_key": "%s"}\n' % value, mode=0o600)
        result = scan(self.home)
        self.assertEqual(len(result.occurrences), 1)
        self.assertEqual(result.occurrences[0].provider, "stripe")

    def test_consecutive_lines_same_column_both_detected(self):
        # Regression: span bookkeeping is per-line, so a key on line N+1
        # at the same column as a key on line N must not be suppressed.
        self._write(".env",
                    f"OPENAI_API_KEY={OPENAI_FAKE}\n"
                    f"ANTHROPIC_API_KEY={ANTHROPIC_FAKE}\n", mode=0o600)
        result = scan(self.home)
        self.assertEqual(len(result.occurrences), 2)

    def test_placeholders_are_skipped(self):
        self._write(".env",
                    "GITHUB_TOKEN=your-token-here\n"
                    "OPENAI_API_KEY=${OPENAI_API_KEY}\n"
                    "FOO_API_KEY=xxxxxxxx\n", mode=0o600)
        result = scan(self.home)
        self.assertEqual(result.occurrences, [])

    def test_sprawl_same_key_two_files(self):
        self._write(".env", f"ANTHROPIC_API_KEY={ANTHROPIC_FAKE}\n", mode=0o600)
        self._write(".codex/config.toml",
                     f'api_key = "{ANTHROPIC_FAKE}"\n', mode=0o600)
        result = scan(self.home)
        kinds = {f.kind for f in result.findings}
        self.assertIn("sprawl", kinds)
        sprawl = [f for f in result.findings if f.kind == "sprawl"][0]
        self.assertEqual(sprawl.severity, "medium")

    def test_history_flagged_high(self):
        self._write(".zsh_history",
                     f"export OPENAI_API_KEY={OPENAI_FAKE}\n", mode=0o600)
        result = scan(self.home)
        history = [f for f in result.findings if f.kind == "history"]
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].severity, "high")

    def test_world_readable_flagged(self):
        self._write(".env", f"OPENAI_API_KEY={OPENAI_FAKE}\n", mode=0o644)
        result = scan(self.home)
        wr = [f for f in result.findings if f.kind == "world-readable"]
        self.assertEqual(len(wr), 1)
        self.assertIn("644", wr[0].detail)

    def test_private_file_not_flagged(self):
        self._write(".env", f"OPENAI_API_KEY={OPENAI_FAKE}\n", mode=0o600)
        result = scan(self.home)
        self.assertEqual([f for f in result.findings
                          if f.kind == "world-readable"], [])

    def test_report_never_contains_key_material(self):
        self._write(".env",
                    f"OPENAI_API_KEY={OPENAI_FAKE}\n"
                    f"ANTHROPIC_API_KEY={ANTHROPIC_FAKE}\n"
                    f"GITHUB_TOKEN={GITHUB_FAKE}\n", mode=0o600)
        result = scan(self.home)
        text = render_human(result) + render_json(result)
        for secret in (OPENAI_FAKE, ANTHROPIC_FAKE, GITHUB_FAKE):
            self.assertNotIn(secret, text)
        # Fingerprints are present so the same key is recognisable.
        self.assertIn(result.occurrences[0].fingerprint, text)

    def test_fingerprint_stable(self):
        self._write(".env", f"OPENAI_API_KEY={OPENAI_FAKE}\n", mode=0o600)
        fp1 = scan(self.home).occurrences[0].fingerprint
        fp2 = scan(self.home).occurrences[0].fingerprint
        self.assertEqual(fp1, fp2)
        self.assertEqual(len(fp1), 12)

    def test_json_report_parses_and_has_rotation(self):
        self._write(".env", f"OPENAI_API_KEY={OPENAI_FAKE}\n", mode=0o600)
        payload = json.loads(render_json(scan(self.home)))
        self.assertEqual(payload["summary"]["keys_found"], 1)
        self.assertIn("openai", payload["rotation"])
        self.assertTrue(payload["rotation"]["openai"].startswith("https://"))

    def test_unrecognized_secret_assignment(self):
        self._write(".env", "MYAPP_API_KEY=Zx9q2mR7vB4kLp8w\n", mode=0o600)
        result = scan(self.home)
        self.assertEqual(len(result.occurrences), 1)
        self.assertEqual(result.occurrences[0].provider, "unrecognized")

    def test_clean_home_exit_zero(self):
        self._write(".env", "# nothing here\n", mode=0o600)
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(["--root", str(self.home)])
        self.assertEqual(code, 0)
        self.assertIn("Clean", out.getvalue())

    def test_keys_found_exit_one(self):
        path = self._write(".env", f"OPENAI_API_KEY={OPENAI_FAKE}\n", mode=0o600)
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(["--root", str(self.home), str(path)])
        self.assertEqual(code, 1)

    @unittest.skipUnless(shutil.which("git"), "git not available")
    def test_git_not_ignored_flagged(self):
        subprocess.run(["git", "init", "-q"], cwd=self.home, check=True)
        subprocess.run(["git", "config", "user.email", "t@t.t"],
                       cwd=self.home, check=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=self.home,
                       check=True)
        self._write(".env", f"OPENAI_API_KEY={OPENAI_FAKE}\n", mode=0o600)
        result = scan(self.home)
        kinds = {f.kind for f in result.findings}
        self.assertIn("not-ignored", kinds)

    @unittest.skipUnless(shutil.which("git"), "git not available")
    def test_git_ignored_not_flagged(self):
        subprocess.run(["git", "init", "-q"], cwd=self.home, check=True)
        self._write(".gitignore", ".env\n")
        self._write(".env", f"OPENAI_API_KEY={OPENAI_FAKE}\n", mode=0o600)
        result = scan(self.home)
        kinds = {f.kind for f in result.findings}
        self.assertNotIn("not-ignored", kinds)
        self.assertNotIn("git-tracked", kinds)


if __name__ == "__main__":
    unittest.main()
