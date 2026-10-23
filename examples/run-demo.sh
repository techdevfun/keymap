#!/bin/sh
# Demo: scan a COPY of the fake home in examples/demo-home.
# All values there are FAKE. Expected output is in expected-output.txt.
# The copy lives in a temp dir outside any git repo, so the git checks
# stay silent, and only .env is world-readable (644) so only it gets
# flagged — the same output on any machine, including CI.
set -eu
cd "$(dirname "$0")/.."
DEMO_TMP="$(mktemp -d)"
trap 'rm -rf "$DEMO_TMP"' EXIT INT TERM
cp -r examples/demo-home/. "$DEMO_TMP/"
chmod 600 "$DEMO_TMP/.claude.json" "$DEMO_TMP/.codex/config.toml" "$DEMO_TMP/.codex/auth.json" \
  "$DEMO_TMP/.config/app.json" "$DEMO_TMP/.zsh_history"
chmod 644 "$DEMO_TMP/.env"
python3 -m keymap --root "$DEMO_TMP" || true
