#!/bin/sh
# Demo: scan the fake home in examples/demo-home.
# All values there are FAKE. Expected output is in expected-output.txt.
# The .env is chmod 644 on purpose so keymap flags it as world-readable.
set -eu
cd "$(dirname "$0")/.."
chmod 644 examples/demo-home/.env
python3 -m keymap --root examples/demo-home || true
