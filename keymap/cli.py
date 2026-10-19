"""CLI: `python -m keymap [--root DIR] [--json] [file ...]`

Exit codes: 0 = no keys found, 1 = keys/findings found, 2 = usage/IO error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .report import render_human, render_json
from .scan import scan, scan_paths


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keymap",
        description="Map where your API keys live — locally, read-only, "
                    "without ever printing key material.",
    )
    parser.add_argument(
        "paths", nargs="*", metavar="FILE",
        help="Specific files to scan instead of the default config locations.")
    parser.add_argument(
        "--root", default=None,
        help="Root directory to scan (default: $HOME). Config files are "
             "looked up relative to this root.")
    parser.add_argument(
        "--json", action="store_true",
        help="Emit machine-readable JSON instead of the human report.")
    parser.add_argument(
        "--version", action="version", version="keymap 0.1.0")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.root).expanduser() if args.root else Path.home()
    if not root.is_dir():
        print(f"keymap: root is not a directory: {root}", file=sys.stderr)
        return 2
    if args.paths:
        result = scan_paths([Path(p).expanduser() for p in args.paths], root)
    else:
        result = scan(root)
    if args.json:
        print(render_json(result), end="")
    else:
        print(render_human(result), end="")
    return 1 if result.has_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
