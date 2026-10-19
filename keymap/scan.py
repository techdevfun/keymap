"""Read-only scanner.

Walks a root directory (default ``$HOME``) over the config files agent
tools and CLIs actually read. Never writes, never follows symlinks out of
the tree, never opens files larger than 2 MB, never prints key material.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path

from .findings import Finding, Occurrence, ScanResult
from .patterns import GENERIC_SECRET_ASSIGN, PATTERNS, looks_like_placeholder

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_DIR_DEPTH = 3

# Single files (relative to the root) that commonly hold provider keys.
TARGET_FILES = [
    ".env", ".env.local", ".env.development", ".env.production",
    ".zshrc", ".bashrc", ".bash_profile", ".profile", ".zprofile",
    ".zsh_history", ".bash_history", ".sh_history",
    ".claude.json", ".claude/settings.json",
    ".codex/config.toml", ".codex/auth.json",
    ".cursor/mcp.json", ".cursor/settings.json",
    ".config/Code/User/settings.json",
    ".config/gh/hosts.yml",
    ".config/opencode/opencode.json",
    ".config/openclaw/openclaw.json",
    ".npmrc", ".pypirc", ".gitconfig",
    ".aws/credentials", ".aws/config",
    ".docker/config.json",
    ".netrc", ".gnupg/gpg.conf",
]

# Directories scanned recursively (shallow) for config-like files.
TARGET_DIRS = [
    ".config", ".codex", ".cursor", ".claude", ".aws", ".docker",
]

CONFIG_SUFFIXES = {".json", ".toml", ".yaml", ".yml", ".ini", ".conf", ".env", ".txt", ".rc"}
CONFIG_BASENAMES = {"credentials", "hosts.yml", "settings.json", "config", "mcp.json"}

HISTORY_NAMES = (".zsh_history", ".bash_history", ".sh_history", ".zsh_history".upper())


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


def _key_name_from_line(line: str, match_start: int) -> str:
    """Best-effort config key name from the text before the match."""
    before = line[:match_start].strip()
    m = re.search(r"([A-Za-z0-9_.\-]+)\s*[:=]\s*[\"']?$", before)
    if m:
        return m.group(1).strip("\"' ")
    m = re.search(r"([A-Za-z0-9_.\-]+)\s*$", before)
    return m.group(1) if m else "(unknown)"


def _scan_text(text: str, rel: str) -> list[Occurrence]:
    occurrences: list[Occurrence] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        # Spans are per-line: a match on one line must never suppress a
        # match at the same column on the next line.
        seen_spans: list[tuple[int, int]] = []
        for pattern in PATTERNS:
            for match in pattern.regex.finditer(line):
                value = match.group(0)
                if looks_like_placeholder(value):
                    continue
                if _overlaps(seen_spans, match.start(), match.end()):
                    continue
                seen_spans.append((match.start(), match.end()))
                occurrences.append(Occurrence(
                    provider=pattern.provider,
                    file=rel,
                    line=lineno,
                    key_name=_key_name_from_line(line, match.start()),
                    fingerprint=fingerprint(value),
                    prefix=pattern.prefix,
                    description=pattern.description,
                ))
        for match in GENERIC_SECRET_ASSIGN.finditer(line):
            value = match.group("value").strip("\"'")
            if looks_like_placeholder(value):
                continue
            if _overlaps(seen_spans, match.start("value"), match.end("value")):
                continue
            seen_spans.append((match.start("value"), match.end("value")))
            occurrences.append(Occurrence(
                provider="unrecognized",
                file=rel,
                line=lineno,
                key_name=match.group("name"),
                fingerprint=fingerprint(value),
                prefix="••••",
                description="Secret-looking assignment, no known provider pattern",
            ))
    return occurrences


def _overlaps(spans: list[tuple[int, int]], start: int, end: int) -> bool:
    return any(s < end and start < e for s, e in spans)


def _is_binary(head: bytes) -> bool:
    return b"\x00" in head


def _scan_file(path: Path, rel: str, result: ScanResult) -> None:
    try:
        if path.is_symlink():
            result.files_skipped += 1
            return
        if path.stat().st_size > MAX_FILE_BYTES:
            result.files_skipped += 1
            return
        with path.open("rb") as fh:
            head = fh.read(8192)
            if _is_binary(head):
                result.files_skipped += 1
                return
            text = (head + fh.read()).decode("utf-8", errors="replace")
    except OSError as exc:
        result.errors.append(f"{rel}: {exc}")
        return
    result.files_scanned += 1
    result.occurrences.extend(_scan_text(text, rel))
    _permission_check(path, rel, result)


def _permission_check(path: Path, rel: str, result: ScanResult) -> None:
    try:
        mode = path.stat().st_mode & 0o777
    except OSError:
        return
    if mode & 0o007:
        result.findings.append(Finding(
            kind="world-readable",
            severity="high",
            file=rel,
            detail=f"File is mode {oct(mode)} — anyone on this machine can read it. "
                   "Run: chmod 600 " + rel,
        ))


def _history_check(result: ScanResult) -> None:
    for occ in result.occurrences:
        if Path(occ.file).name in HISTORY_NAMES or "history" in Path(occ.file).name:
            result.findings.append(Finding(
                kind="history",
                severity="high",
                file=occ.file,
                detail=f"{occ.provider} key (…{occ.fingerprint}) was typed into shell history. "
                       "Rotate the key, then clear that history entry.",
                fingerprints=[occ.fingerprint],
            ))


def _sprawl_check(result: ScanResult) -> None:
    by_fp: dict[str, list[Occurrence]] = {}
    for occ in result.occurrences:
        by_fp.setdefault(occ.fingerprint, []).append(occ)
    for fp, occs in by_fp.items():
        files = sorted({o.file for o in occs})
        if len(files) > 1:
            result.findings.append(Finding(
                kind="sprawl",
                severity="medium",
                file=", ".join(files),
                detail=f"Same {occs[0].provider} key (…{fp}) lives in {len(files)} files. "
                       "Keep one canonical home for it and delete the copies.",
                fingerprints=[fp],
            ))


def _git_check(root: Path, result: ScanResult) -> None:
    if shutil.which("git") is None:
        return
    for occ in result.occurrences:
        fpath = root / occ.file
        repo = _nearest_git_root(fpath.parent)
        if repo is None:
            continue
        rel = os.path.relpath(fpath, repo)
        try:
            tracked = subprocess.run(
                ["git", "-C", str(repo), "ls-files", "--error-unmatch", "--", rel],
                capture_output=True, timeout=5)
            if tracked.returncode == 0:
                result.findings.append(Finding(
                    kind="git-tracked",
                    severity="high",
                    file=occ.file,
                    detail=f"{occ.provider} key (…{occ.fingerprint}) is TRACKED by git. "
                           "Rotate it now — removing it from history later does not un-leak it.",
                    fingerprints=[occ.fingerprint],
                ))
                continue
            ignored = subprocess.run(
                ["git", "-C", str(repo), "check-ignore", "-q", "--", rel],
                capture_output=True, timeout=5)
            if ignored.returncode != 0:
                result.findings.append(Finding(
                    kind="not-ignored",
                    severity="medium",
                    file=occ.file,
                    detail=f"{occ.provider} key (…{occ.fingerprint}) sits in a git repo and is "
                           "NOT gitignored — one careless `git add .` away from a commit.",
                    fingerprints=[occ.fingerprint],
                ))
        except (OSError, subprocess.TimeoutExpired):
            continue


def _nearest_git_root(start: Path) -> Path | None:
    cur = start
    while True:
        if (cur / ".git").exists():
            return cur
        if cur.parent == cur:
            return None
        cur = cur.parent


def _iter_targets(root: Path) -> list[Path]:
    targets: list[Path] = []
    for rel in TARGET_FILES:
        p = root / rel
        if p.is_file():
            targets.append(p)
    for rel in TARGET_DIRS:
        base = root / rel
        if not base.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            depth = Path(dirpath).relative_to(base).parts
            if len(depth) > MAX_DIR_DEPTH:
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames
                           if d not in {".git", "node_modules", "__pycache__"}]
            for name in filenames:
                p = Path(dirpath) / name
                if p.suffix.lower() in CONFIG_SUFFIXES or name in CONFIG_BASENAMES \
                        or "history" in name or name.startswith(".env"):
                    if p not in targets:
                        targets.append(p)
    return targets


def scan(root: Path) -> ScanResult:
    """Scan ``root`` (a home directory) and return occurrences + findings."""
    result = ScanResult()
    for path in _iter_targets(root):
        rel = os.path.relpath(path, root)
        _scan_file(path, rel, result)
    _history_check(result)
    _sprawl_check(result)
    _git_check(root, result)
    return result


def scan_paths(paths: list[Path], root: Path) -> ScanResult:
    """Scan explicit files (used by tests and by `keymap <file> ...`)."""
    result = ScanResult()
    for path in paths:
        if path.is_file():
            try:
                rel = os.path.relpath(path, root)
            except ValueError:
                rel = str(path)
            _scan_file(path, rel, result)
    _history_check(result)
    _sprawl_check(result)
    _git_check(root, result)
    return result
