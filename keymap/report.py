"""Human and JSON reports. Reports contain fingerprints and public prefixes
only — never key material."""

from __future__ import annotations

import json
from dataclasses import asdict

from .findings import ScanResult
from .patterns import ROTATION_URLS

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def render_human(result: ScanResult) -> str:
    lines: list[str] = []
    lines.append("keymap — API key footprint report")
    lines.append(f"Files scanned: {result.files_scanned}  "
                 f"Skipped: {result.files_skipped}")
    if result.errors:
        lines.append(f"Read errors: {len(result.errors)}")
        for err in result.errors[:5]:
            lines.append(f"  ! {err}")
    lines.append("")

    if not result.occurrences:
        lines.append("No provider keys found in scanned config files. Clean.")
        return "\n".join(lines) + "\n"

    lines.append(f"Keys found: {len(result.occurrences)} "
                 f"across {len({o.file for o in result.occurrences})} file(s) "
                 f"— providers: {', '.join(result.providers)}")
    lines.append("")
    lines.append("Occurrences (prefix + fingerprint only — no key material):")
    for occ in sorted(result.occurrences, key=lambda o: (o.file, o.line)):
        lines.append(f"  {occ.file}:{occ.line}  {occ.provider}  "
                     f"{occ.key_name}  {occ.prefix}…{occ.fingerprint}  [{occ.description}]")
    lines.append("")

    if result.findings:
        lines.append("Findings:")
        for f in sorted(result.findings, key=lambda x: SEVERITY_ORDER[x.severity]):
            lines.append(f"  [{f.severity.upper()}] {f.kind} — {f.file}")
            lines.append(f"      {f.detail}")
        lines.append("")
    else:
        lines.append("Findings: none — keys exist but none are sprawled, "
                     "world-readable, in history, or exposed to git.")
        lines.append("")

    lines.append("Rotation checklist (revoke at the provider, then replace):")
    for provider in result.providers:
        url = ROTATION_URLS.get(provider, "")
        lines.append(f"  - {provider}: {url or '(no known revoke URL — check the provider dashboard)'}")
    lines.append("")
    lines.append("After rotating: delete the old value from every file above, "
                 "clear it from shell history, and re-run keymap to confirm.")
    return "\n".join(lines) + "\n"


def render_json(result: ScanResult) -> str:
    payload = {
        "summary": {
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "keys_found": len(result.occurrences),
            "providers": result.providers,
            "findings": len(result.findings),
            "errors": result.errors,
        },
        "occurrences": [asdict(o) for o in result.occurrences],
        "findings": [asdict(f) for f in result.findings],
        "rotation": {
            p: ROTATION_URLS.get(p, "") for p in result.providers
        },
    }
    return json.dumps(payload, indent=2) + "\n"
