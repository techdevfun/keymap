"""Findings: one occurrence per key, plus derived risk checks."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Occurrence:
    """A single key value found in a file. Never holds key material."""

    provider: str
    file: str
    line: int
    key_name: str
    fingerprint: str  # first 12 hex chars of sha256(value)
    prefix: str  # public literal prefix only, e.g. "sk-ant-"
    description: str


@dataclass
class Finding:
    kind: str  # sprawl | world-readable | history | git-tracked | not-ignored
    severity: str  # high | medium | low
    file: str
    detail: str
    fingerprints: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    occurrences: list[Occurrence] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def providers(self) -> list[str]:
        seen: list[str] = []
        for occ in self.occurrences:
            if occ.provider not in seen:
                seen.append(occ.provider)
        return seen

    @property
    def has_findings(self) -> bool:
        return bool(self.occurrences or self.findings)
