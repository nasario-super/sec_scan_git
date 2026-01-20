"""
Fingerprint utilities for deduplicating findings.
"""

from __future__ import annotations

import hashlib
import re

from ..core.models import Finding, FindingType


_QUOTED_STRING_RE = re.compile(r"(['\"])(?:\\.|(?!\1).)*\1")
_NUMBER_RE = re.compile(r"\b\d+\b")
_HEX_RE = re.compile(r"\b[a-fA-F0-9]{32,}\b")
_WHITESPACE_RE = re.compile(r"\s+")


def _normalize_line_content(line: str) -> str:
    """
    Normalize line content to reduce false deltas and avoid raw secrets.
    """
    if not line:
        return ""

    # Mask quoted strings and long hex sequences to avoid raw secrets in hashes
    normalized = _QUOTED_STRING_RE.sub('"<str>"', line)
    normalized = _HEX_RE.sub("<hex>", normalized)
    normalized = _NUMBER_RE.sub("<num>", normalized)
    normalized = _WHITESPACE_RE.sub(" ", normalized).strip()
    return normalized


def build_finding_fingerprint(finding: Finding) -> str:
    """
    Generate a stable fingerprint for a finding.

    Uses normalized content to reduce noise while keeping key identifiers.
    """
    finding_type = finding.type.value if isinstance(finding.type, FindingType) else str(finding.type)
    rule_id = finding.rule_id or finding.category or ""
    normalized_line = _normalize_line_content(finding.line_content or "")

    parts = [
        finding.repository or "",
        finding_type,
        rule_id,
        finding.file_path or "",
        str(finding.line_number or 0),
        normalized_line[:120],
    ]

    content = "|".join(parts)
    return hashlib.sha256(content.encode()).hexdigest()[:32]
