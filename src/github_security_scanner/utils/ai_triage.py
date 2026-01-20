"""
AI-assisted triage utilities for findings.
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

import httpx

from ..core.config import AISettings
from ..storage.models import FindingRecord


_NOISE_PATH_SEGMENTS = {
    "test", "tests", "__tests__", "spec", "specs",
    "fixture", "fixtures", "example", "examples",
    "sample", "samples", "mock", "mocks",
}
_SAFE_CONTEXT_PATTERNS = [
    r"process\.env",
    r"os\.environ",
    r"os\.getenv",
    r"getenv\(",
    r"vault\.",
    r"keyvault",
    r"secretmanager",
    r"secretsmanager",
    r"dotenv",
]
_SANITIZATION_PATTERNS = [
    r"sanitize",
    r"escape",
    r"encode",
    r"param",
    r"prepared",
    r"validator",
    r"dompurify",
]
_PLACEHOLDER_PATTERNS = [
    r"example",
    r"sample",
    r"test",
    r"dummy",
    r"fake",
    r"mock",
    r"placeholder",
    r"changeme",
    r"todo",
    r"fixme",
]


def _path_is_noise(path: str) -> bool:
    parts = re.split(r"[\\/]+", path or "")
    return any(part.lower() in _NOISE_PATH_SEGMENTS for part in parts)


def _matches_any(patterns: list[str], text: str) -> bool:
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def heuristic_triage(finding: FindingRecord) -> dict[str, Any]:
    """
    Lightweight heuristic triage (no external AI).
    """
    reasons: list[str] = []
    label = "needs_review"
    confidence = 0.55

    line = (finding.line_content or "").lower()
    path = finding.file_path or ""
    category = (finding.category or "").lower()
    rule_id = (finding.rule_id or "").lower()
    finding_type = (finding.finding_type or "").lower()

    if _path_is_noise(path):
        reasons.append("Caminho sugere arquivo de teste/fixture/exemplo.")
        label = "false_positive"
        confidence = 0.75

    if _matches_any(_PLACEHOLDER_PATTERNS, line):
        reasons.append("Conteudo parece placeholder/exemplo.")
        label = "false_positive"
        confidence = max(confidence, 0.7)

    if finding_type == "secret" and _matches_any(_SAFE_CONTEXT_PATTERNS, line):
        reasons.append("Valor parece referenciado via env/secret manager.")
        label = "needs_review"
        confidence = max(confidence, 0.65)

    if finding_type == "sast" and _matches_any(_SANITIZATION_PATTERNS, line):
        reasons.append("Ha indicios de sanitizacao/validacao na linha.")
        label = "needs_review"
        confidence = max(confidence, 0.6)

    if "sql" in category or "sql" in rule_id:
        if _matches_any([r"param", r"prepared", r"bind"], line):
            reasons.append("Possivel uso de query parametrizada.")
            label = "needs_review"
            confidence = max(confidence, 0.6)

    if not reasons:
        reasons.append("Sem sinais claros de falso positivo.")
        label = "likely_true_positive"
        confidence = 0.6

    return {
        "label": label,
        "confidence": round(confidence, 2),
        "reasons": reasons[:5],
        "source": "heuristic",
    }


async def llm_triage(
    finding: FindingRecord,
    settings: AISettings,
) -> Optional[dict[str, Any]]:
    """
    Use an OpenAI-compatible API for triage (optional).
    """
    if not settings.api_key or not settings.api_url:
        return None

    payload = {
        "model": settings.model,
        "temperature": settings.temperature,
        "max_tokens": settings.max_tokens,
        "messages": [
            {
                "role": "system",
                "content": (
                    "Voce e um analista de seguranca. "
                    "Retorne apenas JSON com chaves: label, confidence, reasons. "
                    "label deve ser: likely_true_positive, false_positive, needs_review."
                ),
            },
            {
                "role": "user",
                "content": json.dumps({
                    "repository": finding.repository,
                    "type": finding.finding_type,
                    "category": finding.category,
                    "severity": finding.severity,
                    "file_path": finding.file_path,
                    "line_number": finding.line_number,
                    "line_content": finding.line_content,
                    "rule_id": finding.rule_id,
                    "rule_description": finding.rule_description,
                }),
            },
        ],
    }

    timeout = httpx.Timeout(settings.timeout)
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            response = await client.post(
                f"{settings.api_url.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {settings.api_key}"},
                json=payload,
            )
            response.raise_for_status()
        except httpx.HTTPError:
            return None

    data = response.json()
    content = (
        data.get("choices", [{}])[0]
        .get("message", {})
        .get("content", "")
    )
    if not content:
        return None

    try:
        result = json.loads(content)
    except json.JSONDecodeError:
        return None

    if not isinstance(result, dict):
        return None

    label = result.get("label")
    confidence = result.get("confidence")
    reasons = result.get("reasons")
    if label not in {"likely_true_positive", "false_positive", "needs_review"}:
        return None
    if not isinstance(confidence, (int, float)):
        return None
    if not isinstance(reasons, list):
        return None

    return {
        "label": label,
        "confidence": round(float(confidence), 2),
        "reasons": reasons[:5],
        "source": "llm",
    }


async def triage_finding(
    finding: FindingRecord,
    settings: AISettings,
) -> dict[str, Any]:
    """
    Run AI triage with LLM fallback to heuristics.
    """
    if settings.enabled:
        result = await llm_triage(finding, settings)
        if result:
            return result

    return heuristic_triage(finding)
