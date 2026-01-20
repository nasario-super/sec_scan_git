"""
Secret validation utilities (provider-specific).
"""

from __future__ import annotations

import hashlib
import hmac
import re
from datetime import datetime
from typing import Optional

import httpx

from ..storage.models import FindingRecord


_GITHUB_TOKEN_RE = re.compile(r"(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})")
_SLACK_TOKEN_RE = re.compile(r"(xox[baprs]-[A-Za-z0-9-]+)")
_AWS_ACCESS_KEY_RE = re.compile(r"\b(AKIA|ASIA|AGPA|AIDA)[0-9A-Z]{16}\b")
_AWS_SECRET_KEY_RE = re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")
_AWS_SECRET_HINTS = ("secret", "aws_secret_access_key", "secretaccesskey")


def _extract_github_token(line: str) -> Optional[str]:
    match = _GITHUB_TOKEN_RE.search(line or "")
    return match.group(1) if match else None


def _extract_slack_token(line: str) -> Optional[str]:
    match = _SLACK_TOKEN_RE.search(line or "")
    return match.group(1) if match else None


def _extract_aws_keys(line: str) -> tuple[Optional[str], Optional[str]]:
    content = line or ""
    access_match = _AWS_ACCESS_KEY_RE.search(content)
    access_key = access_match.group(0) if access_match else None
    secret_key = None
    if access_key and any(hint in content.lower() for hint in _AWS_SECRET_HINTS):
        secret_match = _AWS_SECRET_KEY_RE.search(content)
        secret_key = secret_match.group(0) if secret_match else None
    return access_key, secret_key


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _get_signature_key(secret_key: str, date_stamp: str, region: str, service: str) -> bytes:
    k_date = _sign(f"AWS4{secret_key}".encode("utf-8"), date_stamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    return _sign(k_service, "aws4_request")


async def _validate_github_token(token: str) -> dict:
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            response = await client.get("https://api.github.com/user", headers=headers)
        except httpx.HTTPError:
            return {"status": "unknown", "message": "Falha ao validar token no GitHub."}

    if response.status_code == 200:
        return {"status": "valid", "message": "Token GitHub valido."}
    if response.status_code == 401:
        return {"status": "invalid", "message": "Token GitHub invalido ou revogado."}
    return {"status": "unknown", "message": "Nao foi possivel confirmar a validade do token."}


async def _validate_slack_token(token: str) -> dict:
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            response = await client.post("https://slack.com/api/auth.test", headers=headers)
        except httpx.HTTPError:
            return {"status": "unknown", "message": "Falha ao validar token no Slack."}

    data = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
    if data.get("ok") is True:
        return {"status": "valid", "message": "Token Slack valido."}
    if data.get("error") in {"invalid_auth", "token_revoked"}:
        return {"status": "invalid", "message": "Token Slack invalido ou revogado."}
    return {"status": "unknown", "message": "Nao foi possivel confirmar a validade do token."}


async def _validate_aws_credentials(access_key: str, secret_key: str) -> dict:
    method = "GET"
    service = "sts"
    region = "us-east-1"
    host = "sts.amazonaws.com"
    endpoint = "https://sts.amazonaws.com"
    request_parameters = "Action=GetCallerIdentity&Version=2011-06-15"

    t = datetime.utcnow()
    amz_date = t.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = t.strftime("%Y%m%d")

    canonical_uri = "/"
    canonical_querystring = request_parameters
    canonical_headers = f"host:{host}\n" f"x-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-date"
    payload_hash = hashlib.sha256(b"").hexdigest()
    canonical_request = "\n".join([
        method,
        canonical_uri,
        canonical_querystring,
        canonical_headers,
        signed_headers,
        payload_hash,
    ])

    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        algorithm,
        amz_date,
        credential_scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ])

    signing_key = _get_signature_key(secret_key, date_stamp, region, service)
    signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    authorization_header = (
        f"{algorithm} Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    headers = {
        "x-amz-date": amz_date,
        "Authorization": authorization_header,
    }

    async with httpx.AsyncClient(timeout=10) as client:
        try:
            response = await client.get(f"{endpoint}/?{request_parameters}", headers=headers)
        except httpx.HTTPError:
            return {"status": "unknown", "message": "Falha ao validar credenciais AWS."}

    if response.status_code == 200:
        return {"status": "valid", "message": "Credenciais AWS validas."}

    body = response.text or ""
    if "InvalidClientTokenId" in body or "SignatureDoesNotMatch" in body:
        return {"status": "invalid", "message": "Credenciais AWS invalidas."}
    if "AccessDenied" in body:
        return {"status": "unknown", "message": "Acesso negado ao validar AWS."}
    return {"status": "unknown", "message": "Nao foi possivel confirmar a validade da AWS."}


async def validate_secret_for_finding(finding: FindingRecord) -> dict:
    """
    Validate a secret based on finding category and line content.
    """
    line_content = finding.line_content or ""
    category = (finding.category or "").lower()

    if "github" in category:
        token = _extract_github_token(line_content)
        if not token:
            return {"status": "unknown", "provider": "github", "message": "Token nao identificado."}
        result = await _validate_github_token(token)
        return {**result, "provider": "github"}

    if "slack" in category:
        token = _extract_slack_token(line_content)
        if not token:
            return {"status": "unknown", "provider": "slack", "message": "Token nao identificado."}
        result = await _validate_slack_token(token)
        return {**result, "provider": "slack"}

    if "aws" in category:
        access_key, secret_key = _extract_aws_keys(line_content)
        if not access_key or not secret_key:
            return {
                "status": "unknown",
                "provider": "aws",
                "message": "Chave AWS incompleta na linha.",
            }
        result = await _validate_aws_credentials(access_key, secret_key)
        return {**result, "provider": "aws"}

    return {"status": "unknown", "provider": "unknown", "message": "Tipo de secret nao suportado."}
