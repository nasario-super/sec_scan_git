"""
SARIF (Static Analysis Results Interchange Format) report generator.

Generates SARIF 2.1.0 compliant output for GitHub Security integration.
"""

import json
from datetime import datetime
from typing import Any

from ..core.models import Finding, ScanResult, Severity
from .base import BaseReporter


class SARIFReporter(BaseReporter):
    """
    Generates SARIF format reports.

    SARIF is the format used by GitHub Security tab and
    other code scanning tools.
    """

    format_name = "sarif"
    file_extension = ".sarif"

    SARIF_VERSION = "2.1.0"
    SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    def generate(self, result: ScanResult) -> str:
        """
        Generate SARIF report.

        Args:
            result: Scan result

        Returns:
            SARIF JSON string
        """
        sarif = {
            "$schema": self.SCHEMA_URI,
            "version": self.SARIF_VERSION,
            "runs": [self._create_run(result)],
        }

        return json.dumps(sarif, indent=2, default=str)

    def _create_run(self, result: ScanResult) -> dict[str, Any]:
        """Create a SARIF run object."""
        return {
            "tool": self._create_tool(),
            "results": [self._create_result(f) for f in result.findings],
            "invocations": [self._create_invocation(result)],
        }

    def _create_tool(self) -> dict[str, Any]:
        """Create SARIF tool object."""
        return {
            "driver": {
                "name": "GitHub Security Scanner",
                "version": "1.0.0",
                "informationUri": "https://github.com/your-org/github-security-scanner",
                "rules": self._create_rules(),
            }
        }

    def _create_rules(self) -> list[dict[str, Any]]:
        """Create SARIF rules from known patterns."""
        rules = [
            {
                "id": "secrets/aws_access_key",
                "name": "AWS Access Key",
                "shortDescription": {"text": "AWS Access Key ID detected"},
                "fullDescription": {"text": "An AWS Access Key ID was found in the code."},
                "helpUri": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
                "defaultConfiguration": {"level": "error"},
            },
            {
                "id": "secrets/github_token",
                "name": "GitHub Token",
                "shortDescription": {"text": "GitHub Personal Access Token detected"},
                "fullDescription": {"text": "A GitHub token was found in the code."},
                "defaultConfiguration": {"level": "error"},
            },
            {
                "id": "secrets/private_key",
                "name": "Private Key",
                "shortDescription": {"text": "Private key detected"},
                "fullDescription": {"text": "A private key was found in the code."},
                "defaultConfiguration": {"level": "error"},
            },
            {
                "id": "sast/sql-injection",
                "name": "SQL Injection",
                "shortDescription": {"text": "Potential SQL Injection vulnerability"},
                "fullDescription": {"text": "User input may be used in SQL queries without proper sanitization."},
                "helpUri": "https://owasp.org/www-community/attacks/SQL_Injection",
                "defaultConfiguration": {"level": "error"},
                "properties": {"tags": ["security", "CWE-89"]},
            },
            {
                "id": "sast/xss",
                "name": "Cross-Site Scripting",
                "shortDescription": {"text": "Potential XSS vulnerability"},
                "fullDescription": {"text": "User input may be rendered without proper escaping."},
                "helpUri": "https://owasp.org/www-community/attacks/xss/",
                "defaultConfiguration": {"level": "warning"},
                "properties": {"tags": ["security", "CWE-79"]},
            },
            {
                "id": "iac/misconfig",
                "name": "Infrastructure Misconfiguration",
                "shortDescription": {"text": "Security misconfiguration in infrastructure code"},
                "fullDescription": {"text": "A security misconfiguration was found in infrastructure as code."},
                "defaultConfiguration": {"level": "warning"},
            },
        ]
        return rules

    def _create_result(self, finding: Finding) -> dict[str, Any]:
        """Create a SARIF result object from a finding."""
        result: dict[str, Any] = {
            "ruleId": finding.rule_id or f"{finding.type.value}/{finding.category}",
            "level": self._severity_to_level(finding.severity),
            "message": {
                "text": finding.rule_description or f"{finding.category} detected in {finding.file_path}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path,
                        },
                        "region": {
                            "startLine": finding.line_number or 1,
                            "startColumn": finding.column_start or 1,
                            "endColumn": finding.column_end or len(finding.line_content) + 1,
                        },
                    }
                }
            ],
        }

        # Add fingerprint for deduplication
        result["partialFingerprints"] = {
            "primaryLocationLineHash": self._hash_content(finding.line_content),
        }

        # Add fix suggestions if available
        if finding.remediation:
            result["fixes"] = [
                {
                    "description": {"text": finding.remediation},
                }
            ]

        # Add CWE if available
        if finding.cwe_id:
            result["taxa"] = [
                {
                    "id": finding.cwe_id,
                    "toolComponent": {"name": "CWE"},
                }
            ]

        # Add properties
        result["properties"] = {
            "repository": finding.repository,
            "category": finding.category,
            "states": [s.value for s in finding.states],
            "confidence": finding.confidence,
        }

        return result

    def _create_invocation(self, result: ScanResult) -> dict[str, Any]:
        """Create SARIF invocation object."""
        return {
            "executionSuccessful": result.metadata.repositories_failed == 0,
            "startTimeUtc": result.metadata.scan_date.isoformat() + "Z",
            "endTimeUtc": datetime.now().isoformat() + "Z",
            "toolExecutionNotifications": [],
        }

    def _severity_to_level(self, severity: Severity) -> str:
        """Convert severity to SARIF level."""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "none",
        }
        return mapping.get(severity, "warning")

    def _hash_content(self, content: str) -> str:
        """Create a hash of content for fingerprinting."""
        import hashlib
        return hashlib.sha256(content.encode()).hexdigest()[:16]

