from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from packageproof.models.schemas import AnalyzePackageRequest, RegistryResult, SourceArchive

SUSPICIOUS_PATTERNS = {
    "credential_stealer": [
        r"\.npmrc",
        r"\.pypirc",
        r"\.ssh/id_rsa",
        r"\.aws/credentials",
        r"application_default_credentials\.json",
        r"process\.env",
        r"os\.environ",
    ],
    "install_script_abuse": [
        r"\bpreinstall\b",
        r"\bpostinstall\b",
        r"\bsetup\.py\b",
        r"\.pth\b",
        r"sitecustomize\.py",
    ],
    "obfuscation": [
        r"\beval\s*\(",
        r"\bexec\s*\(",
        r"base64\.b64decode",
        r"atob\s*\(",
        r"fromCharCode",
    ],
    "network_exfiltration": [
        r"curl\s+",
        r"wget\s+",
        r"fetch\s*\(",
        r"requests\.post",
        r"http://169\.254\.169\.254",
        r"metadata\.google\.internal",
    ],
    "process_execution": [
        r"child_process",
        r"subprocess\.",
        r"os\.system",
        r"Runtime\.getRuntime",
        r"powershell",
    ],
    "crypto_drainer": [
        r"seed phrase",
        r"mnemonic",
        r"private[_-]?key",
        r"metamask",
        r"phantom wallet",
        r"solana wallet",
        r"ethers\.Wallet",
    ],
}


class StaticScanner:
    def scan(
        self,
        request: AnalyzePackageRequest,
        registry: RegistryResult,
        archive: SourceArchive,
    ) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        scripts = registry.metadata.get("scripts") or {}
        for name, command in scripts.items():
            if name in {"preinstall", "install", "postinstall", "prepare"}:
                findings.append(
                    {
                        "type": "install_script",
                        "severity": "medium",
                        "file": "package.json",
                        "detail": f"npm lifecycle script {name}: {command}",
                    }
                )

        for path, content in archive.files.items():
            self._scan_file(path, content, findings)

        behavior_chain = self._behavior_chain(findings)
        attack_types = sorted({finding["type"] for finding in findings})
        return {
            "files_scanned": len(archive.files),
            "archive_truncated": archive.truncated,
            "archive_errors": archive.errors,
            "findings": findings[:100],
            "attack_type_candidates": attack_types,
            "behavior_chain": behavior_chain,
        }

    def _scan_file(self, path: str, content: str, findings: list[dict[str, Any]]) -> None:
        normalized_path = path.lower()
        basename = normalized_path.rsplit("/", maxsplit=1)[-1]
        if basename.endswith(".pth") or basename in {"sitecustomize.py", "usercustomize.py"}:
            findings.append(
                {
                    "type": "install_script_abuse",
                    "severity": "high",
                    "file": path,
                    "detail": "Python startup execution hook present",
                }
            )
        if basename == "setup.py":
            findings.append(
                {
                    "type": "install_script_abuse",
                    "severity": "medium",
                    "file": path,
                    "detail": "setup.py can execute during build or install",
                }
            )

        entropy = self._entropy(content[:50_000])
        if entropy >= 5.5 and len(content) > 8_000:
            findings.append(
                {
                    "type": "obfuscation",
                    "severity": "medium",
                    "file": path,
                    "detail": f"high entropy text content ({entropy:.2f})",
                }
            )

        for attack_type, patterns in SUSPICIOUS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content, flags=re.IGNORECASE):
                    findings.append(
                        {
                            "type": attack_type,
                            "severity": self._severity_for(attack_type),
                            "file": path,
                            "detail": f"matched suspicious pattern: {pattern}",
                        }
                    )

    @staticmethod
    def _severity_for(attack_type: str) -> str:
        if attack_type in {"credential_stealer", "crypto_drainer", "network_exfiltration"}:
            return "high"
        return "medium"

    @staticmethod
    def _entropy(content: str) -> float:
        if not content:
            return 0.0
        counts = Counter(content)
        length = len(content)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    @staticmethod
    def _behavior_chain(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        types = {finding["type"] for finding in findings}
        chains: list[dict[str, Any]] = []
        if {"install_script_abuse", "credential_stealer"} <= types:
            chains.append(
                {
                    "type": "install_time_secret_access",
                    "severity": "critical",
                    "events": ["install_script_abuse", "credential_stealer"],
                }
            )
        if {"install_script_abuse", "network_exfiltration"} <= types:
            chains.append(
                {
                    "type": "install_time_network_behavior",
                    "severity": "critical",
                    "events": ["install_script_abuse", "network_exfiltration"],
                }
            )
        if {"credential_stealer", "network_exfiltration"} <= types:
            chains.append(
                {
                    "type": "possible_secret_exfiltration",
                    "severity": "critical",
                    "events": ["credential_stealer", "network_exfiltration"],
                }
            )
        return chains
