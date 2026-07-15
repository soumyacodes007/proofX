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
        r"getenv\s*\(",
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
        r"axios\.post",
        r"requests\.post",
        r"urllib\.request",
        r"http://169\.254\.169\.254",
        r"metadata\.google\.internal",
    ],
    "process_execution": [
        r"child_process",
        r"subprocess\.",
        r"spawn\s*\(",
        r"execFile\s*\(",
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
            if name not in {"preinstall", "install", "postinstall", "prepare"}:
                continue
            findings.append(
                {
                    "type": "install_script",
                    "severity": self._install_script_severity(command),
                    "file": "package.json",
                    "detail": f"npm lifecycle script {name}: {command}",
                }
            )
            self._scan_text(
                path=f"package.json:scripts.{name}",
                content=str(command),
                findings=findings,
            )

        for path, content in archive.files.items():
            self._scan_file(path, content, findings)

        findings = self._dedupe_findings(findings)
        behavior_chain = self._behavior_chain(findings)
        attack_types = sorted({finding["type"] for finding in findings})
        return {
            "files_scanned": len(archive.files),
            "archive_truncated": archive.truncated,
            "archive_errors": archive.errors,
            "findings": findings[:100],
            "attack_type_candidates": attack_types,
            "behavior_chain": behavior_chain,
            "install_script_risks": self._install_script_risks(findings),
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

        self._scan_text(path, content, findings)

    def _scan_text(self, path: str, content: str, findings: list[dict[str, Any]]) -> None:
        for attack_type, patterns in SUSPICIOUS_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, content, flags=re.IGNORECASE)
                if match is None:
                    continue
                findings.append(
                    {
                        "type": attack_type,
                        "severity": self._severity_for(attack_type),
                        "file": path,
                        "detail": f"matched suspicious pattern: {pattern}",
                        "snippet": self._snippet(content, match.start(), match.end()),
                    }
                )

    @staticmethod
    def _install_script_severity(command: str) -> str:
        risky_tokens = ("curl", "wget", "http://", "https://", "node -e", "python -c")
        return "high" if any(token in command.lower() for token in risky_tokens) else "medium"

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
    def _snippet(content: str, start: int, end: int) -> str:
        left = max(0, start - 40)
        right = min(len(content), end + 40)
        return " ".join(content[left:right].split())

    @staticmethod
    def _dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: set[tuple[str, str, str]] = set()
        deduped: list[dict[str, Any]] = []
        for finding in findings:
            key = (
                str(finding.get("type")),
                str(finding.get("file")),
                str(finding.get("detail")),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        return deduped

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

    @staticmethod
    def _install_script_risks(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        script_files = {
            str(finding["file"])
            for finding in findings
            if finding["type"] in {"install_script", "install_script_abuse"}
        }
        if not script_files:
            return []

        types = {finding["type"] for finding in findings}
        chains: list[dict[str, Any]] = []
        if "network_exfiltration" in types:
            chains.append(
                {
                    "type": "install_script_network_access",
                    "severity": "critical",
                    "events": sorted(script_files) + ["network_exfiltration"],
                }
            )
        if "process_execution" in types:
            chains.append(
                {
                    "type": "install_script_process_execution",
                    "severity": "high",
                    "events": sorted(script_files) + ["process_execution"],
                }
            )
        return chains
