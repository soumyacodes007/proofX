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
        r"OPENAI_API_KEY",
        r"AWS_SECRET_ACCESS_KEY",
        r"NPM_TOKEN",
        r"GH_TOKEN",
        r"GITHUB_TOKEN",
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
                    "phase": "install",
                    "detail": f"npm lifecycle script {name}: {command}",
                }
            )
            self._scan_text(
                path=f"package.json:scripts.{name}",
                content=str(command),
                findings=findings,
                phase="install",
            )

        for path, content in archive.files.items():
            self._scan_file(path, content, findings)
        for binary in archive.binary_files:
            findings.append(
                {
                    "type": "native_binary",
                    "severity": self._binary_severity(binary),
                    "file": binary.get("path", ""),
                    "phase": "runtime",
                    "detail": (
                        f"native/binary artifact present: {binary.get('type')} "
                        f"({binary.get('size')} bytes)"
                    ),
                }
            )

        self._apply_package_context(request, findings)
        findings = self._dedupe_findings(findings)
        behavior_chain = self._behavior_chain(findings)
        attack_types = sorted({finding["type"] for finding in findings})
        return {
            "files_scanned": len(archive.files),
            "archive_truncated": archive.truncated,
            "archive_errors": archive.errors,
            "binary_files": archive.binary_files[:100],
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
                    "phase": "install",
                    "detail": "Python startup execution hook present",
                }
            )
        if basename == "setup.py":
            findings.append(
                {
                    "type": "install_script",
                    "severity": "low",
                    "file": path,
                    "phase": "install",
                    "detail": "setup.py can execute during build or install",
                }
            )

        entropy = self._entropy(content[:50_000])
        if entropy >= 5.5 and len(content) > 8_000:
            findings.append(
                {
                    "type": "obfuscation",
                    "severity": self._contextual_severity(path, "medium"),
                    "file": path,
                    "phase": self._phase_for_path(path),
                    "detail": f"high entropy text content ({entropy:.2f})",
                }
            )

        self._scan_text(path, content, findings, phase=self._phase_for_path(path))

    def _scan_text(
        self,
        path: str,
        content: str,
        findings: list[dict[str, Any]],
        phase: str,
    ) -> None:
        for attack_type, patterns in SUSPICIOUS_PATTERNS.items():
            for pattern in patterns:
                if self._should_skip_pattern(path, attack_type):
                    continue
                match = re.search(pattern, content, flags=re.IGNORECASE)
                if match is None:
                    continue
                findings.append(
                    {
                        "type": attack_type,
                        "severity": self._contextual_severity(
                            path,
                            self._severity_for(attack_type),
                        ),
                        "file": path,
                        "phase": phase,
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
    def _binary_severity(binary: dict[str, Any]) -> str:
        path = str(binary.get("path", "")).lower()
        if any(fragment in path for fragment in ("/test", "/tests", "/docs", "/examples")):
            return "low"
        return "high"

    @staticmethod
    def _phase_for_path(path: str) -> str:
        normalized = path.lower()
        basename = normalized.rsplit("/", maxsplit=1)[-1]
        if basename in {"setup.py", "sitecustomize.py", "usercustomize.py"}:
            return "install"
        if basename.endswith(".pth"):
            return "install"
        return "runtime"

    @staticmethod
    def _contextual_severity(path: str, severity: str) -> str:
        normalized = path.lower()
        low_signal_fragments = ("/test", "/tests", "/docs", "/doc", "/example", "/examples")
        if any(fragment in normalized for fragment in low_signal_fragments):
            return "low"
        return severity

    @staticmethod
    def _should_skip_pattern(path: str, attack_type: str) -> bool:
        basename = path.lower().rsplit("/", maxsplit=1)[-1]
        metadata_files = {"sources.txt", "record", "metadata", "pkg-info"}
        return attack_type == "install_script_abuse" and basename in metadata_files

    @staticmethod
    def _apply_package_context(
        request: AnalyzePackageRequest,
        findings: list[dict[str, Any]],
    ) -> None:
        network_client_packages = {
            "npm": {"axios", "got", "node-fetch", "request", "undici"},
            "pypi": {"aiohttp", "httpx", "requests", "urllib3"},
        }
        package_name = request.package.lower().replace("_", "-")
        if package_name not in network_client_packages[request.ecosystem]:
            return

        for finding in findings:
            if finding.get("type") != "network_exfiltration":
                continue
            if finding.get("phase") == "install":
                continue
            finding["severity"] = "low"
            finding["detail"] = f"{finding['detail']} (network-client package context)"

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
        types_by_file: dict[str, set[str]] = {}
        phases_by_file: dict[str, set[str]] = {}
        for finding in findings:
            file = str(finding.get("file", ""))
            types_by_file.setdefault(file, set()).add(str(finding.get("type")))
            phases_by_file.setdefault(file, set()).add(str(finding.get("phase", "runtime")))

        chains: list[dict[str, Any]] = []
        install_secret_files = [
            file
            for file, file_types in types_by_file.items()
            if "install" in phases_by_file.get(file, set())
            and file_types & {"install_script", "install_script_abuse"}
            and "credential_stealer" in file_types
        ]
        if install_secret_files:
            chains.append(
                {
                    "type": "install_time_secret_access",
                    "severity": "critical",
                    "events": install_secret_files,
                }
            )
        install_network_files = [
            file
            for file, file_types in types_by_file.items()
            if "install" in phases_by_file.get(file, set())
            and file_types & {"install_script", "install_script_abuse"}
            and "network_exfiltration" in file_types
        ]
        if install_network_files:
            chains.append(
                {
                    "type": "install_time_network_behavior",
                    "severity": "critical",
                    "events": install_network_files,
                }
            )
        exfil_files = [
            file
            for file, file_types in types_by_file.items()
            if {"credential_stealer", "network_exfiltration"} <= file_types
        ]
        if exfil_files:
            chains.append(
                {
                    "type": "possible_secret_exfiltration",
                    "severity": "critical",
                    "events": exfil_files,
                }
            )
        return chains

    @staticmethod
    def _install_script_risks(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        types_by_file: dict[str, set[str]] = {}
        for finding in findings:
            file = str(finding.get("file", ""))
            types_by_file.setdefault(file, set()).add(str(finding.get("type")))

        chains: list[dict[str, Any]] = []
        script_network_files = [
            file
            for file, types in types_by_file.items()
            if types & {"install_script", "install_script_abuse"}
            and "network_exfiltration" in types
        ]
        if script_network_files:
            chains.append(
                {
                    "type": "install_script_network_access",
                    "severity": "critical",
                    "events": sorted(script_network_files),
                }
            )
        script_exec_files = [
            file
            for file, types in types_by_file.items()
            if types & {"install_script", "install_script_abuse"}
            and "process_execution" in types
        ]
        if script_exec_files:
            chains.append(
                {
                    "type": "install_script_process_execution",
                    "severity": "high",
                    "events": sorted(script_exec_files),
                }
            )
        return chains
