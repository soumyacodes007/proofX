from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from packageproof.core.config import Settings
from packageproof.models.schemas import AnalyzePackageRequest, RegistryResult

CANARY_FILES = {
    "/home/user/.env": "OPENAI_API_KEY=sk-packageproof-canary\n",
    "/home/user/.npmrc": "//registry.npmjs.org/:_authToken=npm_packageproof_canary\n",
    "/home/user/.pypirc": "[pypi]\npassword = pypi-packageproof-canary\n",
    "/home/user/.ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\npackageproof-canary\n",
    "/home/user/.aws/credentials": "[default]\naws_secret_access_key=packageproof-canary\n",
    "/home/user/.config/gcloud/application_default_credentials.json": '{"canary": true}',
    "/home/user/.config/gh/hosts.yml": "github.com:\n  oauth_token: ghp_packageproof_canary\n",
}

SENSITIVE_PATH_FRAGMENTS = (
    ".aws/credentials",
    ".config/gcloud",
    ".config/gh",
    ".env",
    ".npmrc",
    ".pypirc",
    ".ssh/id_rsa",
)

SUSPICIOUS_EXECUTABLES = (
    "curl",
    "nc",
    "ncat",
    "netcat",
    "powershell",
    "wget",
)


@dataclass(frozen=True)
class DetonationPlan:
    package_spec: str
    workdir: str
    install_command: str
    probe_command: str
    extra_probe_commands: list[str]


@dataclass(frozen=True)
class FailedCommand:
    exit_code: int
    stdout: str
    stderr: str


class E2BDetonator:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def detonate(
        self,
        request: AnalyzePackageRequest,
        registry: RegistryResult,
    ) -> dict[str, Any]:
        if request.analysis_depth == "quick":
            return {
                "sandbox": {
                    "enabled": False,
                    "reason": "analysis_depth=quick skips E2B detonation",
                },
                "network": {},
                "filesystem": {},
                "process": {},
                "artifacts": {},
                "behavior_chain": [],
            }
        if not self.settings.enable_e2b:
            return {
                "sandbox": {
                    "enabled": False,
                    "reason": "ENABLE_E2B is false; deterministic static scan only",
                },
                "network": {},
                "filesystem": {},
                "process": {},
                "artifacts": {},
                "behavior_chain": [],
            }

        if not self.settings.e2b_api_key:
            return {
                "sandbox": {"enabled": False, "reason": "E2B_API_KEY is not configured"},
                "network": {},
                "filesystem": {},
                "process": {},
                "artifacts": {},
                "behavior_chain": [],
            }

        try:
            from e2b import Sandbox
        except ImportError as exc:
            return {
                "sandbox": {"enabled": False, "reason": f"e2b SDK unavailable: {exc}"},
                "network": {},
                "filesystem": {},
                "process": {},
                "artifacts": {},
                "behavior_chain": [],
            }

        plan = self.build_plan(request, registry)
        canary_token = f"packageproof-canary-{uuid4().hex}"
        sandbox = None
        try:
            sandbox_kwargs: dict[str, Any] = {
                "timeout": self.settings.e2b_timeout_seconds,
                "allow_internet_access": self.settings.e2b_allow_internet_access,
                "api_key": self.settings.e2b_api_key,
                "metadata": {
                    "service": "packageproof-pro",
                    "ecosystem": request.ecosystem,
                    "package": request.package,
                },
            }
            if self.settings.e2b_template:
                sandbox_kwargs["template"] = self.settings.e2b_template

            sandbox = Sandbox.create(**sandbox_kwargs)
            setup = self._run(sandbox, self._canary_script(canary_token), timeout=30)
            strace_check = self._run(sandbox, "command -v strace || true", timeout=15)
            strace_install = None
            if not self._stdout(strace_check).strip() and self.settings.e2b_install_strace:
                strace_install = self._run(
                    sandbox,
                    (
                        "sudo apt-get update >/tmp/packageproof-apt-update.log 2>&1 && "
                        "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y strace "
                        ">/tmp/packageproof-apt-install.log 2>&1"
                    ),
                    timeout=120,
                )
                strace_check = self._run(sandbox, "command -v strace || true", timeout=15)
            strace_available = bool(self._stdout(strace_check).strip())

            before = self._run(sandbox, self._snapshot_command(), timeout=30)
            ps_before = self._run(sandbox, self._process_snapshot_command(), timeout=15)
            install = self._run_detonation_command(
                sandbox=sandbox,
                label="install",
                command=plan.install_command,
                strace_available=strace_available,
            )
            probe = self._run_detonation_command(
                sandbox=sandbox,
                label="probe",
                command=plan.probe_command,
                strace_available=strace_available,
                timeout=45,
            )
            extra_results = []
            if request.analysis_depth in {"standard", "deep"}:
                max_extra = 3 if request.analysis_depth == "standard" else 8
                for index, command in enumerate(plan.extra_probe_commands[:max_extra]):
                    extra_results.append(
                        (
                            f"extra_probe_{index}",
                            self._run_detonation_command(
                                sandbox=sandbox,
                                label=f"extra-{index}",
                                command=command,
                                strace_available=strace_available,
                                timeout=30,
                            ),
                        ),
                    )
            observe = None
            if request.analysis_depth == "deep":
                observe = self._run(sandbox, "sleep 20", timeout=25)
            after = self._run(sandbox, self._snapshot_command(), timeout=30)
            ps_after = self._run(sandbox, self._process_snapshot_command(), timeout=15)
            install_strace = self._read_file(sandbox, "/tmp/packageproof-install.strace")
            probe_strace = self._read_file(sandbox, "/tmp/packageproof-probe.strace")
            extra_strace = "\n".join(
                self._read_file(sandbox, f"/tmp/packageproof-extra-{index}.strace")
                for index in range(len(extra_results))
            )
        except Exception as exc:
            return {
                "sandbox": {
                    "enabled": True,
                    "package_spec": plan.package_spec,
                    "error": str(exc),
                },
                "network": {},
                "filesystem": {},
                "process": {},
                "artifacts": {},
                "behavior_chain": [],
            }
        finally:
            if sandbox is not None:
                try:
                    sandbox.kill()
                except Exception:
                    pass

        command_results = {
            "setup": self._command_result(setup),
            "strace_check": self._command_result(strace_check),
            "install": self._command_result(install),
            "probe": self._command_result(probe),
            "ps_before": self._command_result(ps_before),
            "ps_after": self._command_result(ps_after),
        }
        for key, result in extra_results:
            command_results[key] = self._command_result(result)
        if strace_install is not None:
            command_results["strace_install"] = self._command_result(strace_install)
        if observe is not None:
            command_results["observe"] = self._command_result(observe)
        return self.extract_evidence(
            plan=plan,
            command_results=command_results,
            before_snapshot=self._stdout(before),
            after_snapshot=self._stdout(after),
            strace_text="\n".join([install_strace, probe_strace, extra_strace]),
            canary_token=canary_token,
        )

    def build_plan(
        self,
        request: AnalyzePackageRequest,
        registry: RegistryResult,
    ) -> DetonationPlan:
        package_spec = request.package
        if registry.resolved_version and registry.resolved_version != "latest":
            if request.ecosystem == "npm":
                package_spec = f"{request.package}@{registry.resolved_version}"
            else:
                package_spec = f"{request.package}=={registry.resolved_version}"

        workdir = "/home/user/packageproof-work"
        quoted_workdir = shlex.quote(workdir)
        quoted_spec = shlex.quote(package_spec)
        if request.ecosystem == "npm":
            install_command = (
                f"mkdir -p {quoted_workdir} && cd {quoted_workdir} && "
                "npm init -y >/dev/null 2>&1 && "
                f"npm install --foreground-scripts {quoted_spec}"
            )
            probe_code = f"import({request.package!r})"
            probe_command = (
                f"cd {quoted_workdir} && "
                f"node -e {shlex.quote(probe_code)}"
            )
            extra_probe_commands = self._npm_bin_probe_commands(request, registry, workdir)
        else:
            module_name = request.package.replace("-", "_")
            install_command = (
                "python -m pip install --disable-pip-version-check "
                f"--no-input {quoted_spec}"
            )
            probe_code = f"import importlib; importlib.import_module({module_name!r})"
            probe_command = f"python -c {shlex.quote(probe_code)}"
            extra_probe_commands = self._pypi_cli_probe_commands(request)

        return DetonationPlan(
            package_spec=package_spec,
            workdir=workdir,
            install_command=install_command,
            probe_command=probe_command,
            extra_probe_commands=extra_probe_commands,
        )

    def extract_evidence(
        self,
        *,
        plan: DetonationPlan,
        command_results: dict[str, dict[str, Any]],
        before_snapshot: str,
        after_snapshot: str,
        strace_text: str,
        canary_token: str = "packageproof-canary",
    ) -> dict[str, Any]:
        combined_output = "\n".join(
            str(result.get("stdout", "")) + "\n" + str(result.get("stderr", ""))
            for result in command_results.values()
        )
        combined = "\n".join([combined_output, strace_text])
        filesystem_diff = self._diff_snapshots(before_snapshot, after_snapshot)
        canary_accesses = self._canary_accesses(combined, canary_token)
        network_events = self._network_events(combined)
        exec_events = self._exec_events(strace_text)
        sensitive_writes = self._sensitive_writes(filesystem_diff)
        process_events = self._process_events(
            command_results.get("ps_before", {}).get("stdout", ""),
            command_results.get("ps_after", {}).get("stdout", ""),
        )
        behavior_chain = self._behavior_chain(
            canary_accesses=canary_accesses,
            network_events=network_events,
            exec_events=exec_events,
            sensitive_writes=sensitive_writes,
            process_events=process_events,
        )

        return {
            "sandbox": {
                "enabled": True,
                "package_spec": plan.package_spec,
                "workdir": plan.workdir,
                "extra_probe_count": len(plan.extra_probe_commands),
                "commands": command_results,
                "strace_available": bool(command_results["strace_check"]["stdout"].strip()),
            },
            "network": {
                "events": network_events,
                "cloud_metadata_attempts": [
                    event
                    for event in network_events
                    if event.get("host") in {"169.254.169.254", "metadata.google.internal"}
                ],
            },
            "filesystem": {
                "canary_accesses": canary_accesses,
                "added": filesystem_diff["added"][:100],
                "modified": filesystem_diff["modified"][:100],
                "deleted": filesystem_diff["deleted"][:100],
                "sensitive_writes": sensitive_writes,
            },
            "process": {
                "events": process_events,
            },
            "artifacts": self._artifact_summary(
                command_results=command_results,
                filesystem_diff=filesystem_diff,
                strace_text=strace_text,
                network_events=network_events,
            ),
            "behavior_chain": behavior_chain,
        }

    def _run_detonation_command(
        self,
        *,
        sandbox: Any,
        label: str,
        command: str,
        strace_available: bool,
        timeout: int | None = None,
    ) -> Any:
        timeout = timeout or self.settings.e2b_timeout_seconds
        if not strace_available:
            return self._run(sandbox, command, timeout=timeout)

        output_path = f"/tmp/packageproof-{label}.strace"
        traced_command = (
            "strace -f -s 240 -yy "
            "-e trace=execve,openat,connect,sendto "
            f"-o {shlex.quote(output_path)} "
            f"sh -lc {shlex.quote(command)}"
        )
        return self._run(sandbox, traced_command, timeout=timeout)

    @staticmethod
    def _run(sandbox: Any, command: str, timeout: int) -> Any:
        try:
            return sandbox.commands.run(command, timeout=timeout)
        except Exception as exc:
            return FailedCommand(exit_code=-1, stdout="", stderr=str(exc))

    @staticmethod
    def _read_file(sandbox: Any, path: str) -> str:
        try:
            return str(sandbox.files.read(path))
        except Exception:
            try:
                result = sandbox.commands.run(f"cat {shlex.quote(path)} 2>/dev/null || true")
                return str(getattr(result, "stdout", ""))
            except Exception:
                return ""

    @staticmethod
    def _canary_script(canary_token: str) -> str:
        lines = [
            "set -eu",
            (
                "mkdir -p /home/user/.ssh /home/user/.aws "
                "/home/user/.config/gcloud /home/user/.config/gh"
            ),
        ]
        for path, content in E2BDetonator._canary_files(canary_token).items():
            lines.append(f"cat > {shlex.quote(path)} <<'PACKAGEPROOF_CANARY'")
            lines.append(content.rstrip("\n"))
            lines.append("PACKAGEPROOF_CANARY")
        lines.append("chmod 600 /home/user/.ssh/id_rsa")
        return "\n".join(lines)

    @staticmethod
    def _canary_files(canary_token: str) -> dict[str, str]:
        return {
            path: content.replace("packageproof-canary", canary_token)
            for path, content in CANARY_FILES.items()
        }

    @staticmethod
    def _snapshot_command() -> str:
        return (
            "find /home/user /tmp -xdev -type f "
            "-printf '%p\\t%s\\t%T@\\n' 2>/dev/null | sort"
        )

    @staticmethod
    def _process_snapshot_command() -> str:
        return "ps -eo pid,ppid,comm,args --no-headers | sort"

    @staticmethod
    def _command_result(result: Any) -> dict[str, Any]:
        return {
            "exit_code": getattr(result, "exit_code", None),
            "stdout": str(getattr(result, "stdout", ""))[:8000],
            "stderr": str(getattr(result, "stderr", ""))[:8000],
        }

    @staticmethod
    def _stdout(result: Any) -> str:
        return str(getattr(result, "stdout", ""))

    @staticmethod
    def _parse_snapshot(snapshot: str) -> dict[str, tuple[str, str]]:
        parsed: dict[str, tuple[str, str]] = {}
        for line in snapshot.splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            path, size, mtime = parts[0], parts[1], parts[2]
            parsed[path] = (size, mtime)
        return parsed

    def _diff_snapshots(self, before_snapshot: str, after_snapshot: str) -> dict[str, list[str]]:
        before = self._parse_snapshot(before_snapshot)
        after = self._parse_snapshot(after_snapshot)
        before_paths = set(before)
        after_paths = set(after)
        common = before_paths & after_paths
        return {
            "added": sorted(after_paths - before_paths),
            "deleted": sorted(before_paths - after_paths),
            "modified": sorted(path for path in common if before[path] != after[path]),
        }

    @staticmethod
    def _canary_accesses(text: str, canary_token: str) -> list[dict[str, str]]:
        events = []
        if canary_token in text:
            events.append({"path": "<canary-value>", "type": "value_exfiltration"})
        for path in CANARY_FILES:
            filename = path.rsplit("/", 1)[-1]
            if path in text or filename in text:
                events.append({"path": path, "type": "read_or_reference"})
        return events

    @staticmethod
    def _network_events(text: str) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        seen: set[tuple[str, str | None]] = set()
        for line in text.splitlines():
            if not any(token in line for token in ("connect(", "sendto(", "http://", "https://")):
                continue
            urls = re.findall(r"https?://[^\s'\"<>]+", line, flags=re.IGNORECASE)
            for url in urls:
                host = url.split("//", maxsplit=1)[-1].split("/", maxsplit=1)[0]
                key = (host, None)
                if key not in seen:
                    seen.add(key)
                    events.append(
                        {
                            "host": host,
                            "port": "",
                            "source": "output",
                            "classification": E2BDetonator._classify_network_host(host),
                        }
                    )

            ip_match = re.search(r'inet_addr\("(?P<ip>\d+\.\d+\.\d+\.\d+)"\)', line)
            if ip_match is None:
                continue
            port_match = re.search(r"sin_port\(htons\((?P<port>\d+)\)\)", line)
            host = ip_match.group("ip")
            port = port_match.group("port") if port_match else None
            key = (host, port)
            if key in seen:
                continue
            seen.add(key)
            events.append(
                {
                    "host": host,
                    "port": port or "",
                    "source": "strace",
                    "classification": E2BDetonator._classify_network_host(host),
                }
            )

        if "metadata.google.internal" in text:
            events.append(
                {
                    "host": "metadata.google.internal",
                    "port": "",
                    "source": "output",
                    "classification": "cloud_metadata",
                }
            )
        return events[:100]

    @staticmethod
    def _classify_network_host(host: str) -> str:
        normalized = host.lower()
        expected_hosts = (
            "github.com",
            "npmjs.org",
            "registry.npmjs.org",
            "pypi.org",
            "pythonhosted.org",
            "files.pythonhosted.org",
        )
        if normalized in {"169.254.169.254", "metadata.google.internal"}:
            return "cloud_metadata"
        if normalized in {"8.8.8.8", "1.1.1.1"}:
            return "dns_or_connectivity_check"
        if any(expected in normalized for expected in expected_hosts):
            return "expected_registry_or_source"
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", normalized):
            return "raw_ip_or_cdn"
        return "unknown"

    @staticmethod
    def _exec_events(strace_text: str) -> list[dict[str, str]]:
        events: list[dict[str, str]] = []
        for match in re.finditer(r'execve\("(?P<path>[^"]+)"', strace_text):
            path = match.group("path")
            name = path.rsplit("/", 1)[-1]
            if name in SUSPICIOUS_EXECUTABLES:
                events.append({"path": path, "name": name})
        return events[:100]

    @staticmethod
    def _sensitive_writes(filesystem_diff: dict[str, list[str]]) -> list[str]:
        changed = filesystem_diff["added"] + filesystem_diff["modified"]
        return [
            path
            for path in changed
            if any(fragment in path for fragment in SENSITIVE_PATH_FRAGMENTS)
        ][:100]

    @staticmethod
    def _process_events(before: str, after: str) -> list[dict[str, str]]:
        before_lines = set(before.splitlines())
        events = []
        for line in after.splitlines():
            if line in before_lines:
                continue
            if "packageproof" in line or "ps -eo pid,ppid,comm,args" in line:
                continue
            if any(name in line for name in SUSPICIOUS_EXECUTABLES):
                events.append({"process": line[:500], "type": "suspicious_process"})
        return events[:50]

    @staticmethod
    def _behavior_chain(
        *,
        canary_accesses: list[dict[str, str]],
        network_events: list[dict[str, str]],
        exec_events: list[dict[str, str]],
        sensitive_writes: list[str],
        process_events: list[dict[str, str]],
    ) -> list[dict[str, Any]]:
        chains: list[dict[str, Any]] = []
        if canary_accesses:
            chains.append(
                {
                    "type": "sandbox_canary_secret_access",
                    "severity": "critical",
                    "events": canary_accesses,
                }
            )
        cloud_metadata_events = [
            event
            for event in network_events
            if event.get("host") in {"169.254.169.254", "metadata.google.internal"}
        ]
        if cloud_metadata_events:
            chains.append(
                {
                    "type": "sandbox_cloud_metadata_access",
                    "severity": "critical",
                    "events": cloud_metadata_events,
                }
            )
        if canary_accesses and network_events:
            chains.append(
                {
                    "type": "sandbox_possible_secret_exfiltration",
                    "severity": "critical",
                    "events": canary_accesses + network_events,
                }
            )
        if exec_events:
            chains.append(
                {
                    "type": "sandbox_process_execution",
                    "severity": "high",
                    "events": exec_events,
                }
            )
        if process_events:
            chains.append(
                {
                    "type": "sandbox_suspicious_process_tree",
                    "severity": "high",
                    "events": process_events,
                }
            )
        if sensitive_writes:
            chains.append(
                {
                    "type": "sandbox_sensitive_file_write",
                    "severity": "high",
                    "events": sensitive_writes,
                }
            )
        return chains

    @staticmethod
    def _npm_bin_probe_commands(
        request: AnalyzePackageRequest,
        registry: RegistryResult,
        workdir: str,
    ) -> list[str]:
        bin_value = registry.metadata.get("bin")
        if isinstance(bin_value, str):
            names = [request.package.split("/")[-1]]
        elif isinstance(bin_value, dict):
            names = [str(name) for name in bin_value.keys()]
        else:
            names = []
        commands = []
        for name in names[:3]:
            quoted = shlex.quote(name)
            commands.append(
                f"cd {shlex.quote(workdir)} && "
                f"(timeout 15s npx --no-install {quoted} --version || true) && "
                f"(timeout 15s npx --no-install {quoted} --help || true)"
            )
        return commands

    @staticmethod
    def _pypi_cli_probe_commands(request: AnalyzePackageRequest) -> list[str]:
        command = request.package.replace("_", "-")
        return [
            f"(timeout 15s {shlex.quote(command)} --version || true) && "
            f"(timeout 15s {shlex.quote(command)} --help || true)"
        ]

    @staticmethod
    def _artifact_summary(
        *,
        command_results: dict[str, dict[str, Any]],
        filesystem_diff: dict[str, list[str]],
        strace_text: str,
        network_events: list[dict[str, str]],
    ) -> dict[str, Any]:
        return {
            "command_count": len(command_results),
            "command_keys": sorted(command_results),
            "strace_line_count": len(strace_text.splitlines()),
            "added_file_count": len(filesystem_diff["added"]),
            "modified_file_count": len(filesystem_diff["modified"]),
            "deleted_file_count": len(filesystem_diff["deleted"]),
            "network_event_count": len(network_events),
        }
