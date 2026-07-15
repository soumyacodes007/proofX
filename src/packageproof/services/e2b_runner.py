from __future__ import annotations

from typing import Any

from packageproof.core.config import Settings
from packageproof.models.schemas import AnalyzePackageRequest, RegistryResult

CANARY_FILES = {
    "/home/user/.env": "OPENAI_API_KEY=sk-packageproof-canary\n",
    "/home/user/.npmrc": "//registry.npmjs.org/:_authToken=npm_packageproof_canary\n",
    "/home/user/.pypirc": "[pypi]\npassword = pypi-packageproof-canary\n",
    "/home/user/.ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\npackageproof-canary\n",
    "/home/user/.aws/credentials": "[default]\naws_secret_access_key=packageproof-canary\n",
    "/home/user/.config/gcloud/application_default_credentials.json": '{"canary": true}',
}


class E2BDetonator:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def detonate(
        self,
        request: AnalyzePackageRequest,
        registry: RegistryResult,
    ) -> dict[str, Any]:
        if not self.settings.enable_e2b:
            return {
                "sandbox": {
                    "enabled": False,
                    "reason": "ENABLE_E2B is false; deterministic static scan only",
                },
                "network": {},
                "filesystem": {},
                "behavior_chain": [],
            }

        if not self.settings.e2b_api_key:
            return {
                "sandbox": {"enabled": False, "reason": "E2B_API_KEY is not configured"},
                "network": {},
                "filesystem": {},
                "behavior_chain": [],
            }

        try:
            from e2b import Sandbox
        except ImportError as exc:
            return {
                "sandbox": {"enabled": False, "reason": f"e2b SDK unavailable: {exc}"},
                "network": {},
                "filesystem": {},
                "behavior_chain": [],
            }

        package_spec = request.package
        if registry.resolved_version and registry.resolved_version != "latest":
            package_spec = f"{request.package}=={registry.resolved_version}"
            if request.ecosystem == "npm":
                package_spec = f"{request.package}@{registry.resolved_version}"

        try:
            sandbox = Sandbox.create(timeout=self.settings.e2b_timeout_seconds)
            setup = self._plant_canaries(sandbox)
            install = self._install_package(sandbox, request.ecosystem, package_spec)
            probe = self._probe_package(sandbox, request.ecosystem, request.package)
            listing = sandbox.commands.run(
                "find /home/user -maxdepth 3 -type f | sort",
                timeout=self.settings.e2b_timeout_seconds,
            )
            try:
                sandbox.kill()
            except Exception:
                pass
        except Exception as exc:
            return {
                "sandbox": {"enabled": True, "error": str(exc)},
                "network": {},
                "filesystem": {},
                "behavior_chain": [],
            }

        combined_output = "\n".join(
            [
                str(getattr(install, "stdout", "")),
                str(getattr(install, "stderr", "")),
                str(getattr(probe, "stdout", "")),
                str(getattr(probe, "stderr", "")),
            ]
        )
        canary_mentions = []
        for path in CANARY_FILES:
            filename = path.rsplit("/", 1)[-1]
            if path in combined_output or filename in combined_output:
                canary_mentions.append(path)
        behavior_chain = []
        if canary_mentions:
            behavior_chain.append(
                {
                    "type": "sandbox_canary_secret_access",
                    "severity": "critical",
                    "events": canary_mentions,
                }
            )

        return {
            "sandbox": {
                "enabled": True,
                "setup": self._command_result(setup),
                "install": self._command_result(install),
                "probe": self._command_result(probe),
            },
            "network": {
                "note": (
                    "Phase 1 captures command output; packet-level capture is planned "
                    "for Phase 3"
                ),
            },
            "filesystem": {
                "canary_mentions": canary_mentions,
                "home_files": str(getattr(listing, "stdout", ""))[:4000],
            },
            "behavior_chain": behavior_chain,
        }

    @staticmethod
    def _plant_canaries(sandbox: Any) -> Any:
        commands = [
            "mkdir -p /home/user/.ssh /home/user/.aws /home/user/.config/gcloud",
            *[
                f"cat > {path} <<'PACKAGEPROOF_CANARY'\n{content}\nPACKAGEPROOF_CANARY"
                for path, content in CANARY_FILES.items()
            ],
        ]
        return sandbox.commands.run(" && ".join(commands), timeout=30)

    def _install_package(self, sandbox: Any, ecosystem: str, package_spec: str) -> Any:
        if ecosystem == "npm":
            command = f"cd /home/user && npm init -y && npm install {package_spec}"
        else:
            command = f"python -m pip install --disable-pip-version-check {package_spec}"
        return sandbox.commands.run(command, timeout=self.settings.e2b_timeout_seconds)

    def _probe_package(self, sandbox: Any, ecosystem: str, package_name: str) -> Any:
        if ecosystem == "npm":
            module_name = package_name.split("/")[-1]
            command = f"cd /home/user && node -e \"require('{module_name}')\""
        else:
            module_name = package_name.replace("-", "_")
            command = (
                "python - <<'PY'\n"
                "import importlib\n"
                f"importlib.import_module('{module_name}')\n"
                "PY"
            )
        return sandbox.commands.run(command, timeout=30)

    @staticmethod
    def _command_result(result: Any) -> dict[str, Any]:
        return {
            "exit_code": getattr(result, "exit_code", None),
            "stdout": str(getattr(result, "stdout", ""))[:4000],
            "stderr": str(getattr(result, "stderr", ""))[:4000],
        }
