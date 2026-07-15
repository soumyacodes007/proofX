from __future__ import annotations

from packageproof.models.schemas import (
    AnalyzePackageRequest,
    EvidenceBundle,
    RegistryResult,
    SourceArchive,
)
from packageproof.services.name_attack import NameAttackDetector
from packageproof.services.registry import RegistryClient
from packageproof.services.scoring import ScoreEngine
from packageproof.services.static_scanner import StaticScanner
from tests.fixtures.malicious_packages import npm_native_dropper, pypi_startup_secret_stealer


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
    archive = pypi_startup_secret_stealer()

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


def test_network_client_context_downgrades_http_examples():
    request = AnalyzePackageRequest(ecosystem="pypi", package="requests")
    registry = RegistryResult(
        ecosystem="pypi",
        package="requests",
        requested_version="latest",
        resolved_version="2.34.2",
        exists=True,
    )
    archive = SourceArchive(
        files={
            "requests/setup.py": "setup(name='requests')",
            "requests/src/requests/__init__.py": (
                "\"\"\"Example: requests.post('https://httpbin.org/post')\"\"\""
            ),
            "requests/src/requests.egg-info/SOURCES.txt": "setup.py\nsrc/requests/__init__.py",
        }
    )

    static = StaticScanner().scan(request, registry, archive)
    evidence = EvidenceBundle(
        registry={
            "metadata": {
                "reputation": {"signals": []},
                "name_attack": {"signals": [], "safer_alternatives": []},
            },
            "errors": [],
        },
        static=static,
    )
    result = ScoreEngine().score(request, evidence)

    assert result.verdict == "allow"
    assert "network_exfiltration" not in result.attack_types
    assert result.scoring["raw_score"] < 35
    assert all(
        finding["severity"] == "low"
        for finding in static["findings"]
        if finding["type"] == "network_exfiltration"
    )


def test_score_breakdown_blocks_sandbox_secret_exfiltration():
    request = AnalyzePackageRequest(ecosystem="npm", package="badpkg")
    evidence = EvidenceBundle(
        registry={
            "metadata": {
                "reputation": {"signals": []},
                "name_attack": {"signals": [], "safer_alternatives": []},
            },
            "errors": [],
        },
        behavior_chain=[
            {
                "type": "sandbox_possible_secret_exfiltration",
                "severity": "critical",
                "events": [{"path": "/home/user/.env"}, {"host": "203.0.113.10"}],
            }
        ],
    )

    result = ScoreEngine().score(request, evidence)

    assert result.verdict == "block"
    assert "sandbox_possible_secret_exfiltration" in result.attack_types
    assert result.scoring["contributions"][0]["weight"] == 75


def test_static_scanner_flags_native_binary_fixture():
    request = AnalyzePackageRequest(ecosystem="npm", package="native-dropper")
    registry = RegistryResult(
        ecosystem="npm",
        package="native-dropper",
        requested_version="latest",
        resolved_version="1.0.0",
        exists=True,
    )
    archive = npm_native_dropper()

    result = StaticScanner().scan(request, registry, archive)

    assert "native_binary" in result["attack_type_candidates"]
    assert result["binary_files"][0]["path"] == "package/build/dropper.node"


def test_registry_version_diff_flags_new_lifecycle_script():
    previous_info = {"scripts": {"test": "node test.js"}, "dependencies": {}}
    current_info = {
        "scripts": {"test": "node test.js", "postinstall": "node postinstall.js"},
        "dependencies": {},
    }

    result = RegistryClient._npm_version_diff("1.0.0", previous_info, current_info)

    assert result["added_scripts"] == ["postinstall"]
    assert result["signals"][0]["type"] == "new_lifecycle_script"
