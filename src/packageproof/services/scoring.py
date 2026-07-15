from __future__ import annotations

from dataclasses import dataclass

from packageproof.models.schemas import AgentAction, AnalyzePackageRequest, EvidenceBundle, Verdict


@dataclass(frozen=True)
class ScoreResult:
    score: int
    verdict: Verdict
    agent_action: AgentAction
    attack_types: list[str]
    safer_alternatives: list[str]
    summary: str


class ScoreEngine:
    def score(self, request: AnalyzePackageRequest, evidence: EvidenceBundle) -> ScoreResult:
        score = 0
        attack_types: set[str] = set()
        safer_alternatives: set[str] = set()

        registry_errors = evidence.registry.get("errors", [])
        if registry_errors:
            score += 25

        registry_metadata = evidence.registry.get("metadata", {})
        reputation = registry_metadata.get("reputation", {})
        for signal in reputation.get("signals", []):
            score += self._signal_weight(signal.get("severity", "low"), default=5)
            attack_types.add(str(signal.get("type")))

        name_attack = registry_metadata.get("name_attack", {})
        for signal in name_attack.get("signals", []):
            score += self._signal_weight(signal.get("severity", "medium"), default=18)
            attack_types.add(str(signal.get("type")))
            alternative = signal.get("safer_alternative")
            if alternative:
                safer_alternatives.add(str(alternative))
        for alternative in name_attack.get("safer_alternatives", []):
            safer_alternatives.add(str(alternative))

        advisories = evidence.known_bad
        if advisories:
            malicious = [item for item in advisories if item.get("type") == "malicious"]
            score += 55 if malicious else 20
            attack_types.add("known_malicious" if malicious else "known_vulnerability")

        static_findings = evidence.static.get("findings", [])
        static_weights = {
            "credential_stealer": 35,
            "network_exfiltration": 30,
            "crypto_drainer": 30,
            "install_script_abuse": 25,
            "install_script": 15,
            "process_execution": 15,
            "obfuscation": 12,
        }
        seen_static_types: set[str] = set()
        for finding in static_findings:
            finding_type = str(finding.get("type"))
            if finding_type in seen_static_types:
                continue
            seen_static_types.add(finding_type)
            score += static_weights.get(finding_type, 8)
            attack_types.add(finding_type)

        for chain in evidence.behavior_chain:
            score += 35 if chain.get("severity") == "critical" else 15
            attack_types.add(str(chain.get("type")))

        if evidence.sandbox.get("error"):
            score += 5

        score = min(score, 100)
        verdict: Verdict
        agent_action: AgentAction
        if score >= 70:
            verdict = "block"
            agent_action = "do_not_install"
        elif score >= 35:
            verdict = "review"
            agent_action = "manual_review_required"
        else:
            verdict = "allow"
            agent_action = "install_allowed"

        summary = self._summary(request, verdict, score, sorted(attack_types), registry_errors)
        return ScoreResult(
            score=score,
            verdict=verdict,
            agent_action=agent_action,
            attack_types=sorted(attack_types),
            safer_alternatives=sorted(safer_alternatives),
            summary=summary,
        )

    @staticmethod
    def _signal_weight(severity: str, default: int) -> int:
        return {"critical": 35, "high": 35, "medium": 20, "low": 6}.get(severity, default)

    @staticmethod
    def _summary(
        request: AnalyzePackageRequest,
        verdict: Verdict,
        score: int,
        attack_types: list[str],
        registry_errors: list[str],
    ) -> str:
        coordinates = f"{request.ecosystem}:{request.package}@{request.version}"
        if registry_errors:
            return (
                f"{coordinates} returned {verdict} with risk score {score}. "
                f"Registry lookup issues require review: {'; '.join(registry_errors[:2])}."
            )
        if attack_types:
            return (
                f"{coordinates} returned {verdict} with risk score {score}. "
                f"Primary signals: {', '.join(attack_types[:5])}."
            )
        return (
            f"{coordinates} returned {verdict} with risk score {score}; "
            "no high-risk signals were found."
        )
