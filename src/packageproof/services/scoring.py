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
    scoring: dict[str, object]


class ScoreEngine:
    def score(self, request: AnalyzePackageRequest, evidence: EvidenceBundle) -> ScoreResult:
        attack_types: set[str] = set()
        safer_alternatives: set[str] = set()
        contributions: list[dict[str, object]] = []

        def add_contribution(
            *,
            source: str,
            signal: str,
            weight: int,
            reason: str,
            attack_type: str | None = None,
        ) -> None:
            if weight <= 0:
                return
            contributions.append(
                {
                    "source": source,
                    "signal": signal,
                    "weight": weight,
                    "reason": reason,
                    "attack_type": attack_type,
                }
            )
            if attack_type and weight >= 10:
                attack_types.add(attack_type)

        registry_errors = evidence.registry.get("errors", [])
        if registry_errors:
            not_found = any("not found" in str(error).lower() for error in registry_errors)
            add_contribution(
                source="registry",
                signal="unresolved_package" if not_found else "registry_lookup_issue",
                weight=35 if not_found else 25,
                reason="; ".join(str(error) for error in registry_errors[:2]),
                attack_type="unresolved_package" if not_found else "registry_lookup_issue",
            )

        registry_metadata = evidence.registry.get("metadata", {})
        reputation = registry_metadata.get("reputation", {})
        for signal in reputation.get("signals", []):
            signal_type = str(signal.get("type"))
            add_contribution(
                source="registry.reputation",
                signal=signal_type,
                weight=self._signal_weight(str(signal.get("severity", "low")), default=5),
                reason=str(signal.get("detail", signal_type)),
                attack_type=signal_type,
            )

        name_attack = registry_metadata.get("name_attack", {})
        for signal in name_attack.get("signals", []):
            signal_type = str(signal.get("type"))
            add_contribution(
                source="registry.name",
                signal=signal_type,
                weight=self._signal_weight(str(signal.get("severity", "medium")), default=18),
                reason=str(signal.get("detail", signal_type)),
                attack_type=signal_type,
            )
            alternative = signal.get("safer_alternative")
            if alternative:
                safer_alternatives.add(str(alternative))
        for alternative in name_attack.get("safer_alternatives", []):
            safer_alternatives.add(str(alternative))

        advisories = evidence.known_bad
        if advisories:
            malicious = [item for item in advisories if item.get("type") == "malicious"]
            add_contribution(
                source="known_bad",
                signal="known_malicious" if malicious else "known_vulnerability",
                weight=75 if malicious else 20,
                reason=str((malicious or advisories)[0].get("summary") or "OSV advisory matched"),
                attack_type="known_malicious" if malicious else "known_vulnerability",
            )

        static_findings = evidence.static.get("findings", [])
        static_weights = {
            "credential_stealer": 35,
            "network_exfiltration": 30,
            "crypto_drainer": 30,
            "install_script_abuse": 25,
            "install_script": 15,
            "native_binary": 25,
            "process_execution": 15,
            "obfuscation": 12,
        }
        static_best_by_type: dict[str, dict[str, object]] = {}
        for finding in static_findings:
            finding_type = str(finding.get("type"))
            base_weight = static_weights.get(finding_type, 8)
            finding_score = self._finding_weight(
                severity=str(finding.get("severity", "medium")),
                base_weight=base_weight,
            )
            current = static_best_by_type.get(finding_type)
            if current is None or finding_score > int(current["weight"]):
                static_best_by_type[finding_type] = {
                    "weight": finding_score,
                    "detail": finding.get("detail", finding_type),
                    "file": finding.get("file", ""),
                }
        for finding_type, selected in static_best_by_type.items():
            reason = str(selected["detail"])
            if selected.get("file"):
                reason = f"{reason} in {selected['file']}"
            add_contribution(
                source="static",
                signal=finding_type,
                weight=int(selected["weight"]),
                reason=reason,
                attack_type=finding_type,
            )

        for chain in evidence.behavior_chain:
            chain_type = str(chain.get("type"))
            add_contribution(
                source="behavior_chain",
                signal=chain_type,
                weight=self._behavior_chain_weight(chain),
                reason=f"Observed behavior chain: {chain_type}",
                attack_type=chain_type,
            )

        if evidence.sandbox.get("error"):
            add_contribution(
                source="sandbox",
                signal="sandbox_error",
                weight=5,
                reason=str(evidence.sandbox.get("error")),
            )

        raw_score = sum(int(item["weight"]) for item in contributions)
        score = raw_score
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
            scoring={
                "raw_score": raw_score,
                "capped_score": score,
                "contributions": contributions,
            },
        )

    @staticmethod
    def _signal_weight(severity: str, default: int) -> int:
        return {"critical": 35, "high": 35, "medium": 20, "low": 6}.get(severity, default)

    @staticmethod
    def _finding_weight(severity: str, base_weight: int) -> int:
        if severity == "critical":
            return max(base_weight, 35)
        if severity == "high":
            return base_weight
        if severity == "medium":
            return min(base_weight, 15)
        if severity == "low":
            return min(base_weight, 3)
        return min(base_weight, 8)

    @staticmethod
    def _behavior_chain_weight(chain: dict[str, object]) -> int:
        chain_type = str(chain.get("type"))
        weights = {
            "sandbox_possible_secret_exfiltration": 75,
            "sandbox_canary_secret_access": 55,
            "sandbox_cloud_metadata_access": 55,
            "possible_secret_exfiltration": 45,
            "install_time_secret_access": 45,
            "install_time_network_behavior": 35,
            "install_script_network_access": 35,
            "sandbox_sensitive_file_write": 30,
            "sandbox_process_execution": 25,
            "sandbox_suspicious_process_tree": 25,
            "install_script_process_execution": 25,
        }
        if chain_type in weights:
            return weights[chain_type]
        return 35 if chain.get("severity") == "critical" else 15

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
