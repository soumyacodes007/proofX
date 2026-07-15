from __future__ import annotations

import json

import httpx

from packageproof.core.config import Settings
from packageproof.models.schemas import AIAnalysis, AnalyzePackageRequest, EvidenceBundle, Verdict


class OpenRouterAnalyst:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def analyze(
        self,
        *,
        request: AnalyzePackageRequest,
        evidence: EvidenceBundle,
        fallback_summary: str,
        score: int,
        verdict: Verdict,
    ) -> AIAnalysis:
        if not self.settings.openrouter_api_key:
            return AIAnalysis(
                summary=fallback_summary,
                error="OPENROUTER_API_KEY is not configured",
            )

        prompt = {
            "task": "Analyze package security evidence for a coding agent.",
            "requirements": [
                "Do not change the verdict.",
                (
                    "Return JSON with keys: summary, attack_family, confidence, "
                    "false_positive_notes, agent_reason, evidence_refs."
                ),
                "Keep summary under 90 words.",
                "Use only evidence provided; do not invent findings.",
                (
                    "evidence_refs should point to evidence paths such as known_bad[0], "
                    "static.findings[0], behavior_chain[0], scoring.contributions[0]."
                ),
            ],
            "package": request.model_dump(),
            "verdict": verdict,
            "risk_score": score,
            "evidence": evidence.model_dump(),
        }
        payload = {
            "model": self.settings.openrouter_model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You explain package malware risk from provided evidence. "
                        "Return JSON only."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(prompt, default=str),
                },
            ],
            "response_format": {"type": "json_object"},
        }
        try:
            async with httpx.AsyncClient(timeout=self.settings.http_timeout_seconds) as client:
                response = await client.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.settings.openrouter_api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
            content = data["choices"][0]["message"]["content"]
            parsed = json.loads(content)
            summary = str(parsed.get("summary", "")).strip()
            return AIAnalysis(
                model=self.settings.openrouter_model,
                summary=summary or fallback_summary,
                attack_family=self._string_list(parsed.get("attack_family"))[:8],
                confidence=self._confidence(parsed.get("confidence")),
                false_positive_notes=str(parsed.get("false_positive_notes", ""))[:1000],
                agent_reason=str(parsed.get("agent_reason", ""))[:1000],
                evidence_refs=self._string_list(parsed.get("evidence_refs"))[:12],
            )
        except Exception as exc:
            return AIAnalysis(
                model=self.settings.openrouter_model,
                summary=fallback_summary,
                error=str(exc),
            )

    async def summarize(
        self,
        *,
        request: AnalyzePackageRequest,
        evidence: EvidenceBundle,
        fallback_summary: str,
        score: int,
        verdict: Verdict,
    ) -> str:
        return (
            await self.analyze(
                request=request,
                evidence=evidence,
                fallback_summary=fallback_summary,
                score=score,
                verdict=verdict,
            )
        ).summary

    @staticmethod
    def _confidence(value: object) -> str:
        normalized = str(value or "medium").lower()
        if normalized in {"low", "medium", "high"}:
            return normalized
        return "medium"

    @staticmethod
    def _string_list(value: object) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(item) for item in value]
        return [str(value)]
