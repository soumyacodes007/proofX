from __future__ import annotations

import json

import httpx

from packageproof.core.config import Settings
from packageproof.models.schemas import AnalyzePackageRequest, EvidenceBundle, Verdict


class OpenRouterAnalyst:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def summarize(
        self,
        *,
        request: AnalyzePackageRequest,
        evidence: EvidenceBundle,
        fallback_summary: str,
        score: int,
        verdict: Verdict,
    ) -> str:
        if not self.settings.openrouter_api_key:
            return fallback_summary

        prompt = {
            "task": "Write a concise package security analyst summary for a coding agent.",
            "requirements": [
                "Do not change the verdict.",
                "Mention the strongest deterministic evidence.",
                "Mention likely false positive considerations when relevant.",
                "Keep it under 90 words.",
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
            return summary or fallback_summary
        except Exception:
            return fallback_summary
