from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from packageproof.models.schemas import AnalyzePackageRequest, RegistryResult

SignalSeverity = Literal["low", "medium", "high"]


@dataclass(frozen=True)
class NameSignal:
    type: str
    severity: SignalSeverity
    detail: str
    safer_alternative: str | None = None


POPULAR_PACKAGES = {
    "npm": {
        "axios",
        "browserslist",
        "chalk",
        "commander",
        "dotenv",
        "eslint",
        "express",
        "lodash",
        "next",
        "prettier",
        "react",
        "typescript",
        "vite",
        "webpack",
    },
    "pypi": {
        "boto3",
        "django",
        "fastapi",
        "flask",
        "litellm",
        "numpy",
        "openai",
        "pandas",
        "pydantic",
        "pytest",
        "requests",
        "setuptools",
        "urllib3",
    },
}

KNOWN_TYPOS = {
    "npm": {
        "browserlist": "browserslist",
        "lodahs": "lodash",
        "expres": "express",
        "typscript": "typescript",
    },
    "pypi": {
        "djagno": "django",
        "fast-api": "fastapi",
        "reqeusts": "requests",
        "requestes": "requests",
        "setuptool": "setuptools",
    },
}


class NameAttackDetector:
    def analyze(
        self,
        request: AnalyzePackageRequest,
        registry: RegistryResult,
    ) -> dict[str, object]:
        normalized = self._normalize(request.package, request.ecosystem)
        signals: list[NameSignal] = []

        known_target = KNOWN_TYPOS[request.ecosystem].get(normalized)
        if known_target:
            signals.append(
                NameSignal(
                    type="typosquatting",
                    severity="high",
                    detail=f"Package name is a known typo candidate for {known_target}",
                    safer_alternative=known_target,
                )
            )
        else:
            fuzzy_target = self._closest_popular_package(normalized, request.ecosystem)
            if fuzzy_target:
                distance = self._levenshtein(normalized, fuzzy_target)
                signals.append(
                    NameSignal(
                        type="typosquatting",
                        severity="medium",
                        detail=(
                            f"Package name is edit distance {distance} from popular "
                            f"package {fuzzy_target}"
                        ),
                        safer_alternative=fuzzy_target,
                    )
                )

        if self._looks_internal_name(normalized, request.ecosystem):
            signals.append(
                NameSignal(
                    type="dependency_confusion",
                    severity="medium",
                    detail="Package name looks internal or private but is registry-resolvable",
                )
            )

        if not registry.exists and self._looks_ai_plausible_name(normalized):
            signals.append(
                NameSignal(
                    type="slopsquatting",
                    severity="medium",
                    detail="Package name is plausible but unresolved in the public registry",
                )
            )

        return {
            "normalized_name": normalized,
            "signals": [signal.__dict__ for signal in signals],
            "safer_alternatives": sorted(
                {
                    signal.safer_alternative
                    for signal in signals
                    if signal.safer_alternative is not None
                }
            ),
        }

    @staticmethod
    def _normalize(package_name: str, ecosystem: str) -> str:
        normalized = package_name.strip().lower().replace("_", "-")
        if ecosystem == "npm" and normalized.startswith("@"):
            return normalized.split("/", maxsplit=1)[-1]
        return normalized

    def _closest_popular_package(self, package_name: str, ecosystem: str) -> str | None:
        if len(package_name) < 5:
            return None
        for candidate in POPULAR_PACKAGES[ecosystem]:
            if candidate == package_name:
                return None
            distance = self._levenshtein(package_name, candidate)
            threshold = 1 if len(candidate) <= 6 else 2
            if distance <= threshold:
                return candidate
        return None

    @staticmethod
    def _looks_internal_name(package_name: str, ecosystem: str) -> bool:
        internal_terms = {"corp", "internal", "private", "company", "enterprise"}
        parts = set(package_name.replace("@", "").replace("/", "-").split("-"))
        if parts & internal_terms:
            return True
        return ecosystem == "npm" and package_name.startswith("@") and "internal" in package_name

    @staticmethod
    def _looks_ai_plausible_name(package_name: str) -> bool:
        terms = package_name.split("-")
        security_or_agent_terms = {
            "agent",
            "ai",
            "chain",
            "crypto",
            "mcp",
            "openai",
            "sdk",
            "wallet",
        }
        return len(terms) >= 2 and bool(set(terms) & security_or_agent_terms)

    @staticmethod
    def _levenshtein(left: str, right: str) -> int:
        if left == right:
            return 0
        if not left:
            return len(right)
        if not right:
            return len(left)

        previous = list(range(len(right) + 1))
        for i, left_char in enumerate(left, start=1):
            current = [i]
            for j, right_char in enumerate(right, start=1):
                insertion = current[j - 1] + 1
                deletion = previous[j] + 1
                substitution = previous[j - 1] + (left_char != right_char)
                current.append(min(insertion, deletion, substitution))
            previous = current
        return previous[-1]
