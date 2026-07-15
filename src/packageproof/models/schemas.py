from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

Ecosystem = Literal["npm", "pypi"]
AnalysisDepth = Literal["quick", "standard", "deep"]
Verdict = Literal["allow", "review", "block"]
AgentAction = Literal["install_allowed", "manual_review_required", "do_not_install"]


class HealthResponse(BaseModel):
    status: str
    service: str
    payment_configured: bool
    x402_enabled: bool


class AnalyzePackageRequest(BaseModel):
    ecosystem: Ecosystem
    package: str = Field(min_length=1, max_length=214)
    version: str = Field(default="latest", min_length=1, max_length=128)
    analysis_depth: AnalysisDepth = "standard"
    include_ai_summary: bool = True

    @field_validator("package")
    @classmethod
    def normalize_package(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("package is required")
        return value

    @field_validator("version")
    @classmethod
    def normalize_version(cls, value: str) -> str:
        return value.strip() or "latest"


class EvidenceBundle(BaseModel):
    known_bad: list[dict[str, Any]] = Field(default_factory=list)
    registry: dict[str, Any] = Field(default_factory=dict)
    static: dict[str, Any] = Field(default_factory=dict)
    sandbox: dict[str, Any] = Field(default_factory=dict)
    network: dict[str, Any] = Field(default_factory=dict)
    filesystem: dict[str, Any] = Field(default_factory=dict)
    behavior_chain: list[dict[str, Any]] = Field(default_factory=list)


class AnalyzePackageResponse(BaseModel):
    report_id: str
    verdict: Verdict
    risk_score: int = Field(ge=0, le=100)
    agent_action: AgentAction
    attack_types: list[str]
    summary: str
    evidence: EvidenceBundle
    safer_alternatives: list[str]
    created_at: datetime


class RegistryResult(BaseModel):
    ecosystem: Ecosystem
    package: str
    requested_version: str
    resolved_version: str | None = None
    exists: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)
    source_url: str | None = None
    advisories: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class SourceArchive(BaseModel):
    files: dict[str, str] = Field(default_factory=dict)
    truncated: bool = False
    errors: list[str] = Field(default_factory=list)
