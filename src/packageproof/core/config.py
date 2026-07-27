from __future__ import annotations

from functools import cached_property
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "PackageProof Pro"
    environment: str = "development"
    database_url: str = "sqlite:///./data/packageproof.db"

    x402_enabled: bool = False
    network: str = "eip155:196"
    pay_to_address: str = ""
    okx_api_key: str = ""
    okx_secret_key: str = ""
    okx_passphrase: str = ""
    okx_base_url: str = "https://web3.okx.com"
    analyze_package_price: str = "$0.05"
    x402_exempt_payers: str = ""

    e2b_api_key: str = ""
    enable_e2b: bool = False
    e2b_allow_internet_access: bool = True
    e2b_install_strace: bool = True
    e2b_template: str | None = None
    e2b_timeout_seconds: int = Field(default=90, ge=10, le=300)

    openrouter_api_key: str = ""
    openrouter_model: str = "openai/gpt-4.1-mini"

    cache_ttl_seconds: int = 60 * 60 * 24
    http_timeout_seconds: float = 15.0
    max_archive_bytes: int = 8 * 1024 * 1024
    max_static_files: int = 250

    @property
    def payment_configured(self) -> bool:
        return all(
            [
                self.pay_to_address,
                self.okx_api_key,
                self.okx_secret_key,
                self.okx_passphrase,
            ]
        )

    @property
    def x402_exempt_payer_list(self) -> list[str]:
        default_demo_payer = "0x3a2daf805449362147809cf600f6789b0f66e604"
        if self.x402_exempt_payers.strip().lower() in {"none", "false", "disabled"}:
            return []
        raw_payers = self.x402_exempt_payers.strip() or default_demo_payer
        return [
            payer.strip()
            for payer in raw_payers.split(",")
            if payer.strip()
        ]

    @cached_property
    def sqlite_path(self) -> Path:
        prefix = "sqlite:///"
        if not self.database_url.startswith(prefix):
            raise ValueError("Phase 1 supports sqlite database URLs only")
        return Path(self.database_url.removeprefix(prefix)).resolve()
