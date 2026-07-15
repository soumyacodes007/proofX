from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from packageproof.core.config import Settings
from packageproof.models.schemas import AnalyzePackageResponse


class ReportStore:
    def __init__(self, db_path: Path, cache_ttl_seconds: int) -> None:
        self.db_path = db_path
        self.cache_ttl = timedelta(seconds=cache_ttl_seconds)

    @classmethod
    def from_settings(cls, settings: Settings) -> ReportStore:
        return cls(settings.sqlite_path, settings.cache_ttl_seconds)

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS reports (
                    report_id TEXT PRIMARY KEY,
                    cache_key TEXT NOT NULL,
                    package_coordinates TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    response_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_reports_cache_key ON reports(cache_key, created_at)"
            )

    def get(self, report_id: str) -> AnalyzePackageResponse | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT response_json FROM reports WHERE report_id = ?",
                (report_id,),
            ).fetchone()
        if row is None:
            return None
        return AnalyzePackageResponse.model_validate_json(row["response_json"])

    def get_cached(self, cache_key: str) -> AnalyzePackageResponse | None:
        cutoff = datetime.now(UTC) - self.cache_ttl
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT response_json, created_at
                FROM reports
                WHERE cache_key = ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (cache_key,),
            ).fetchone()
        if row is None:
            return None
        created_at = datetime.fromisoformat(row["created_at"])
        if created_at < cutoff:
            return None
        return AnalyzePackageResponse.model_validate_json(row["response_json"])

    def save(
        self,
        *,
        cache_key: str,
        package_coordinates: dict[str, str],
        response: AnalyzePackageResponse,
    ) -> None:
        payload = response.model_dump_json()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO reports (
                    report_id,
                    cache_key,
                    package_coordinates,
                    verdict,
                    risk_score,
                    response_json,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    response.report_id,
                    cache_key,
                    json.dumps(package_coordinates, sort_keys=True),
                    response.verdict,
                    response.risk_score,
                    payload,
                    response.created_at.isoformat(),
                ),
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
