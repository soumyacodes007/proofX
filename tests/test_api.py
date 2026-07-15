from __future__ import annotations

from fastapi.testclient import TestClient

from packageproof.core.config import Settings
from packageproof.main import create_app


def test_health(tmp_path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'test.db'}"))
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_report_not_found(tmp_path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'test.db'}"))
    client = TestClient(app)

    response = client.get("/v1/reports/rpt_missing")

    assert response.status_code == 404


def test_validation_rejects_unknown_ecosystem(tmp_path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'test.db'}"))
    client = TestClient(app)

    response = client.post(
        "/v1/analyze-package",
        json={"ecosystem": "rubygems", "package": "rails"},
    )

    assert response.status_code == 422
