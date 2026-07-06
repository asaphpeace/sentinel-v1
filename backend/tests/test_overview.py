"""
B2 + B3 + B4 — Overview endpoint tests.
Threat surface, portfolio certs, and report-data endpoints.
"""
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.factories import (
    make_tenant, make_user, make_domain, make_dmarc_aggregate,
)


# ── B2: Threat surface ─────────────────────────────────────────────────────────

async def test_threat_surface_empty_returns_has_data_false(auth_client):
    client, _ = auth_client
    resp = await client.get("/overview/threat-surface?days=30")
    assert resp.status_code == 200
    body = resp.json()
    assert body["has_data"] is False
    assert body["total_attempts"] == 0


async def test_threat_surface_with_data_returns_counts(
    client: AsyncClient, db_session: AsyncSession
):
    tenant = await make_tenant(db_session, name="Threat Corp")
    user = await make_user(db_session, tenant, email="threat@test.com", password="pass123")
    domain = await make_domain(db_session, tenant, dmarc_stage="reject")
    await make_dmarc_aggregate(
        db_session, domain,
        days_ago=3,
        source_ip="10.0.0.1",
        total_count=500,
        pass_count=50,
        fail_count=450,
        disposition="reject",
        classification="spoof",
    )
    await db_session.flush()

    resp = await client.post(
        "/auth/token",
        data={"username": "threat@test.com", "password": "pass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    token = resp.json()["access_token"]
    client.headers.update({"Authorization": f"Bearer {token}"})

    resp = await client.get("/overview/threat-surface?days=30")
    assert resp.status_code == 200
    body = resp.json()
    assert body["has_data"] is True
    assert body["total_attempts"] > 0


# ── B3: Portfolio certs ────────────────────────────────────────────────────────

async def test_all_certs_returns_list(auth_client):
    client, _ = auth_client
    resp = await client.get("/overview/certs")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


async def test_all_certs_requires_auth(client: AsyncClient, db_session: AsyncSession):
    resp = await client.get("/overview/certs")
    assert resp.status_code == 401


# ── B4: Report data ────────────────────────────────────────────────────────────

async def test_report_data_shape(auth_client):
    client, _ = auth_client
    resp = await client.get("/overview/report-data?period_days=30")
    assert resp.status_code == 200
    body = resp.json()

    required_keys = [
        "generated_at", "workspace_name", "period_days",
        "sentinel", "total_domains", "total_volume",
        "dmarc_reject_count", "dmarc_none_count",
        "cert_alerts", "threat", "domains", "cert_expiry_list",
    ]
    for key in required_keys:
        assert key in body, f"Missing key: {key}"


async def test_report_data_workspace_name_matches_tenant(
    client: AsyncClient, db_session: AsyncSession
):
    tenant = await make_tenant(db_session, name="Report Workspace")
    await make_user(db_session, tenant, email="report@test.com", password="pass123")
    await db_session.flush()

    resp = await client.post(
        "/auth/token",
        data={"username": "report@test.com", "password": "pass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    token = resp.json()["access_token"]
    client.headers.update({"Authorization": f"Bearer {token}"})

    resp = await client.get("/overview/report-data")
    assert resp.status_code == 200
    assert resp.json()["workspace_name"] == "Report Workspace"


async def test_report_data_period_days_param(auth_client):
    client, _ = auth_client
    for days in [30, 60, 90]:
        resp = await client.get(f"/overview/report-data?period_days={days}")
        assert resp.status_code == 200
        assert resp.json()["period_days"] == days


async def test_report_data_requires_auth(client: AsyncClient, db_session: AsyncSession):
    resp = await client.get("/overview/report-data")
    assert resp.status_code == 401
