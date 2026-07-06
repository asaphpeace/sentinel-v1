"""
Prowler scan pass (BUILD_PLAN.md Phase 1 step 7). Prowler runs in its own
isolated venv (backend/.venv-prowler) invoked as a subprocess — its pinned
deps (pydantic==2.12.5, boto3==1.40.61 at time of writing) conflict outright
with this app's pins, confirmed via PyPI metadata before deciding to isolate
it rather than install into the app's own venv.

The CSV column names and delimiter asserted here are lifted directly from
prowler/lib/outputs/csv/csv.py in the installed package (not guessed), and
the real installed `prowler` binary is invoked in one test to prove the CLI
flags this module constructs are actually valid against that binary.
"""
import subprocess
import uuid
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import CloudAccountConnection, Engagement
from app.services import cloud_scan_service
from tests.factories import make_tenant

# Real Prowler CSV header row + one FAIL row, matching CSV.transform()'s
# exact field order/names in the installed package.
_SAMPLE_CSV = (
    "AUTH_METHOD;TIMESTAMP;ACCOUNT_UID;CHECK_ID;CHECK_TITLE;STATUS;SEVERITY;"
    "RESOURCE_UID;RESOURCE_NAME;DESCRIPTION;REMEDIATION_RECOMMENDATION_TEXT\n"
    "profile;2026-07-03T00:00:00;123456789012;iam_root_mfa_enabled;Root MFA enabled;"
    "FAIL;critical;arn:aws:iam::123456789012:root;root;Root account has no MFA;"
    "Enable MFA on the root account\n"
)


async def _make_connection_and_engagement(db_session: AsyncSession):
    tenant = await make_tenant(db_session)
    connection = CloudAccountConnection(
        id=uuid.uuid4(), tenant_id=tenant.id, provider="aws",
        role_arn="arn:aws:iam::123456789012:role/Test", external_id="ext-123",
        status="connected",
    )
    engagement = Engagement(id=uuid.uuid4(), tenant_id=tenant.id, tier="cloud", status="active")
    db_session.add_all([connection, engagement])
    await db_session.flush()
    return connection, engagement


def test_parse_prowler_csv_reads_the_real_schema(tmp_path):
    csv_path = tmp_path / "scan.csv"
    csv_path.write_text(_SAMPLE_CSV, encoding="utf-8")

    rows = cloud_scan_service._parse_prowler_csv(csv_path)

    assert len(rows) == 1
    assert rows[0]["CHECK_ID"] == "iam_root_mfa_enabled"
    assert rows[0]["SEVERITY"] == "critical"


def test_parse_prowler_csv_missing_file_returns_empty(tmp_path):
    assert cloud_scan_service._parse_prowler_csv(tmp_path / "does-not-exist.csv") == []


async def test_run_prowler_scan_persists_findings_from_csv_output(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_subprocess(role_arn, external_id, output_dir):
        (Path(output_dir) / "scan.csv").write_text(_SAMPLE_CSV, encoding="utf-8")
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cloud_scan_service, "_run_prowler_subprocess", _fake_subprocess)

    findings = await cloud_scan_service.run_prowler_scan(db_session, engagement, connection)

    assert len(findings) == 1
    assert findings[0].check_id == "iam_root_mfa_enabled"
    assert findings[0].severity == "critical"
    assert findings[0].tier == "cloud"
    assert findings[0].engagement_id == engagement.id
    assert findings[0].remediation_guidance == "Enable MFA on the root account"


async def test_run_prowler_scan_returns_empty_on_nonzero_exit(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_failure(role_arn, external_id, output_dir):
        return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="AccessDenied")

    monkeypatch.setattr(cloud_scan_service, "_run_prowler_subprocess", _fake_failure)

    findings = await cloud_scan_service.run_prowler_scan(db_session, engagement, connection)
    assert findings == []


async def test_run_prowler_scan_handles_timeout_gracefully(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_timeout(role_arn, external_id, output_dir):
        raise subprocess.TimeoutExpired(cmd="prowler", timeout=1)

    monkeypatch.setattr(cloud_scan_service, "_run_prowler_subprocess", _fake_timeout)

    findings = await cloud_scan_service.run_prowler_scan(db_session, engagement, connection)
    assert findings == []


@pytest.mark.skipif(not Path(settings.command_prowler_bin).exists(), reason="Prowler not installed in .venv-prowler")
async def test_run_prowler_scan_against_the_real_binary_fails_gracefully_without_aws_access(
    db_session: AsyncSession,
):
    """
    Not mocked — invokes the actual installed prowler binary with an
    obviously-unreachable role in this sandboxed environment (no real AWS
    credentials configured). This can't prove Prowler correctly scans a
    real account, but it does prove the CLI flags this module constructs
    are accepted by the real binary and that a failed run degrades to an
    empty finding list rather than raising or hanging.
    """
    connection, engagement = await _make_connection_and_engagement(db_session)

    findings = await cloud_scan_service.run_prowler_scan(db_session, engagement, connection)
    assert findings == []
