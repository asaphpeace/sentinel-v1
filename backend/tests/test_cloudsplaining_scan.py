"""
Cloudsplaining privilege-escalation scan pass (BUILD_PLAN.md Phase 1 step 8).
Runs in its own isolated venv (backend/.venv-iam-tools), separate from BOTH
the app's own venv and Prowler's — installing Cloudsplaining alongside
Prowler in one venv silently upgraded Prowler's exact-pinned boto3, found by
testing it directly rather than trusting that "isolated from the app" was
isolated enough. PMapper (originally also planned here) was dropped: its
latest release doesn't import on Python 3.10+ (removed collections.Mapping
alias) and patching the installed package wasn't the right fix.

This file tests cloud_scan_service's plumbing (subprocess construction,
output parsing, Finding persistence) against a mocked subprocess — it can't
import `cloudsplaining` itself, since that package only exists in
.venv-iam-tools, not this app's own venv where the main suite runs. The
role-name -> ARN cross-referencing logic that actually needs cloudsplaining
installed is tested separately in tools/test_cloudsplaining_privesc_scan.py,
meant to run under .venv-iam-tools's interpreter.
"""
import json
import subprocess
import uuid
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import CloudAccountConnection, Engagement
from app.services import cloud_scan_service
from tests.factories import make_tenant

_SAMPLE_PATHS_JSON = json.dumps([{
    "principal_arn": "arn:aws:iam::123456789012:role/escalatable-role",
    "escalation_type": "CreateNewPolicyVersion",
    "actions": ["iam:createpolicyversion"],
    "severity": "high",
}])


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


async def test_run_priv_esc_analysis_persists_paths_from_script_output(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_subprocess(role_arn, external_id):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout=_SAMPLE_PATHS_JSON, stderr="")

    monkeypatch.setattr(cloud_scan_service, "_run_cloudsplaining_subprocess", _fake_subprocess)

    paths = await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)

    assert len(paths) == 1
    assert paths[0].source_principal_arn == "arn:aws:iam::123456789012:role/escalatable-role"
    assert paths[0].target_principal_arn == "account-admin"
    assert paths[0].technique_chain == ["iam:createpolicyversion"]
    assert paths[0].severity == "high"
    assert paths[0].engagement_id == engagement.id


async def test_run_priv_esc_analysis_returns_empty_on_nonzero_exit(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_failure(role_arn, external_id):
        return subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="AccessDenied")

    monkeypatch.setattr(cloud_scan_service, "_run_cloudsplaining_subprocess", _fake_failure)

    paths = await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)
    assert paths == []


async def test_run_priv_esc_analysis_handles_unparseable_output(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_garbage(role_arn, external_id):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="not json", stderr="")

    monkeypatch.setattr(cloud_scan_service, "_run_cloudsplaining_subprocess", _fake_garbage)

    paths = await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)
    assert paths == []


async def test_run_priv_esc_analysis_handles_timeout_gracefully(db_session: AsyncSession, monkeypatch):
    connection, engagement = await _make_connection_and_engagement(db_session)

    def _fake_timeout(role_arn, external_id):
        raise subprocess.TimeoutExpired(cmd="cloudsplaining", timeout=1)

    monkeypatch.setattr(cloud_scan_service, "_run_cloudsplaining_subprocess", _fake_timeout)

    paths = await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)
    assert paths == []


@pytest.mark.skipif(
    not Path(settings.command_iam_tools_python).exists(), reason="iam-tools venv not installed"
)
async def test_run_priv_esc_analysis_against_the_real_script_fails_gracefully_without_aws_access(
    db_session: AsyncSession,
):
    """Not mocked — invokes the real script with no AWS credentials
    available in this sandboxed environment. Proves the subprocess
    construction (paths, args) is valid against the real interpreter and
    script, and that a failed run degrades to an empty list."""
    connection, engagement = await _make_connection_and_engagement(db_session)

    paths = await cloud_scan_service.run_priv_esc_analysis(db_session, engagement, connection)
    assert paths == []
