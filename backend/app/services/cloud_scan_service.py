"""
Sentinel Command Tier 0 — cloud posture scanning.

Module boundary for CloudAccountConnection lifecycle (AWS role assumption
first; Azure/GCP follow once AWS proves the pipeline end-to-end — see
BUILD_PLAN.md Phase 1) and the two scan passes that populate Finding /
CloudPrivEscPath from a connected account:

  - Prowler: baseline CIS/best-practice checks -> Finding rows
  - Cloudsplaining / PMapper: IAM privilege-escalation graph -> CloudPrivEscPath rows

Function bodies are stubs (BUILD_PLAN.md Phase 1, not yet done) — signatures
and call shape are settled so routers/tests can be written against them now.
"""
from __future__ import annotations

import asyncio
import csv
import json
import logging
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import CloudAccountConnection, CloudPrivEscPath, Engagement, Finding

_log = logging.getLogger(__name__)


# ── Connection lifecycle ─────────────────────────────────────────────────────

def _trust_policy(external_id: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{settings.command_aws_account_id}:root"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
        }],
    }


def _cloudformation_template(external_id: str) -> str:
    # SecurityAudit + ViewOnlyAccess is the same read-only pairing
    # ARCHITECTURE.md's Tier 0 spec calls for — enough for Prowler/
    # Cloudsplaining/PMapper to enumerate and analyze, nothing that grants
    # write access to the customer's account.
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Sentinel Command read-only cloud posture scanning role",
        "Resources": {
            "SentinelCommandRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": "SentinelCommandReadOnly",
                    "AssumeRolePolicyDocument": _trust_policy(external_id),
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/SecurityAudit",
                        "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess",
                    ],
                },
            },
        },
        "Outputs": {
            "RoleArn": {"Value": {"Fn::GetAtt": ["SentinelCommandRole", "Arn"]}},
        },
    }, indent=2)


def generate_aws_connection_setup(external_id: str) -> dict:
    """Return the CloudFormation snippet + trust-policy detail a customer
    needs to create the cross-account role. external_id must be generated
    by the caller (per-connection, random) and embedded in the trust policy
    for confused-deputy protection — see the AWS docs on cross-account role
    assumption using a third party."""
    return {
        "trust_policy": json.dumps(_trust_policy(external_id), indent=2),
        "cloudformation_template": _cloudformation_template(external_id),
        "instructions": [
            "Deploy the CloudFormation template in the AWS account you want scanned.",
            "Copy the RoleArn output once the stack finishes creating.",
            "Paste that Role ARN back into Sentinel Command to complete the connection.",
        ],
    }


async def verify_aws_connection(db: AsyncSession, connection: CloudAccountConnection) -> bool:
    """Attempt sts:AssumeRole against connection.role_arn with the stored
    external_id. On success, flips connection.status to 'connected' and sets
    connected_at; on failure, flips it to 'error'. Never persists a
    credential — this only proves the role is assumable, the STS session
    itself is used in-place by the caller (Phase 1's scan passes) and
    discarded."""
    def _assume():
        sts = boto3.client("sts")
        return sts.assume_role(
            RoleArn=connection.role_arn,
            RoleSessionName="sentinel-command-verify",
            ExternalId=connection.external_id,
            DurationSeconds=900,
        )

    try:
        await asyncio.to_thread(_assume)
    except ClientError as e:
        _log.warning(
            "Cloud connection verify failed: connection_id=%s error=%s",
            connection.id, e.response.get("Error", {}).get("Code"),
        )
        connection.status = "error"
        await db.commit()
        return False

    connection.status = "connected"
    connection.connected_at = datetime.now(timezone.utc)
    await db.commit()
    return True


# ── Scan passes ───────────────────────────────────────────────────────────────

def _run_prowler_subprocess(role_arn: str, external_id: str, output_dir: str) -> subprocess.CompletedProcess:
    # Must be absolute: Windows' CreateProcess (unlike Path.exists()) doesn't
    # resolve a relative path against the current working directory the way
    # POSIX exec does — a relative command here fails with WinError 2 even
    # when the file genuinely exists at that relative location.
    prowler_bin = str(Path(settings.command_prowler_bin).resolve())
    cmd = [
        prowler_bin, "aws",
        "--role", role_arn,
        "--external-id", external_id,
        "--role-session-name", "sentinel-command-scan",
        "--status", "FAIL",  # only findings we'd actually persist
        "--output-formats", "csv",
        "--output-directory", output_dir,
        "--output-filename", "scan",
        "--no-banner",
        "--ignore-exit-code-3",  # exit 3 means "there are FAIL findings", not an error — verified against
        # prowler/__main__.py's own exit handling, not assumed from docs
    ]
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=settings.command_scan_timeout_seconds,
    )


def _parse_prowler_csv(csv_path: Path) -> list[dict]:
    if not csv_path.exists():
        return []
    with csv_path.open(newline="", encoding="utf-8") as f:
        # Semicolon-delimited — verified against prowler/lib/outputs/csv/csv.py,
        # which uses ";" specifically because AWS ARNs/resource lists contain commas.
        return list(csv.DictReader(f, delimiter=";"))


async def run_prowler_scan(
    db: AsyncSession, engagement: Engagement, connection: CloudAccountConnection
) -> list[Finding]:
    """Assume connection.role_arn (via Prowler's own --role/--external-id,
    using this host's ambient AWS credentials as the calling identity — the
    same resolution boto3.client("sts") uses in verify_aws_connection), run
    Prowler against the session in its isolated venv, persist one Finding
    per FAIL check. check_id is Prowler's own CheckID, so results map onto
    the Compliance Matrix's CIS-aligned frameworks for free."""
    with tempfile.TemporaryDirectory() as tmp:
        try:
            proc = await asyncio.to_thread(_run_prowler_subprocess, connection.role_arn, connection.external_id, tmp)
        except subprocess.TimeoutExpired:
            _log.warning("Prowler scan timed out: connection_id=%s", connection.id)
            return []

        if proc.returncode != 0:
            _log.warning(
                "Prowler scan failed: connection_id=%s returncode=%s stderr=%s",
                connection.id, proc.returncode, proc.stderr[-2000:],
            )
            return []

        rows = _parse_prowler_csv(Path(tmp) / "scan.csv")

    findings: list[Finding] = []
    for row in rows:
        finding = Finding(
            id=uuid.uuid4(),
            tenant_id=connection.tenant_id,
            engagement_id=engagement.id,
            asset_id=None,  # Tier 0 doesn't yet resolve RESOURCE_UID to a CloudAsset row — see BUILD_PLAN.md follow-up
            tier="cloud",
            severity=(row.get("SEVERITY") or "medium").lower(),
            title=row.get("CHECK_TITLE") or row.get("CHECK_ID") or "Unknown check",
            status="open",
            check_id=row.get("CHECK_ID"),
            detail=row.get("DESCRIPTION"),
            remediation_guidance=row.get("REMEDIATION_RECOMMENDATION_TEXT"),
        )
        db.add(finding)
        findings.append(finding)

    if findings:
        await db.commit()
    return findings


_CLOUDSPLAINING_SCRIPT = Path(__file__).resolve().parents[2] / "tools" / "cloudsplaining_privesc_scan.py"


def _run_cloudsplaining_subprocess(role_arn: str, external_id: str) -> subprocess.CompletedProcess:
    python_bin = str(Path(settings.command_iam_tools_python).resolve())
    cmd = [python_bin, str(_CLOUDSPLAINING_SCRIPT), "--role-arn", role_arn, "--external-id", external_id]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=settings.command_scan_timeout_seconds)


async def run_priv_esc_analysis(
    db: AsyncSession, engagement: Engagement, connection: CloudAccountConnection
) -> list[CloudPrivEscPath]:
    """Assume connection.role_arn (the script does this itself, same as
    Prowler's own --role/--external-id — see cloudsplaining_privesc_scan.py),
    run Cloudsplaining's policy analysis in its isolated venv, persist one
    CloudPrivEscPath per discovered principal -> admin escalation chain.
    PMapper does not run here — see command_iam_tools_python's config
    comment for why it was dropped rather than patched."""
    try:
        proc = await asyncio.to_thread(_run_cloudsplaining_subprocess, connection.role_arn, connection.external_id)
    except subprocess.TimeoutExpired:
        _log.warning("Cloudsplaining scan timed out: connection_id=%s", connection.id)
        return []

    if proc.returncode != 0:
        _log.warning(
            "Cloudsplaining scan failed: connection_id=%s returncode=%s stderr=%s",
            connection.id, proc.returncode, proc.stderr[-2000:],
        )
        return []

    try:
        rows = json.loads(proc.stdout)
    except json.JSONDecodeError:
        _log.warning("Cloudsplaining scan produced unparseable output: connection_id=%s", connection.id)
        return []

    paths: list[CloudPrivEscPath] = []
    for row in rows:
        path = CloudPrivEscPath(
            id=uuid.uuid4(),
            tenant_id=connection.tenant_id,
            engagement_id=engagement.id,
            cloud_account_connection_id=connection.id,
            source_principal_arn=row["principal_arn"],
            target_principal_arn="account-admin",  # Cloudsplaining's method covers "can reach admin-equivalent",
            # not a specific target principal the way a full graph tool like PMapper would resolve
            technique_chain=row.get("actions", []),
            severity=row.get("severity", "high"),
        )
        db.add(path)
        paths.append(path)

    if paths:
        await db.commit()
    return paths


async def rescan_connection(db: AsyncSession, engagement: Engagement, connection: CloudAccountConnection) -> None:
    """Entry point for the recurring APScheduler job (BUILD_PLAN.md Phase 1,
    step 9) — runs both passes and bumps connection.last_scanned_at. Callers
    must confirm engagement.status == 'active' immediately before invoking
    this, and workers must re-check it during long-running scans, not just
    once at the start — see ARCHITECTURE.md Section 6 on why Emergency Stop
    has to be enforced per-action."""
    await run_prowler_scan(db, engagement, connection)
    await run_priv_esc_analysis(db, engagement, connection)
    connection.last_scanned_at = datetime.now(timezone.utc)
    await db.commit()
