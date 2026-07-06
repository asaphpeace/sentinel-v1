"""
Sentinel Command Tier 0 — cloud account connection lifecycle.
See BUILD_PLAN.md Phase 1 step 6 and ARCHITECTURE.md's CloudAccountConnection
spec. AWS-only for now; moto mocks STS/IAM so this exercises the real
boto3 assume-role call without touching a real AWS account.
"""
import json

import boto3
from httpx import AsyncClient
from moto import mock_aws
from sqlalchemy.ext.asyncio import AsyncSession

from tests.factories import make_tenant, make_user


async def test_create_connection_returns_aws_setup(auth_client):
    client, _tenant = auth_client
    resp = await client.post("/cloud-connections", json={"provider": "aws"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "pending_verification"
    assert body["external_id"]
    assert "AssumeRole" in body["trust_policy"]
    assert "SentinelCommandRole" in body["cloudformation_template"]
    assert len(body["instructions"]) == 3


async def test_create_connection_rejects_unsupported_provider(auth_client):
    client, _tenant = auth_client
    resp = await client.post("/cloud-connections", json={"provider": "azure"})
    assert resp.status_code == 400


async def test_list_connections_scoped_to_tenant(auth_client):
    client, _tenant = auth_client
    await client.post("/cloud-connections", json={"provider": "aws"})
    resp = await client.get("/cloud-connections")
    assert resp.status_code == 200
    assert len(resp.json()) == 1


async def test_verify_connection_succeeds_against_a_real_assumable_role(auth_client):
    # mock_aws as a decorator on an async def breaks pytest-asyncio's
    # coroutine detection (it wraps the function and pytest stops
    # recognizing it as async) — the context-manager form doesn't have
    # that problem.
    with mock_aws():
        client, _tenant = auth_client
        create_resp = await client.post("/cloud-connections", json={"provider": "aws"})
        connection = create_resp.json()
        external_id = connection["external_id"]

        # Create a role in the moto-mocked AWS account whose trust policy
        # matches what a real customer would deploy from our CloudFormation
        # template — same external_id condition, scoped to this test's
        # "calling" identity within moto's simulated account.
        iam = boto3.client("iam", region_name="us-east-1")
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
            }],
        }
        role = iam.create_role(
            RoleName="SentinelCommandReadOnly",
            AssumeRolePolicyDocument=json.dumps(trust_policy),
        )
        role_arn = role["Role"]["Arn"]

        resp = await client.post(f"/cloud-connections/{connection['id']}/verify", json={"role_arn": role_arn})
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "connected"
        assert body["role_arn"] == role_arn
        assert body["connected_at"] is not None


async def test_verify_connection_fails_for_nonexistent_role(auth_client, monkeypatch):
    # moto's assume_role doesn't actually validate that the target role
    # exists or that its trust policy matches (it'll happily hand back
    # credentials for an ARN nothing ever created) — real AWS STS returns
    # AccessDenied in that case. Rather than rely on moto's fidelity here,
    # force the real failure mode (a botocore ClientError) directly and
    # verify our own error handling: status flips to 'error', request
    # returns 400, no credential or exception leaks out.
    from botocore.exceptions import ClientError

    def _raise(*args, **kwargs):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "not authorized"}}, "AssumeRole")

    class _FakeSTS:
        assume_role = staticmethod(_raise)

    monkeypatch.setattr("app.services.cloud_scan_service.boto3.client", lambda *a, **k: _FakeSTS())

    client, _tenant = auth_client
    create_resp = await client.post("/cloud-connections", json={"provider": "aws"})
    connection = create_resp.json()

    fake_arn = "arn:aws:iam::123456789012:role/DoesNotExist"
    resp = await client.post(f"/cloud-connections/{connection['id']}/verify", json={"role_arn": fake_arn})
    assert resp.status_code == 400

    list_resp = await client.get("/cloud-connections")
    assert list_resp.json()[0]["status"] == "error"


async def test_connections_are_isolated_by_tenant(auth_client, client: AsyncClient, db_session: AsyncSession):
    owner_client, _owner_tenant = auth_client
    create_resp = await owner_client.post("/cloud-connections", json={"provider": "aws"})
    connection_id = create_resp.json()["id"]

    # A second, real user in a *different* tenant must not see or be able
    # to act on the first tenant's connection.
    other_tenant = await make_tenant(db_session, name="Other Workspace")
    await make_user(db_session, other_tenant, email="other@example.com", password="pass123")
    await db_session.flush()
    login = await client.post(
        "/auth/token",
        data={"username": "other@example.com", "password": "pass123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    other_client = client
    other_client.headers.update({"Authorization": f"Bearer {login.json()['access_token']}"})

    list_resp = await other_client.get("/cloud-connections")
    assert list_resp.json() == []

    verify_resp = await other_client.post(
        f"/cloud-connections/{connection_id}/verify", json={"role_arn": "arn:aws:iam::123456789012:role/X"}
    )
    assert verify_resp.status_code == 404
