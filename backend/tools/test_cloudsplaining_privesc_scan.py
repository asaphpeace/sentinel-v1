"""
Tests for cloudsplaining_privesc_scan.py's role-name -> ARN cross-
referencing logic. Requires `cloudsplaining` itself, which only exists in
backend/.venv-iam-tools — NOT part of the main app test suite (see
tests/test_cloudsplaining_scan.py for the plumbing tests that do run there).

Run manually from backend/:
    .venv-iam-tools/Scripts/python -m pytest tools/test_cloudsplaining_privesc_scan.py

Fixtures below are real get_account_authorization_details()-shaped input,
verified against actual Cloudsplaining output while building the script
(see its module docstring) — not guessed from documentation.
"""
from cloudsplaining.scan.authorization_details import AuthorizationDetails
from cloudsplaining.shared.exclusions import DEFAULT_EXCLUSIONS

from cloudsplaining_privesc_scan import find_privilege_escalation_paths


def test_resolves_role_name_to_arn_for_a_known_escalation():
    fixture = {
        "UserDetailList": [], "GroupDetailList": [],
        "RoleDetailList": [{
            "RoleName": "escalatable-role", "RoleId": "AROATEST123",
            "Arn": "arn:aws:iam::123456789012:role/escalatable-role", "Path": "/",
            "CreateDate": "2026-01-01T00:00:00Z",
            "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []},
            "InstanceProfileList": [],
            "RolePolicyList": [{
                "PolicyName": "escalation-policy",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": ["iam:CreatePolicyVersion", "iam:PassRole"],
                        "Resource": "*",
                    }],
                },
            }],
            "AttachedManagedPolicies": [], "Tags": [], "RoleLastUsed": {},
        }],
        "Policies": [],
    }

    auth_details = AuthorizationDetails(fixture, DEFAULT_EXCLUSIONS)
    paths = find_privilege_escalation_paths(auth_details.results)

    assert len(paths) == 1
    assert paths[0]["principal_arn"] == "arn:aws:iam::123456789012:role/escalatable-role"
    assert paths[0]["escalation_type"] == "CreateNewPolicyVersion"
    assert paths[0]["severity"] == "high"


def test_empty_for_a_role_with_no_escalation_potential():
    fixture = {
        "UserDetailList": [], "GroupDetailList": [],
        "RoleDetailList": [{
            "RoleName": "read-only-role", "RoleId": "AROATEST456",
            "Arn": "arn:aws:iam::123456789012:role/read-only-role", "Path": "/",
            "CreateDate": "2026-01-01T00:00:00Z",
            "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []},
            "InstanceProfileList": [],
            "RolePolicyList": [{
                "PolicyName": "read-only-policy",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::bucket/*"}],
                },
            }],
            "AttachedManagedPolicies": [], "Tags": [], "RoleLastUsed": {},
        }],
        "Policies": [],
    }

    auth_details = AuthorizationDetails(fixture, DEFAULT_EXCLUSIONS)
    assert find_privilege_escalation_paths(auth_details.results) == []
