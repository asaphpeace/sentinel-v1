"""
Runs inside backend/.venv-iam-tools (not the app's own venv — see
requirements-tools.txt for why Cloudsplaining/PMapper are isolated).

Assumes the target role, downloads the account's IAM authorization details,
and emits a flat JSON array of privilege-escalation findings to stdout —
deliberately NOT reusing Cloudsplaining's own nested export format (findings
are keyed by policy ID with role *names* under AttachedTo, not principal
ARNs directly; verified empirically against a real fixture while building
this, not assumed from docs).

Usage:
    python cloudsplaining_privesc_scan.py --role-arn <arn> --external-id <id>

Output shape:
    [{"principal_arn": "...", "escalation_type": "...", "actions": [...]}, ...]
"""
from __future__ import annotations

import argparse
import json
import sys

import boto3
from cloudsplaining.scan.authorization_details import AuthorizationDetails
from cloudsplaining.shared.exclusions import DEFAULT_EXCLUSIONS

_POLICY_SECTIONS = ("inline_policies", "customer_managed_policies", "aws_managed_policies")


def _assume_role_session(role_arn: str, external_id: str) -> boto3.Session:
    sts = boto3.client("sts")
    creds = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="sentinel-command-cloudsplaining",
        ExternalId=external_id,
        DurationSeconds=900,
    )["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def _fetch_authorization_details(session: boto3.Session) -> dict:
    iam = session.client("iam")
    merged = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
    for page in iam.get_paginator("get_account_authorization_details").paginate():
        for key in merged:
            merged[key].extend(page.get(key, []))
    return merged


def find_privilege_escalation_paths(results: dict) -> list[dict]:
    role_arn_by_name = {r["name"]: r["arn"] for r in results["roles"].values()}

    paths = []
    for section in _POLICY_SECTIONS:
        for policy in results.get(section, {}).values():
            privesc = policy.get("PrivilegeEscalation", {})
            findings = privesc.get("findings") or []
            if not findings:
                continue
            severity = privesc.get("severity", "high")  # Cloudsplaining rates this category "high" as of writing
            for role_name in policy.get("AttachedTo", {}).get("roles", []):
                role_arn = role_arn_by_name.get(role_name)
                if not role_arn:
                    continue
                for finding in findings:
                    paths.append({
                        "principal_arn": role_arn,
                        "escalation_type": finding.get("type"),
                        "actions": finding.get("actions", []),
                        "severity": severity,
                    })
    return paths


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role-arn", required=True)
    parser.add_argument("--external-id", required=True)
    args = parser.parse_args()

    session = _assume_role_session(args.role_arn, args.external_id)
    account_details = _fetch_authorization_details(session)
    auth_details = AuthorizationDetails(account_details, DEFAULT_EXCLUSIONS)
    paths = find_privilege_escalation_paths(auth_details.results)

    json.dump(paths, sys.stdout)


if __name__ == "__main__":
    main()
