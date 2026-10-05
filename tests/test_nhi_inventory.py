"""Tests for nhi_inventory.py. Every export is synthetic and written in the test; ids are made up."""

from __future__ import annotations

from conftest import load_script, run_json, run_main, write_files, write_json

mod = load_script("nhi-inventory", "nhi_inventory.py")
AS_OF = ["--as-of", "2026-10-05"]
APP_A = "00000000-0000-0000-0000-0000000000a1"
APP_B = "00000000-0000-0000-0000-0000000000b2"
MI = "00000000-0000-0000-0000-0000000000c3"

APPLICATIONS = {
    "value": [
        {
            "id": "obj-app-a",
            "appId": APP_A,
            "displayName": "invoice-agent",
            "createdDateTime": "2025-01-10T00:00:00Z",
            "owners": [{"userPrincipalName": "sam@example.com"}],
            "passwordCredentials": [
                {
                    "keyId": "11111111-0000-0000-0000-00000000aaaa",
                    "startDateTime": "2025-01-10T00:00:00Z",
                    "endDateTime": "2026-12-01T00:00:00Z",
                    "secretText": None,
                }
            ],
            "keyCredentials": [
                {
                    "keyId": "11111111-0000-0000-0000-00000000bbbb",
                    "startDateTime": "2026-06-01T00:00:00Z",
                    "endDateTime": "2027-06-01T00:00:00Z",
                    "usage": "Verify",
                }
            ],
        },
        {"id": "obj-app-b", "appId": APP_B, "displayName": "old-sync-bot", "createdDateTime": "2024-01-01T00:00:00Z"},
    ]
}
SERVICE_PRINCIPALS = {
    "value": [
        {"id": "sp-a", "appId": APP_A, "displayName": "invoice-agent", "servicePrincipalType": "Application"},
        {"id": "sp-b", "appId": APP_B, "displayName": "old-sync-bot", "servicePrincipalType": "Application"},
        {
            "id": "sp-c",
            "appId": MI,
            "displayName": "vm-runner",
            "servicePrincipalType": "ManagedIdentity",
            "tags": ["owner:platform@example.com"],
        },
    ]
}
SIGN_INS = {
    "value": [
        {"appId": APP_A, "lastSignInActivity": {"lastSignInDateTime": "2026-10-01T09:00:00Z"}},
        {
            "appId": APP_B,
            "applicationAuthenticationClientSignInActivity": {"lastSignInDateTime": "2026-03-01T09:00:00Z"},
        },
    ]
}


def entra_folder(tmp_path):
    return write_json(
        tmp_path / "exports",
        {
            "entra-applications.json": APPLICATIONS,
            "entra-service-principals.json": SERVICE_PRINCIPALS,
            "entra-sign-in-activity.json": SIGN_INS,
            "entra-resource-sps.json": {
                "value": [
                    {
                        "id": "res-graph",
                        "displayName": "Microsoft Graph",
                        "appRoles": [{"id": "role-1", "value": "Mail.Send"}],
                    }
                ]
            },
            "entra-app-role-assignments.json": {
                "value": [{"id": "asg-1", "principalId": "sp-a", "resourceId": "res-graph", "appRoleId": "role-1"}]
            },
        },
    )


def by_id(doc):
    return {i["id"]: i for i in doc["identities"]}


def test_entra_merges_app_and_service_principal_and_flags(tmp_path):
    rc, doc = run_json(mod, [str(entra_folder(tmp_path)), *AS_OF])
    assert rc == 1
    ids = by_id(doc)
    a = ids[f"entra:{APP_A}"]
    assert a["owners"] == ["sam@example.com"] and a["flags"] == []
    assert a["credential_count"] == 2 and a["oldest_credential_age_days"] == 633
    assert a["assignments"][0]["name"] == "Microsoft Graph: Mail.Send"
    assert ids[f"entra:{APP_B}"]["flags"] == ["no-owner", "dormant"]
    mi = ids[f"entra:{MI}"]
    assert mi["type"] == "entra-managed-identity" and mi["owners"] == ["platform@example.com"]
    assert mi["flags"] == ["never-used"]


def test_key_ids_are_masked_and_secret_text_never_appears(tmp_path):
    rc, out, _ = run_main(mod, [str(entra_folder(tmp_path)), *AS_OF, "--json"])
    assert "****aaaa" in out and "****bbbb" in out
    assert "11111111-0000-0000-0000-00000000aaaa" not in out and "secretText" not in out


def test_aws_users_roles_and_trust(tmp_path):
    details = {
        "UserDetailList": [
            {
                "UserName": "ci-deployer",
                "Arn": "arn:aws:iam::111122223333:user/ci-deployer",
                "CreateDate": "2025-02-01T00:00:00Z",
                "Tags": [{"Key": "Owner", "Value": "ops@example.com"}],
                "AttachedManagedPolicies": [
                    {"PolicyName": "PowerUserAccess", "PolicyArn": "arn:aws:iam::aws:policy/PowerUserAccess"}
                ],
            }
        ],
        "RoleDetailList": [
            {
                "RoleName": "agent-runtime",
                "Path": "/",
                "Arn": "arn:aws:iam::111122223333:role/agent-runtime",
                "CreateDate": "2025-05-01T00:00:00Z",
                "RoleLastUsed": {"LastUsedDate": "2026-10-04T00:00:00Z"},
                "AssumeRolePolicyDocument": {"Statement": [{"Principal": {"Service": "ecs-tasks.amazonaws.com"}}]},
            },
            {"RoleName": "AWSServiceRoleForSupport", "Path": "/aws-service-role/support.amazonaws.com/"},
        ],
    }
    keys = {
        "AccessKeyMetadata": [
            {
                "UserName": "ci-deployer",
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "Status": "Active",
                "CreateDate": "2025-02-01T00:00:00Z",
            }
        ]
    }
    report = (
        "user,arn,user_creation_time,password_enabled,access_key_1_active,access_key_1_last_rotated,"
        "access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date\n"
        "ci-deployer,arn,2025-02-01T00:00:00+00:00,false,true,2025-02-01T00:00:00+00:00,"
        "2026-04-01T00:00:00+00:00,false,N/A,N/A\n"
    )
    folder = write_json(tmp_path, {"aws-authorization-details.json": details, "aws-access-keys.json": keys})
    write_files(folder, {"aws-credential-report.csv": report})
    rc, doc = run_json(mod, [str(folder), *AS_OF])
    ids = by_id(doc)
    assert set(ids) == {"aws-user:ci-deployer", "aws-role:agent-runtime"}
    user = ids["aws-user:ci-deployer"]
    assert user["credentials"][0]["key_id"] == "****MPLE" and user["flags"] == ["dormant"]
    assert user["owners"] == ["ops@example.com"]
    role = ids["aws-role:agent-runtime"]
    assert role["trust"] == ["Service: ecs-tasks.amazonaws.com"] and role["flags"] == ["no-owner"]
    assert rc == 1
    _, doc = run_json(mod, [str(folder), *AS_OF, "--include-aws-managed-roles"])
    assert "aws-role:AWSServiceRoleForSupport" in by_id(doc)


def test_github_and_register_merge_owner_into_existing_identity(tmp_path):
    folder = write_json(
        tmp_path,
        {
            "github-installations.json": {
                "installations": [
                    {
                        "id": 7,
                        "app_slug": "deploy-bot",
                        "account": {"login": "acme"},
                        "created_at": "2026-01-01T00:00:00Z",
                        "permissions": {"contents": "write"},
                        "repository_selection": "selected",
                    }
                ]
            },
            "github-deploy-keys.json": [
                {
                    "id": 42,
                    "title": "release",
                    "created_at": "2026-02-01T00:00:00Z",
                    "read_only": False,
                    "repository": "acme/site",
                    "last_used": None,
                }
            ],
        },
    )
    write_files(
        folder,
        {
            "register.csv": "id,name,type,owner,purpose,permissions\n"
            "github-app:deploy-bot,,,lee@example.com,ship releases,\n"
            "support-agent,Support agent,agent,kim@example.com,answer tickets,tickets:read;kb:read\n"
        },
    )
    rc, doc = run_json(mod, [str(folder), *AS_OF])
    ids = by_id(doc)
    app = ids["github-app:deploy-bot"]
    assert app["owners"] == ["lee@example.com"] and app["purpose"] == "ship releases"
    assert {"kind": "app-permission", "name": "contents:write", "ref": ""} in app["assignments"]
    key = ids["github-deploy-key:acme/site#42"]
    assert key["flags"] == ["no-owner", "never-used"]
    reg = ids["register:support-agent"]
    assert [a["name"] for a in reg["assignments"]] == ["tickets:read", "kb:read"] and reg["flags"] == []
    assert rc == 1


def test_markdown_lists_flagged_identities_and_notes(tmp_path):
    folder = write_json(tmp_path, {"entra-applications.json": APPLICATIONS})
    rc, out, _ = run_main(mod, [str(folder), *AS_OF])
    assert rc == 1
    assert out.startswith("# Non-human identity inventory")
    assert "## Needs a person (1)" in out and "old-sync-bot" in out
    assert "Entra last use is unknown" in out
    assert "| unknown |" in out


def test_clean_inventory_exits_zero_and_out_writes_file(tmp_path):
    folder = write_files(
        tmp_path / "in", {"register.csv": "id,name,owner,last_used\nbot-1,Bot,amy@example.com,2026-10-01\n"}
    )
    out = tmp_path / "inventory.md"
    rc, stdout, _ = run_main(mod, [str(folder), *AS_OF, "--out", str(out)])
    assert rc == 0 and stdout == ""
    assert "Nothing flagged" in out.read_text(encoding="utf-8")


def test_redact_tokenises_owner_addresses(tmp_path):
    rc, doc = run_json(mod, [str(entra_folder(tmp_path)), *AS_OF, "--redact"])
    assert "sam@example.com" not in str(doc)
    assert by_id(doc)[f"entra:{APP_A}"]["owners"][0].endswith("@redacted.invalid")


def test_bad_input_exits_2(tmp_path):
    assert run_main(mod, [str(tmp_path / "missing"), *AS_OF])[0] == 2
    empty = tmp_path / "empty"
    empty.mkdir()
    assert run_main(mod, [str(empty), *AS_OF])[0] == 2
    write_files(tmp_path / "bad", {"entra-applications.json": "{not json"})
    rc, _, err = run_main(mod, [str(tmp_path / "bad"), *AS_OF])
    assert rc == 2 and "not valid JSON" in err
    write_files(tmp_path / "reg", {"register.csv": "name,owner\nx,y\n"})
    assert run_main(mod, [str(tmp_path / "reg"), *AS_OF])[0] == 2
    assert run_main(mod, [str(entra_folder(tmp_path)), "--as-of", "05/10/2026"])[0] == 2
