"""Tests for kill_switch_runbook.py. Inventories are synthetic and written in each test; ids are made up."""

from __future__ import annotations

from conftest import load_script, run_json, run_main, write_files, write_json

mod = load_script("agent-kill-switch-runbook", "kill_switch_runbook.py")
inventory_mod = load_script("nhi-inventory", "nhi_inventory.py")
APP = "00000000-0000-0000-0000-0000000000a1"
AS_OF = ["--as-of", "2026-10-05"]

INVENTORY = {
    "identities": [
        {
            "id": f"entra:{APP}",
            "type": "entra-app",
            "name": "invoice-agent",
            "owners": ["sam@example.com"],
            "refs": {"app_id": APP, "service_principal_id": "sp-a"},
            "credentials": [
                {"kind": "client-secret", "key_id": "****aaaa"},
                {"kind": "certificate", "key_id": "****bbbb"},
                {"kind": "federated", "key_id": "****cccc"},
            ],
            "assignments": [
                {"kind": "application-permission", "name": "Microsoft Graph: Mail.Send"},
                {"kind": "delegated-permission", "name": "Microsoft Graph: User.Read (all users)"},
            ],
        },
        {
            "id": "aws-user:ci-deployer",
            "type": "aws-iam-user",
            "name": "ci-deployer",
            "owners": [],
            "refs": {"user_name": "ci-deployer", "console_password": True},
            "credentials": [{"kind": "access-key", "key_id": "****MPLE"}],
            "assignments": [
                {"kind": "managed-policy", "name": "PowerUserAccess", "ref": "arn:aws:iam::aws:policy/PowerUserAccess"},
                {"kind": "group", "name": "deployers"},
            ],
        },
        {
            "id": "aws-role:agent-runtime",
            "type": "aws-iam-role",
            "name": "agent-runtime",
            "owners": ["ops@example.com"],
            "refs": {"role_name": "agent-runtime"},
            "credentials": [],
            "assignments": [{"kind": "inline-policy", "name": "s3-read"}],
        },
        {
            "id": "github-deploy-key:acme/site#42",
            "type": "github-deploy-key",
            "name": "release",
            "refs": {"repository": "acme/site", "deploy_key_id": 42},
            "credentials": [{"kind": "deploy-key", "key_id": "****42"}],
            "assignments": [{"kind": "repository-access", "name": "acme/site (read-write)"}],
        },
        {
            "id": "register:support-agent",
            "type": "agent",
            "name": "Support agent",
            "owners": ["kim@example.com"],
            "refs": {"platform": "the ticketing vendor", "gateway": "the MCP gateway"},
            "credentials": [{"kind": "api-key", "key_id": "****9z9z"}],
            "assignments": [
                {"kind": "declared-permission", "name": "tickets:write"},
                {"kind": "mystery-grant", "name": "something new"},
            ],
        },
    ]
}


def inv(tmp_path):
    return str(write_json(tmp_path, {"inventory.json": INVENTORY}) / "inventory.json")


def test_entra_runbook_order_and_coverage(tmp_path):
    rc, doc = run_json(mod, [inv(tmp_path), "--identity", f"entra:{APP}", *AS_OF])
    assert rc == 0 and doc["coverage"]["missing"] == []
    phases = [s["phase"] for s in doc["steps"]]
    assert phases == sorted(phases, key=mod.PHASES.index)
    assert phases[0] == "stop new actions" and phases[-1] == "confirm"
    assert "az ad sp update --id sp-a --set accountEnabled=false" in doc["steps"][0]["change"]
    secret = next(s for s in doc["steps"] if "credential client-secret ****aaaa" in s["covers"])
    assert "<key id ending aaaa>" in secret["change"] and secret["verify"].startswith("az ad app credential list")
    assert any("--cert" in s["change"] for s in doc["steps"] if "credential certificate ****bbbb" in s["covers"])


def test_aws_user_and_role_steps(tmp_path):
    rc, doc = run_json(mod, [inv(tmp_path), "--identity", "aws-user:ci-deployer", *AS_OF])
    assert rc == 0
    changes = " ".join(s["change"] for s in doc["steps"])
    assert "AWSDenyAll" in doc["steps"][0]["change"] and "delete-login-profile" in changes
    assert (
        "--status Inactive" in changes
        and "remove-user-from-group --user-name ci-deployer --group-name deployers" in changes
    )
    rc, doc = run_json(mod, [inv(tmp_path), "--identity", "aws-role:agent-runtime", *AS_OF])
    assert rc == 0
    assert "AWSRevokeOlderSessions" in doc["steps"][1]["change"]
    assert "delete-role-policy --role-name agent-runtime --policy-name s3-read" in doc["steps"][2]["change"]


def test_generic_runbook_and_uncovered_assignment_exits_1(tmp_path):
    rc, doc = run_json(mod, [inv(tmp_path), "--identity", "register:support-agent", *AS_OF])
    assert rc == 0 and doc["coverage"]["missing"] == []  # the generic access step covers every declared assignment
    gateway = next(s for s in doc["steps"] if s["phase"] == "gateway")
    assert "the MCP gateway" in gateway["title"]
    write_json(
        tmp_path,
        {
            "one.json": {
                "identities": [
                    dict(
                        INVENTORY["identities"][2],
                        assignments=[
                            {"kind": "inline-policy", "name": "s3-read"},
                            {"kind": "permission-boundary", "name": "edge"},
                        ],
                    )
                ]
            }
        },
    )
    rc, out, _ = run_main(mod, [str(tmp_path / "one.json"), "--identity", "aws-role:agent-runtime", *AS_OF])
    assert rc == 1 and "Not covered (add a manual step for each):" in out and "- permission-boundary edge" in out


def test_markdown_template_and_custom_template(tmp_path):
    rc, out, _ = run_main(
        mod, [inv(tmp_path), "--identity", "github-deploy-key:acme/site#42", *AS_OF, "--gateway", "the egress proxy"]
    )
    assert rc == 0 and out.startswith("# Kill switch runbook: release")
    assert "gh api -X DELETE repos/acme/site/keys/42" in out and "the egress proxy" in out
    assert "1 of 1" not in out and "2 of 2 credentials and assignments" in out
    write_files(tmp_path, {"t.md": "Runbook for {{identity}}\n{{steps}}\n{{coverage}}\n", "bad.md": "No steps here\n"})
    rc, out, _ = run_main(
        mod, [inv(tmp_path), "--identity", "aws-role:agent-runtime", "--template", str(tmp_path / "t.md")]
    )
    assert rc == 0 and out.startswith("Runbook for aws-role:agent-runtime")
    rc, out, _ = run_main(
        mod, [inv(tmp_path), "--identity", "aws-role:agent-runtime", "--template", str(tmp_path / "bad.md")]
    )
    assert rc == 1


def test_github_app_and_out_file(tmp_path):
    data = {
        "identities": [
            {
                "id": "github-app:deploy-bot",
                "type": "github-app",
                "name": "deploy-bot",
                "refs": {"installation_id": 7, "account": "acme"},
                "credentials": [],
                "assignments": [{"kind": "app-permission", "name": "contents:write"}],
            }
        ]
    }
    path = write_json(tmp_path, {"gh.json": data}) / "gh.json"
    target = tmp_path / "runbook.md"
    rc, stdout, _ = run_main(mod, [str(path), "--identity", "github-app:deploy-bot", "--out", str(target), *AS_OF])
    text = target.read_text(encoding="utf-8")
    assert rc == 0 and stdout == "" and "select(.id==7)" in text and "Suspend" in text


def test_works_on_real_inventory_output(tmp_path):
    exports = write_json(
        tmp_path / "exports",
        {
            "entra-applications.json": {
                "value": [
                    {
                        "appId": APP,
                        "displayName": "invoice-agent",
                        "owners": [{"userPrincipalName": "sam@example.com"}],
                        "passwordCredentials": [
                            {"keyId": "11111111-0000-0000-0000-00000000aaaa", "endDateTime": "2027-01-01T00:00:00Z"}
                        ],
                    }
                ]
            }
        },
    )
    inventory_path = tmp_path / "inventory.json"
    inventory_mod.main([str(exports), *AS_OF, "--json", "--out", str(inventory_path)])
    rc, doc = run_json(mod, [str(inventory_path), "--identity", f"entra:{APP}", *AS_OF])
    assert rc == 0 and doc["coverage"]["needed"] == ["credential client-secret ****aaaa"]


def test_bad_input_exits_2(tmp_path):
    assert run_main(mod, [inv(tmp_path), "--identity", "entra:nope"])[0] == 2
    assert run_main(mod, [str(tmp_path / "missing.json"), "--identity", "x"])[0] == 2
    write_files(tmp_path, {"bad.json": "{", "list.json": "[]"})
    assert run_main(mod, [str(tmp_path / "bad.json"), "--identity", "x"])[0] == 2
    assert run_main(mod, [str(tmp_path / "list.json"), "--identity", "x"])[0] == 2
    assert run_main(mod, [inv(tmp_path), "--identity", f"entra:{APP}", "--as-of", "today"])[0] == 2
    assert run_main(mod, [inv(tmp_path), "--identity", f"entra:{APP}", "--template", str(tmp_path / "no.md")])[0] == 2
