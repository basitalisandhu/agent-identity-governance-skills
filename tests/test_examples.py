"""The bundled examples (plugins/agent-identity-governance/examples) run exactly as each SKILL.md says.

The SKILL.md "To see the output first" commands are the newcomer's first run; these tests keep their exit codes and
the facts the text promises true.
"""

from __future__ import annotations

import json
import re

from conftest import ROOT, load_script, run_json, run_main

EX = ROOT / "plugins" / "agent-identity-governance" / "examples"
AS_OF = ["--as-of", "2026-10-05"]
inventory_mod = load_script("nhi-inventory", "nhi_inventory.py")


def inventory(tmp_path) -> str:
    out = tmp_path / "inventory.json"
    rc, _, _ = run_main(inventory_mod, [str(EX / "exports"), *AS_OF, "--json", "--out", str(out)])
    assert rc == 1
    return str(out)


def test_inventory_example(tmp_path):
    rc, doc = run_json(inventory_mod, [str(EX / "exports"), *AS_OF])
    assert rc == 1 and doc["summary"]["flagged"] == 3
    types = doc["summary"]["by_type"]
    assert types["entra-agent-blueprint"] == 1 and types["entra-agent-identity"] == 2
    _, out, _ = run_main(inventory_mod, [str(EX / "exports"), *AS_OF])
    assert "shared by 2 agent identities" in out


def test_entra_review_example():
    mod = load_script("entra-agent-id-review", "entra_agent_review.py")
    rc, doc = run_json(mod, [str(EX / "exports"), *AS_OF])
    assert rc == 1 and doc["summary"]["identities"] == 5
    inherited = [
        r["display_name"]
        for r in doc["reviewed"]
        if any(p.get("inherited") and p["permission"] == "Mail.Send" for p in r["application_permissions"])
    ]
    assert sorted(inherited) == ["ledger-agent-apac", "ledger-agent-emea"]


def test_radar_example():
    mod = load_script("credential-expiry-radar", "credential_expiry_radar.py")
    rc, doc = run_json(mod, [str(EX / "exports"), *AS_OF])
    assert rc == 1
    kinds = [r["kind"] for r in doc["credentials"]]
    assert kinds.count("client secret on agent blueprint, used by 2 agent identities") == 1


def test_recertification_example(tmp_path):
    mod = load_script("agent-recertification", "agent_recertification.py")
    argv = [inventory(tmp_path), "--attestations", str(EX / "attestations.csv"), "--users", str(EX / "users.json")]
    rc, doc = run_json(mod, [*argv, *AS_OF])
    flags = {r["identity_id"]: r["flags"] for r in doc["identities"]}
    assert rc == 1
    assert "removal-not-done" in flags["entra:00000000-0000-0000-0000-0000000000b2"]
    assert "owner-left" in flags["aws-user:ci-deployer"]


def test_connector_register_example():
    mod = load_script("connector-register", "connector_register.py")
    argv = [str(EX / "register.yaml"), "--tools", str(EX / "tools"), "--manifests", str(EX / "manifests"), *AS_OF]
    rc, doc = run_json(mod, argv)
    assert rc == 1
    assert sorted(f["rule"] for f in doc["findings"]) == [
        "review-overdue",
        "undeclared-permission",
        "unregistered-server",
        "unregistered-tool",
    ]


def test_timeline_example():
    mod = load_script("agent-action-timeline", "agent_action_timeline.py")
    logs = EX / "logs"
    argv = [
        "--identity",
        "ci-deployer",
        "--cloudtrail",
        str(logs / "cloudtrail.json"),
        "--allow-list",
        str(logs / "allow.txt"),
    ]
    rc, out, _ = run_main(mod, argv)
    assert rc == 1 and "iam:CreateAccessKey" in out and "Outside the allow list: 1" in out


def test_kill_switch_example(tmp_path):
    mod = load_script("agent-kill-switch-runbook", "kill_switch_runbook.py")
    rc, doc = run_json(mod, [inventory(tmp_path), "--identity", "entra:00000000-0000-0000-0000-0000000000e5", *AS_OF])
    assert rc == 0 and "microsoft.graph.agentIdentity" in doc["steps"][0]["change"]


def test_leaked_credential_example(tmp_path):
    mod = load_script("leaked-credential-response", "leaked_credential_response.py")
    argv = [
        inventory(tmp_path),
        "--identity",
        "aws-user:ci-deployer",
        "--credential",
        "MPLE",
        "--leaked-at",
        "2026-10-02T01:30:00Z",
        "--cloudtrail",
        str(EX / "logs" / "cloudtrail.json"),
    ]
    rc, out, _ = run_main(mod, argv)
    assert rc == 1 and "New source IP addresses: 203.0.113.77" in out


def test_examples_hold_no_full_key_ids_beyond_documentation_values():
    text = "".join(p.read_text(encoding="utf-8") for p in EX.rglob("*") if p.is_file())
    assert "secretText" not in text
    # the only AWS key id is AWS's own documentation example
    assert set(re.findall(r"AKIA[0-9A-Z]{16}", text)) <= {"AKIAIOSFODNN7EXAMPLE"}
    json.loads((EX / "exports" / "entra-applications.json").read_text(encoding="utf-8"))
