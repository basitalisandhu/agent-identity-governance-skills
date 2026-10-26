"""End-to-end chain: a leaked CI key, from inventory to switch-off, through the dispatcher on the bundled examples.

A key for the ci-deployer IAM user turns up in a ticket. The responder builds the inventory (nhi-inventory),
reconstructs what the identity did (agent-action-timeline), checks what the leaked key reached after the leak time
(leaked-credential-response), prepares the switch-off (agent-kill-switch-runbook), seals the timeline as evidence
(agent-audit-log-integrity) and, at quarter end, the recertification picks up the identity's owner problems
(agent-recertification). This test runs those steps through scripts/cli.py, as the container does, and checks that
the outputs agree with each other.
"""

from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts" / "cli.py"
EX = ROOT / "plugins" / "agent-identity-governance" / "examples"
AS_OF = ["--as-of", "2026-10-05"]
IDENTITY = "aws-user:ci-deployer"
LEAKED_AT = "2026-10-02T01:30:00Z"


def cli(*args: str) -> tuple[int, str]:
    proc = subprocess.run([sys.executable, str(CLI), *args], capture_output=True, text=True, timeout=60, cwd=ROOT)
    assert proc.returncode in (0, 1), f"{args[0]} exited {proc.returncode}: {proc.stderr}"
    return proc.returncode, proc.stdout


@pytest.fixture(scope="module")
def chain(tmp_path_factory):
    work = tmp_path_factory.mktemp("leak")
    inventory = work / "inventory.json"
    out = {"inventory_rc": cli("inventory", str(EX / "exports"), *AS_OF, "--json", "--out", str(inventory))[0]}
    out["inventory"] = json.loads(inventory.read_text(encoding="utf-8"))
    logs = ["--cloudtrail", str(EX / "logs" / "cloudtrail.json")]
    out["timeline"] = json.loads(
        cli("timeline", "--identity", "ci-deployer", *logs, "--allow-list", str(EX / "logs" / "allow.txt"), "--json")[1]
    )
    leak_args = ["--identity", IDENTITY, "--credential", "MPLE", "--leaked-at", LEAKED_AT, *logs, "--json"]
    out["leak"] = json.loads(cli("leaked-credential", str(inventory), *leak_args)[1])
    out["runbook"] = json.loads(cli("kill-switch", str(inventory), "--identity", IDENTITY, *AS_OF, "--json")[1])
    sheets = work / "sheets"
    recert_args = ["--attestations", str(EX / "attestations.csv"), "--users", str(EX / "users.json"), *AS_OF]
    out["recert"] = json.loads(cli("recertify", str(inventory), *recert_args, "--json", "--out", str(sheets))[1])
    out["tracking"] = list(csv.DictReader((sheets / "tracking.csv").open(encoding="utf-8")))
    out["work"] = work
    return out


def record(chain) -> dict:
    return next(i for i in chain["inventory"]["identities"] if i["id"] == IDENTITY)


def test_the_leak_and_the_timeline_tell_the_same_story(chain):
    outside = [e for e in chain["timeline"]["events"] if "outside-allow-list" in e["flags"]]
    after = {(e["time"], e["action"]) for e in chain["leak"]["events_after_leak"]}
    assert outside, "the example plants one action outside the allow list"
    assert all(e["time"] > LEAKED_AT for e in outside), "the out-of-policy action happened after the leak"
    assert {(e["time"], e["action"]) for e in outside} <= after
    assert set(chain["leak"]["new_source_ips"]) == {e["ip"] for e in outside}


def test_leak_response_rotates_the_credential_the_inventory_holds(chain):
    key_ids = {c["key_id"] for c in record(chain)["credentials"]}
    assert chain["leak"]["credential_in_inventory"] is True
    assert {c["key_id"] for c in chain["leak"]["credential"]} <= key_ids
    assert any("****MPLE" in step["credential"] for step in chain["leak"]["rotation_order"])


def test_runbook_covers_every_credential_and_assignment_in_the_inventory(chain):
    rec = record(chain)
    needed = set(chain["runbook"]["coverage"]["needed"])
    assert {f"credential {c['kind']} {c['key_id']}" for c in rec["credentials"]} <= needed
    assert {f"{a['kind']} {a['name']}" for a in rec["assignments"]} <= needed
    assert chain["runbook"]["coverage"]["missing"] == []


def test_recertification_carries_the_inventory_owner_flags(chain):
    no_owner = {i["id"] for i in chain["inventory"]["identities"] if "no-owner" in i["flags"]}
    flagged = {r["identity_id"] for r in chain["recert"]["identities"] if "no-owner" in r["flags"]}
    assert no_owner and no_owner == flagged
    assert {r["identity_id"] for r in chain["tracking"]} == {i["id"] for i in chain["inventory"]["identities"]}
    leaked = next(r for r in chain["recert"]["identities"] if r["identity_id"] == IDENTITY)
    assert "owner-left" in leaked["flags"], "the leaked identity's owner has left: the sheet says so"


def test_sealed_timeline_detects_an_edit(chain):
    events = chain["work"] / "timeline.jsonl"
    events.write_text("".join(json.dumps(e) + "\n" for e in chain["timeline"]["events"]), encoding="utf-8")
    sealed = chain["work"] / "timeline.sealed.jsonl"
    rc, text = cli("audit-chain", "seal", str(events))
    sealed.write_text(text, encoding="utf-8")
    rc, doc = cli("audit-chain", "verify", str(sealed), "--json")
    assert rc == 0 and json.loads(doc)["intact"] is True
    tampered = chain["work"] / "timeline.tampered.jsonl"
    tampered.write_text(text.replace("iam:CreateAccessKey", "s3:ListBuckets"), encoding="utf-8")
    rc, doc = cli("audit-chain", "verify", str(tampered), "--json")
    assert rc == 1 and "hash-mismatch" in [f["kind"] for f in json.loads(doc)["findings"]]
