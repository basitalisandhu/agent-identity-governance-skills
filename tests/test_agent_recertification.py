"""Tests for agent_recertification.py. Inventories, attestations and users are synthetic and written per test."""

from __future__ import annotations

import csv
import io

from conftest import load_script, run_json, run_main, write_files, write_json

mod = load_script("agent-recertification", "agent_recertification.py")
AS_OF = ["--as-of", "2026-10-05"]


def identity(ident, owners, assignments=(), creds=(), last_used="2026-10-01T00:00:00Z"):
    return {
        "id": ident,
        "name": ident.split(":")[-1],
        "type": "entra-app",
        "owners": list(owners),
        "last_used": last_used,
        "credentials": [{"key_id": k} for k in creds],
        "assignments": [{"kind": "application-permission", "name": a} for a in assignments],
        "trust": [],
    }


INVENTORY = {
    "identities": [
        identity("entra:invoice-agent", ["sam@example.com"], ["Graph: Mail.Send"], ["****aaaa", "****bbbb"]),
        identity("entra:sync-bot", ["lee@example.com"], ["Graph: User.Read.All"]),
        identity("register:helper", []),
        identity("aws-role:old-runner", ["kim@example.com"]),
    ]
}
PREVIOUS = {
    "identities": [
        identity("entra:invoice-agent", ["sam@example.com"], ["Graph: Mail.Read"], ["****aaaa"]),
        identity("entra:sync-bot", ["lee@example.com"], ["Graph: User.Read.All"]),
        identity("aws-role:old-runner", ["kim@example.com"]),
        identity("github-app:retired", ["amy@example.com"]),
    ]
}
ATTESTATIONS = """
    identity_id,owner,decision,attested_on,attested_by
    entra:invoice-agent,sam@example.com,keep,2026-02-01,sam@example.com
    entra:invoice-agent,sam@example.com,keep,2026-08-01,sam@example.com
    entra:sync-bot,lee@example.com,keep,2026-03-01,lee@example.com
    aws-role:old-runner,kim@example.com,remove,2026-09-01,kim@example.com
    """
USERS = {
    "value": [
        {"userPrincipalName": "sam@example.com", "accountEnabled": True},
        {"userPrincipalName": "kim@example.com", "accountEnabled": True},
        {"userPrincipalName": "lee@example.com", "accountEnabled": False},
    ]
}


def files(tmp_path):
    folder = write_json(tmp_path, {"inventory.json": INVENTORY, "previous.json": PREVIOUS, "users.json": USERS})
    write_files(folder, {"attestations.csv": ATTESTATIONS})
    return [
        str(folder / "inventory.json"),
        "--attestations",
        str(folder / "attestations.csv"),
        "--users",
        str(folder / "users.json"),
        "--previous-inventory",
        str(folder / "previous.json"),
        *AS_OF,
    ]


def by_id(doc):
    return {r["identity_id"]: r for r in doc["identities"]}


def test_flags_each_rule(tmp_path):
    rc, doc = run_json(mod, files(tmp_path))
    assert rc == 1
    rows = by_id(doc)
    assert rows["entra:invoice-agent"]["flags"] == []
    assert rows["entra:invoice-agent"]["last_attested"] == "2026-08-01"
    assert rows["entra:sync-bot"]["flags"] == ["owner-left", "attestation-stale"]
    assert rows["register:helper"]["flags"] == ["no-owner", "never-attested"]
    assert rows["aws-role:old-runner"]["flags"] == ["removal-not-done"]
    assert doc["quarter"] == "2026-Q4"


def test_changes_since_last_quarter(tmp_path):
    _, doc = run_json(mod, files(tmp_path))
    rows = by_id(doc)
    assert rows["entra:invoice-agent"]["changes"] == [
        "credential added ****bbbb",
        "gained application-permission: Graph: Mail.Send",
        "lost application-permission: Graph: Mail.Read",
    ]
    assert rows["register:helper"]["changes"] == ["new since last quarter"]
    assert doc["removed_since_last_quarter"] == ["github-app:retired"]


def test_sheets_route_to_owner_or_unassigned(tmp_path):
    out = tmp_path / "pack"
    rc, stdout, _ = run_main(mod, [*files(tmp_path), "--out", str(out)])
    assert rc == 1 and "Wrote 3 sheet(s)" in stdout
    names = sorted(p.name for p in out.iterdir())
    assert names == ["review-kim-example-com.md", "review-sam-example-com.md", "review-unassigned.md", "tracking.csv"]
    unassigned = (out / "review-unassigned.md").read_text(encoding="utf-8")
    assert "sync-bot" in unassigned and "helper" in unassigned
    sam = (out / "review-sam-example-com.md").read_text(encoding="utf-8")
    assert "What it can do: application-permission: Graph: Mail.Send" in sam
    assert "Decision (keep, reduce, remove), by whom and date: ____" in sam


def test_tracking_csv_columns_and_blank_decisions(tmp_path):
    out = tmp_path / "pack"
    run_main(mod, [*files(tmp_path), "--out", str(out), "--quarter", "FY27-Q2"])
    rows = list(csv.DictReader(io.StringIO((out / "tracking.csv").read_text(encoding="utf-8"))))
    assert [r["identity_id"] for r in rows] == sorted(r["identity_id"] for r in rows)
    first = rows[0]
    assert first["quarter"] == "FY27-Q2" and first["decision"] == "" and first["decided_by"] == ""
    sync = next(r for r in rows if r["identity_id"] == "entra:sync-bot")
    assert sync["owner"] == "unassigned" and sync["attestation_age_days"] == "218"


def test_csv_inventory_without_users_and_max_age(tmp_path):
    write_files(
        tmp_path,
        {
            "inv.csv": "id,name,type,owner,last_used,permissions\nbot-1,Bot,agent,amy@example.com,,a;b\n",
            "att.csv": "identity_id,decision,attested_on\nbot-1,keep,2026-09-01\n",
        },
    )
    rc, doc = run_json(mod, [str(tmp_path / "inv.csv"), "--attestations", str(tmp_path / "att.csv"), *AS_OF])
    assert rc == 0 and doc["identities"][0]["owner_status"] == "not checked"
    assert doc["identities"][0]["can_do"] == ["permission: a", "permission: b"]
    rc, doc = run_json(
        mod, [str(tmp_path / "inv.csv"), "--attestations", str(tmp_path / "att.csv"), *AS_OF, "--max-age", "30"]
    )
    assert rc == 1 and doc["identities"][0]["flags"] == ["attestation-stale"]


def test_stdout_has_summary_and_every_sheet(tmp_path):
    rc, out, _ = run_main(mod, files(tmp_path))
    assert out.startswith("# Agent and workload identity recertification 2026-Q4")
    assert out.count("# Recertification 2026-Q4:") == 3
    assert "| never-attested | 1 |" in out and "Gone since last quarter" in out


def test_bad_input_exits_2(tmp_path):
    write_files(
        tmp_path,
        {
            "inv.json": '{"identities": [{"name": "no id"}]}',
            "bad.json": "[",
            "att.csv": "identity_id,attested_on\nx,05/10/2026\n",
            "noid.csv": "name\nx\n",
        },
    )
    assert run_main(mod, [str(tmp_path / "inv.json"), *AS_OF])[0] == 2
    assert run_main(mod, [str(tmp_path / "bad.json"), *AS_OF])[0] == 2
    assert run_main(mod, [str(tmp_path / "missing.json"), *AS_OF])[0] == 2
    assert run_main(mod, [str(tmp_path / "noid.csv"), *AS_OF])[0] == 2
    write_json(tmp_path, {"ok.json": {"identities": []}})
    assert run_main(mod, [str(tmp_path / "ok.json"), "--attestations", str(tmp_path / "att.csv"), *AS_OF])[0] == 2
    assert run_main(mod, [str(tmp_path / "ok.json"), "--as-of", "soon"])[0] == 2
