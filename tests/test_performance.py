"""Cost guards that do not depend on machine speed.

The deep pass of 2026-10-26 timed every script on the bundled examples scaled 10, 100, 1,000 and 3,000 times. Two
were quadratic: audit_chain.py coverage rebuilt the expected-id set once per logged id (193.83 s to 0.36 s on
100,000 log lines), entra-agent-id-review searched every service principal once per blueprint (4.89 s to 0.15 s at
3,000x) and agent-recertification filtered every identity once per owner sheet (11.96 s to 1.25 s at 3,000x).
These tests count the work instead of timing it, so they fail if a loop goes back to being nested.
"""

from __future__ import annotations

import json

from conftest import ROOT, load_script, run_main

EX = ROOT / "plugins" / "agent-identity-governance" / "examples"
AS_OF = ["--as-of", "2026-10-05"]


def blueprint_exports(folder, n):
    blueprints, sps = [], []
    for i in range(n):
        app = f"00000000-0000-0000-0000-{i:012x}"
        blueprints.append({"id": f"b{i}", "appId": app, "displayName": f"agent-blueprint-{i}"})
        sps.append({"id": f"s{i}", "appId": app, "displayName": f"agent-blueprint-{i}"})
        sps.append(
            {
                "id": f"a{i}",
                "appId": f"10000000-0000-0000-0000-{i:012x}",
                "displayName": f"agent-{i}",
                "@odata.type": "#microsoft.graph.agentIdentity",
                "agentIdentityBlueprintId": app,
            }
        )
    (folder / "entra-agent-blueprints.json").write_text(json.dumps({"value": blueprints}), encoding="utf-8")
    (folder / "entra-service-principals.json").write_text(json.dumps({"value": sps}), encoding="utf-8")
    return folder


def test_entra_review_reads_service_principals_once_per_pass(tmp_path, monkeypatch):
    mod = load_script("entra-agent-id-review", "entra_agent_review.py")
    calls = {"n": 0}
    real = mod.is_agent_type

    def counting(obj):
        calls["n"] += 1
        return real(obj)

    monkeypatch.setattr(mod, "is_agent_type", counting)
    n = 200
    rc, out, err = run_main(mod, [str(blueprint_exports(tmp_path, n)), *AS_OF, "--json"])
    assert rc in (0, 1), err
    assert len(json.loads(out)["reviewed"]) >= n
    # linear: a few passes over the 2n service principals; the nested loop made about n x 2n = 80,000 calls
    assert calls["n"] <= 10 * 2 * n


def test_recertification_groups_identities_once_for_all_sheets(tmp_path, monkeypatch):
    inv_mod = load_script("nhi-inventory", "nhi_inventory.py")
    inventory = tmp_path / "inventory.json"
    rc, _, err = run_main(inv_mod, [str(EX / "exports"), *AS_OF, "--json", "--out", str(inventory)])
    assert rc in (0, 1), err
    mod = load_script("agent-recertification", "agent_recertification.py")
    seen = []
    real = mod.sheet_markdown

    def checking(doc, owner, rows=None):
        seen.append(rows is not None)
        return real(doc, owner, rows)

    monkeypatch.setattr(mod, "sheet_markdown", checking)
    rc, _, err = run_main(mod, [str(inventory), *AS_OF, "--out", str(tmp_path / "sheets")])
    assert rc in (0, 1), err
    assert seen and all(seen), "every sheet gets its owner's rows, grouped once, instead of filtering all identities"


def test_audit_coverage_builds_the_expected_set_once(tmp_path, monkeypatch):
    mod = load_script("agent-audit-log-integrity", "audit_chain.py")
    n = 500
    log = tmp_path / "log.jsonl"
    log.write_text("".join(json.dumps({"tool_use_id": f"toolu_{i}"}) + "\n" for i in range(n)), encoding="utf-8")
    expected = tmp_path / "expected.txt"
    expected.write_text("".join(f"toolu_{i + 1}\n" for i in range(n)), encoding="utf-8")
    calls = {"n": 0}

    def counting_set(*args):
        calls["n"] += 1
        return set(*args)

    monkeypatch.setattr(mod, "set", counting_set, raising=False)
    rc, out, err = run_main(mod, ["coverage", str(log), "--expected", str(expected), "--json"])
    assert rc == 1, err
    doc = json.loads(out)
    assert doc["missing"] == [f"toolu_{n}"] and doc["not_expected"] == ["toolu_0"]
    assert calls["n"] < 10, f"set() built {calls['n']} times for {n} logged ids"
