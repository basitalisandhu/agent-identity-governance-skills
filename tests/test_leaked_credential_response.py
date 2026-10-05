"""Tests for leaked_credential_response.py. Inventories and audit exports are synthetic and written per test."""

from __future__ import annotations

import hashlib
import json

from conftest import load_script, run_json, run_main, write_files, write_json

mod = load_script("leaked-credential-response", "leaked_credential_response.py")
KEY = "AKIAIOSFODNN7EXAMPLE"

INVENTORY = {
    "identities": [
        {
            "id": "aws-user:ci-deployer",
            "type": "aws-iam-user",
            "name": "ci-deployer",
            "owners": ["ops@example.com"],
            "refs": {"user_name": "ci-deployer"},
            "credentials": [
                {"kind": "access-key", "key_id": "****MPLE", "created": "2026-01-01T00:00:00Z"},
                {"kind": "access-key", "key_id": "****NEW1", "created": "2026-10-02T03:00:00Z"},
            ],
            "assignments": [
                {"kind": "managed-policy", "name": "IAMFullAccess"},
                {"kind": "managed-policy", "name": "AmazonS3ReadOnlyAccess"},
            ],
            "trust": [],
        },
        {
            "id": "aws-user:reporting",
            "type": "aws-iam-user",
            "name": "reporting",
            "owners": ["amy@example.com"],
            "credentials": [
                {"kind": "access-key", "key_id": "****RPT9", "created": "2026-10-02T04:00:00Z"},
                {"kind": "access-key", "key_id": "****OLD8", "created": "2025-06-01T00:00:00Z"},
            ],
            "assignments": [],
        },
    ]
}


def cloudtrail_event(time, name, ip, key=KEY):
    return {
        "CloudTrailEvent": json.dumps(
            {
                "eventTime": time,
                "eventSource": "iam.amazonaws.com",
                "eventName": name,
                "sourceIPAddress": ip,
                "userIdentity": {"type": "IAMUser", "userName": "ci-deployer", "accessKeyId": key},
            }
        )
    }


def setup(tmp_path):
    folder = write_json(
        tmp_path / "in",
        {
            "inventory.json": INVENTORY,
            "ct.json": {
                "Events": [
                    cloudtrail_event("2026-09-30T10:00:00Z", "ListUsers", "192.0.2.10"),
                    cloudtrail_event("2026-10-02T02:00:00Z", "ListUsers", "203.0.113.50"),
                    cloudtrail_event("2026-10-02T03:00:00Z", "CreateAccessKey", "203.0.113.50"),
                    cloudtrail_event("2026-10-02T05:00:00Z", "GetUser", "192.0.2.10", key="KEYID00000000000NEW1"),
                ]
            },
        },
    )
    return folder, [
        str(folder / "inventory.json"),
        "--identity",
        "aws-user:ci-deployer",
        "--credential",
        "MPLE",
        "--leaked-at",
        "2026-10-02T01:30:00Z",
        "--cloudtrail",
        str(folder / "ct.json"),
    ]


def test_use_after_leak_new_ip_and_leaked_key(tmp_path):
    _, args = setup(tmp_path)
    rc, doc = run_json(mod, args)
    assert rc == 1
    assert doc["events_before_leak"] == 1 and len(doc["events_after_leak"]) == 3
    flags = {e["action"]: e["flags"] for e in doc["events_after_leak"]}
    assert flags["iam:CreateAccessKey"] == ["leaked-key", "new-source-ip"]
    assert flags["iam:GetUser"] == []
    assert doc["used_leaked_key"] == 2 and doc["new_source_ips"] == ["203.0.113.50"]


def test_reach_and_escalation(tmp_path):
    _, args = setup(tmp_path)
    _, doc = run_json(mod, args)
    assert doc["escalation_capable"] is True
    assert {r["what"]: r["escalation_capable"] for r in doc["reach"]} == {
        "managed-policy: IAMFullAccess": True,
        "managed-policy: AmazonS3ReadOnlyAccess": False,
    }


def test_rotation_order(tmp_path):
    _, args = setup(tmp_path)
    _, doc = run_json(mod, args)
    order = [(o["identity"], o["credential"]) for o in doc["rotation_order"]]
    assert order == [
        ("aws-user:ci-deployer", "access-key ****MPLE"),
        ("aws-user:ci-deployer", "access-key ****NEW1"),
        ("aws-user:reporting", "access-key ****RPT9"),
    ]
    assert doc["rotation_order"][1]["step"].startswith("remove: created after the leak time")


def test_evidence_folder_hashes_and_refuses_overwrite(tmp_path):
    folder, args = setup(tmp_path)
    out = tmp_path / "evidence"
    rc, stdout, _ = run_main(mod, [*args, "--out", str(out)])
    assert rc == 1
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    paths = [f["path"] for f in manifest["files"]]
    assert paths == [
        "checklist.md",
        "events-after-leak.json",
        "findings.json",
        "inputs/01-inventory.json",
        "inputs/02-ct.json",
    ]
    assert (out / "MANIFEST.md").exists()
    for f in manifest["files"]:
        assert hashlib.sha256((out / f["path"]).read_bytes()).hexdigest() == f["sha256"]
    assert (out / "inputs" / "02-ct.json").read_bytes() == (folder / "ct.json").read_bytes()
    digest = hashlib.sha256((out / "manifest.json").read_bytes()).hexdigest()
    assert f"SHA-256 of manifest.json: {digest}" in stdout
    assert run_main(mod, [*args, "--out", str(out)])[0] == 2


def test_checklist_masks_keys_and_has_sections(tmp_path):
    _, args = setup(tmp_path)
    rc, out, _ = run_main(mod, args)
    assert KEY not in out and "KEYID00000000000NEW1" not in out
    for heading in (
        "## 1. Contain",
        "## 2. Scope",
        "## 3. Use after the leak",
        "## 4. Rotate, in this order",
        "## 5. Prove no further use",
        "## 6. Record",
    ):
        assert heading in out
    assert "IAMFullAccess (escalation-capable)" in out


def test_quiet_case_and_unknown_credential(tmp_path):
    folder, args = setup(tmp_path)
    quiet = list(args)
    quiet[quiet.index("--leaked-at") + 1] = "2026-10-03"
    write_json(
        folder,
        {
            "inv2.json": {
                "identities": [
                    dict(
                        INVENTORY["identities"][0],
                        credentials=[INVENTORY["identities"][0]["credentials"][0]],
                        assignments=[],
                    )
                ]
            }
        },
    )
    quiet[0] = str(folder / "inv2.json")
    rc, doc = run_json(mod, quiet)
    assert (
        rc == 0 and doc["events_after_leak"] == [] and doc["rotation_order"][0]["credential"] == "access-key ****MPLE"
    )
    rc, doc = run_json(mod, [*quiet[:4], "ZZZZ", *quiet[5:]])
    assert rc == 1 and doc["credential_in_inventory"] is False


def test_match_values_and_app_log(tmp_path):
    folder = write_json(
        tmp_path,
        {
            "inv.json": {
                "identities": [
                    {"id": "register:helper", "type": "agent", "name": "helper", "credentials": [], "assignments": []}
                ]
            }
        },
    )
    write_files(
        folder,
        {"app.jsonl": json.dumps({"ts": "2026-10-04T00:00:00Z", "client_id": "client-77", "action": "export"}) + "\n"},
    )
    base = [
        str(folder / "inv.json"),
        "--identity",
        "register:helper",
        "--credential",
        "abcd",
        "--leaked-at",
        "2026-10-01",
        "--app-log",
        str(folder / "app.jsonl"),
    ]
    _, doc = run_json(mod, base)
    assert doc["events_matched"] == 0
    _, doc = run_json(mod, [*base, "--match", "client-77"])
    assert [e["action"] for e in doc["events_after_leak"]] == ["app:export"]


def test_bad_input_exits_2(tmp_path):
    _, args = setup(tmp_path)
    bad_time = list(args)
    bad_time[bad_time.index("--leaked-at") + 1] = "yesterday"
    assert run_main(mod, bad_time)[0] == 2
    wrong = list(args)
    wrong[wrong.index("--identity") + 1] = "aws-user:nobody"
    assert run_main(mod, wrong)[0] == 2
    write_files(tmp_path, {"bad.json": "{", "file.txt": "x"})
    assert run_main(mod, [str(tmp_path / "bad.json"), *args[1:]])[0] == 2
    assert run_main(mod, [*args, "--out", str(tmp_path / "file.txt")])[0] == 2
    assert run_main(mod, [*args[:-2], "--cloudtrail", str(tmp_path / "missing.json")])[0] == 2
