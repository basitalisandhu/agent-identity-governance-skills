"""Tests for agent_action_timeline.py. Audit exports are synthetic and written in each test; ids are made up."""

from __future__ import annotations

import json

from conftest import load_script, run_json, run_main, write_files, write_json

mod = load_script("agent-action-timeline", "agent_action_timeline.py")
APP = "00000000-0000-0000-0000-0000000000a1"
ROLE_ARN = "arn:aws:sts::111122223333:assumed-role/agent-runtime/session-1"


def exports(tmp_path):
    signins = {
        "value": [
            {
                "createdDateTime": "2026-10-01T09:00:00Z",
                "appId": APP,
                "resourceDisplayName": "Microsoft Graph",
                "ipAddress": "192.0.2.10",
                "status": {"errorCode": 0},
            },
            {
                "createdDateTime": "2026-10-01T09:05:00Z",
                "appId": "someone-else",
                "resourceDisplayName": "Microsoft Graph",
            },
        ]
    }
    audit = {
        "value": [
            {
                "activityDateTime": "2026-10-01T09:10:00.1234567Z",
                "activityDisplayName": "Add member to group",
                "initiatedBy": {"app": {"appId": APP, "displayName": "invoice-agent"}},
                "targetResources": [{"displayName": "Finance"}],
                "result": "success",
            }
        ]
    }
    inner = {
        "eventTime": "2026-10-01T08:59:00Z",
        "eventSource": "s3.amazonaws.com",
        "eventName": "GetObject",
        "sourceIPAddress": "198.51.100.7",
        "userIdentity": {
            "arn": ROLE_ARN,
            "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "sessionContext": {"sessionIssuer": {"userName": "agent-runtime"}},
        },
    }
    denied = dict(inner, eventName="DeleteBucket", eventTime="2026-10-01T09:20:00Z", errorCode="AccessDenied")
    cloudtrail = {"Events": [{"CloudTrailEvent": json.dumps(inner)}, {"CloudTrailEvent": json.dumps(denied)}]}
    # gh api --paginate --slurp saves a list of pages, each a list of events
    github = [
        [{"@timestamp": 1790847600000, "action": "repo.create", "actor": "invoice-agent[bot]", "repo": "acme/new"}]
    ]
    folder = write_json(
        tmp_path, {"signins.json": signins, "audit.json": audit, "ct.json": cloudtrail, "gh.json": github}
    )
    app_log = "\n".join(
        json.dumps(x)
        for x in [
            {
                "ts": "2026-10-01T09:30:00+10:00",
                "agent": "invoice-agent",
                "tool": "send_email",
                "target": "ap@example.com",
            },
            {"time": "2026-10-01T09:31:00Z", "agent": "other-agent", "tool": "send_email"},
        ]
    )
    write_files(folder, {"app.jsonl": app_log + "\n"})
    return folder


def args_for(folder):
    return [
        "--identity",
        APP,
        "--identity",
        "agent-runtime",
        "--identity",
        "invoice-agent[bot]",
        "--identity",
        "invoice-agent",
        "--entra-signins",
        str(folder / "signins.json"),
        "--entra-audit",
        str(folder / "audit.json"),
        "--cloudtrail",
        str(folder / "ct.json"),
        "--github-audit",
        str(folder / "gh.json"),
        "--app-log",
        str(folder / "app.jsonl"),
    ]


def test_filters_normalises_and_orders(tmp_path):
    rc, doc = run_json(mod, args_for(exports(tmp_path)))
    assert rc == 0
    got = [(e["time"], e["action"]) for e in doc["events"]]
    assert got == [
        ("2026-09-30T23:30:00Z", "app:send_email"),
        ("2026-10-01T08:59:00Z", "s3:GetObject"),
        ("2026-10-01T09:00:00Z", "signin:Microsoft Graph"),
        ("2026-10-01T09:10:00Z", "entra:Add member to group"),
        ("2026-10-01T09:20:00Z", "s3:DeleteBucket"),
        ("2026-10-01T09:40:00Z", "github:repo.create"),
    ]
    assert doc["summary"]["by_source"] == {
        "app-log": 1,
        "cloudtrail": 2,
        "entra-audit": 1,
        "entra-signin": 1,
        "github-audit": 1,
    }


def test_key_ids_masked_and_failures_marked(tmp_path):
    rc, out, _ = run_main(mod, [*args_for(exports(tmp_path)), "--json"])
    assert "AKIAIOSFODNN7EXAMPLE" not in out and "****MPLE" in out
    doc = json.loads(out)
    delete = next(e for e in doc["events"] if e["action"] == "s3:DeleteBucket")
    assert delete["failed"] and "failed" in delete["flags"] and doc["summary"]["failed"] == 1


def test_allow_list_flags_actions_outside_it(tmp_path):
    folder = exports(tmp_path)
    write_files(folder, {"allow.txt": "# what the agent may do\ns3:Get*\nsignin:*\napp:send_email\n"})
    rc, doc = run_json(mod, [*args_for(folder), "--allow-list", str(folder / "allow.txt")])
    assert rc == 1
    outside = [e["action"] for e in doc["events"] if "outside-allow-list" in e["flags"]]
    assert outside == ["entra:Add member to group", "s3:DeleteBucket", "github:repo.create"]


def test_baseline_first_seen_and_window(tmp_path):
    folder = exports(tmp_path)
    write_files(
        folder,
        {
            "base.txt": "s3:GetObject\nsignin:Microsoft Graph\napp:send_email\nentra:Add member to group\n"
            "github:repo.create\n"
        },
    )
    rc, doc = run_json(mod, [*args_for(folder), "--baseline", str(folder / "base.txt")])
    assert rc == 1 and [e["action"] for e in doc["events"] if "first-seen" in e["flags"]] == ["s3:DeleteBucket"]
    rc, doc = run_json(mod, [*args_for(folder), "--since", "2026-10-01T09:00:00Z", "--until", "2026-10-01T09:15:00Z"])
    assert [e["action"] for e in doc["events"]] == ["signin:Microsoft Graph", "entra:Add member to group"]
    assert all("first-in-window" in e["flags"] for e in doc["events"]) and rc == 0


def test_bursts(tmp_path):
    lines = [
        json.dumps({"timestamp": f"2026-10-02T10:00:{s:02d}Z", "agent": "bot-1", "action": "read"}) for s in range(25)
    ]
    lines.append(json.dumps({"timestamp": "2026-10-02T11:00:00Z", "agent": "bot-1", "action": "read"}))
    write_files(tmp_path, {"app.jsonl": "\n".join(lines) + "\n"})
    rc, doc = run_json(mod, ["--identity", "BOT-1", "--app-log", str(tmp_path / "app.jsonl")])
    assert rc == 1 and doc["bursts"] == [{"start": "2026-10-02T10:00:00Z", "end": "2026-10-02T10:00:24Z", "events": 25}]
    assert "burst" not in doc["events"][-1]["flags"]
    rc, doc = run_json(mod, ["--identity", "bot-1", "--app-log", str(tmp_path / "app.jsonl"), "--burst-count", "30"])
    assert rc == 0 and doc["bursts"] == []


def test_markdown_output_and_out_file(tmp_path):
    folder = exports(tmp_path)
    rc, out, _ = run_main(mod, args_for(folder))
    assert (
        out.startswith("# Agent action timeline") and "| 2026-10-01T09:20:00Z | cloudtrail | s3:DeleteBucket |" in out
    )
    assert "not checked (no --allow-list)" in out
    target = tmp_path / "timeline.md"
    rc, stdout, _ = run_main(
        mod, ["--identity", "nobody", "--app-log", str(folder / "app.jsonl"), "--out", str(target)]
    )
    assert rc == 0 and stdout == "" and "no event matched" in target.read_text(encoding="utf-8")


def test_bad_input_exits_2(tmp_path):
    write_files(tmp_path, {"bad.jsonl": '{"ts": 1}\nnot json\n', "bad.json": "{", "list.jsonl": "[1]\n"})
    assert run_main(mod, ["--identity", "x"])[0] == 2
    assert run_main(mod, ["--identity", "x", "--app-log", str(tmp_path / "bad.jsonl")])[0] == 2
    assert run_main(mod, ["--identity", "x", "--app-log", str(tmp_path / "list.jsonl")])[0] == 2
    assert run_main(mod, ["--identity", "x", "--cloudtrail", str(tmp_path / "bad.json")])[0] == 2
    assert run_main(mod, ["--identity", "x", "--cloudtrail", str(tmp_path / "missing.json")])[0] == 2
    write_json(tmp_path, {"ok.json": {"Records": []}})
    assert run_main(mod, ["--identity", "x", "--cloudtrail", str(tmp_path / "ok.json"), "--since", "soon"])[0] == 2
    assert run_main(mod, [])[0] == 2
