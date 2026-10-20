"""Tests for audit_chain.py (agent-audit-log-integrity).

Every test writes a synthetic agent action log into tmp_path, seals it, changes it the way an attacker or a broken
writer would, and checks what verify and coverage report. The HMAC key is a made-up test value written to tmp_path.
"""

from __future__ import annotations

import json

from conftest import load_script, run_main

mod = load_script("agent-audit-log-integrity", "audit_chain.py")


def actions(n=5, start_minute=0):
    return [
        {
            "ts": f"2026-10-19T22:{start_minute + i:02d}:00Z",
            "agent": "invoice-agent",
            "tool_use_id": f"toolu_{i:02d}",
            "tool": "mcp__erp__get_invoice",
        }
        for i in range(n)
    ]


def write_jsonl(path, records):
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return path


def sealed(tmp_path, records=None, key=None):
    raw = write_jsonl(tmp_path / "log.jsonl", records or actions())
    out = tmp_path / "log.sealed.jsonl"
    argv = ["seal", str(raw), "--out", str(out), "--json"]
    if key:
        kf = tmp_path / "key"
        kf.write_text(key, encoding="utf-8")
        argv += ["--key-file", str(kf)]
    rc, stdout, _ = run_main(mod, argv)
    assert rc == 0
    return out, json.loads(stdout)["head"]


def load(path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def verify(path, *more):
    rc, out, err = run_main(mod, ["verify", str(path), "--json", *more])
    return rc, (json.loads(out) if out else {"err": err})


def kinds(report):
    return [f["kind"] for f in report["findings"]]


def test_seal_then_verify_is_intact(tmp_path):
    path, head = sealed(tmp_path)
    recs = load(path)
    assert [r["_chain"]["seq"] for r in recs] == [0, 1, 2, 3, 4]
    assert recs[0]["_chain"]["prev"] == "0" * 64
    assert recs[1]["_chain"]["prev"] == recs[0]["_chain"]["hash"]
    assert head == f"4:{recs[-1]['_chain']['hash']}"
    rc, report = verify(path, "--head", head)
    assert rc == 0 and report["intact"] is True and report["findings"] == []


def test_edited_line_is_a_hash_mismatch(tmp_path):
    path, head = sealed(tmp_path)
    recs = load(path)
    recs[2]["tool"] = "mcp__mail__send_email"
    write_jsonl(path, recs)
    rc, report = verify(path, "--head", head)
    assert rc == 1
    assert report["findings"][0] == {
        "kind": "hash-mismatch",
        "line": 3,
        "detail": "sequence 2: content does not match its hash (edited, or the wrong key)",
    }


def test_deleted_line_is_a_gap(tmp_path):
    path, head = sealed(tmp_path)
    recs = load(path)
    del recs[1]
    write_jsonl(path, recs)
    rc, report = verify(path, "--head", head)
    assert rc == 1 and kinds(report) == ["seq-gap", "prev-mismatch"]


def test_reordered_lines(tmp_path):
    path, _ = sealed(tmp_path)
    recs = load(path)
    recs[1], recs[2] = recs[2], recs[1]
    write_jsonl(path, recs)
    rc, report = verify(path)
    assert rc == 1
    assert "prev-mismatch" in kinds(report) and "seq-backwards" in kinds(report)


def test_inserted_unsealed_and_damaged_lines(tmp_path):
    path, _ = sealed(tmp_path)
    text = path.read_text(encoding="utf-8").splitlines()
    text.insert(2, json.dumps({"ts": "2026-10-19T22:01:30Z", "tool": "Bash"}))
    text.append("{not json")
    path.write_text("\n".join(text) + "\n", encoding="utf-8")
    rc, report = verify(path)
    assert rc == 1
    assert "unsealed-line" in kinds(report) and "unparseable-line" in kinds(report)


def test_truncated_against_head_and_appended_is_information(tmp_path):
    path, head = sealed(tmp_path)
    recs = load(path)
    write_jsonl(path, recs[:3])
    rc, report = verify(path, "--head", head)
    assert rc == 1 and kinds(report) == ["truncated"]
    # Lines appended after the stored head are reported but are not a problem.
    path2, _ = sealed(tmp_path, actions(6))
    first5 = load(path2)[:5]
    head5 = f"4:{first5[-1]['_chain']['hash']}"
    rc, report = verify(path2, "--head", head5)
    assert rc == 0 and kinds(report) == ["appended"]


def test_hmac_key_wrong_key_and_missing_key(tmp_path):
    path, head = sealed(tmp_path, key="test-key-not-a-secret")
    good = tmp_path / "good"
    good.write_text("test-key-not-a-secret", encoding="utf-8")
    bad = tmp_path / "bad"
    bad.write_text("another-test-key", encoding="utf-8")
    assert verify(path, "--key-file", str(good), "--head", head)[0] == 0
    rc, report = verify(path, "--key-file", str(bad))
    assert rc == 1 and kinds(report).count("hash-mismatch") == 5
    rc, report = verify(path)
    assert rc == 1 and "key-needed" in kinds(report)
    assert "test-key" not in json.dumps(report)


def test_time_going_backwards(tmp_path):
    recs = actions(3)
    recs[2]["ts"] = "2026-10-19T21:00:00Z"
    path, _ = sealed(tmp_path, recs)
    rc, report = verify(path)
    assert rc == 1 and kinds(report) == ["time-backwards"]
    rc, report = verify(path, "--skew", "7200")
    assert rc == 0


def test_starts_mid_chain_and_continued_seal(tmp_path):
    path, head = sealed(tmp_path)
    recs = load(path)
    write_jsonl(path, recs[2:])
    rc, report = verify(path)
    assert rc == 1 and kinds(report) == ["starts-mid-chain"]
    more = write_jsonl(tmp_path / "more.jsonl", actions(2, start_minute=10))
    rc, out, _ = run_main(mod, ["seal", str(more), "--start-seq", "5", "--json", "--out", str(tmp_path / "m.jsonl")])
    assert rc == 0 and json.loads(out)["head"].startswith("6:")


def test_coverage_finds_unrecorded_actions(tmp_path):
    path, _ = sealed(tmp_path)
    session = tmp_path / "session.jsonl"
    rows = [{"type": "user", "message": {"role": "user", "content": "go"}}]
    rows += [
        {"type": "assistant", "message": {"content": [{"type": "tool_use", "id": f"toolu_{i:02d}", "name": "X"}]}}
        for i in range(7)
    ]
    write_jsonl(session, rows)
    rc, out, _ = run_main(mod, ["coverage", str(path), "--transcript", str(session), "--json"])
    report = json.loads(out)
    assert rc == 1 and report["missing"] == ["toolu_05", "toolu_06"] and report["logged"] == 5
    ids = tmp_path / "ids.txt"
    ids.write_text("toolu_00\ntoolu_01\n", encoding="utf-8")
    rc, out, _ = run_main(mod, ["coverage", str(path), "--expected", str(ids), "--id-field", "tool_use_id"])
    assert rc == 0 and "Recorded: 2 (100%)" in out and "`toolu_04` (line 5)" in out


def test_markdown_verify_report(tmp_path):
    path, _ = sealed(tmp_path)
    rc, out, _ = run_main(mod, ["verify", str(path)])
    assert rc == 0
    assert "Result: intact (0 problem(s))." in out and "## Findings" in out


def test_bad_inputs_exit_2(tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("\n\n", encoding="utf-8")
    assert run_main(mod, ["verify", str(empty)])[0] == 2
    junk = tmp_path / "junk.jsonl"
    junk.write_text("not json\n[1, 2]\n", encoding="utf-8")
    rc, _, err = run_main(mod, ["verify", str(junk)])
    assert rc == 2 and "no JSON object lines" in err
    assert run_main(mod, ["verify", str(tmp_path / "missing.jsonl")])[0] == 2
    path, _ = sealed(tmp_path)
    rc, _, err = run_main(mod, ["seal", str(path)])
    assert rc == 2 and "already carries _chain" in err
    assert run_main(mod, ["verify", str(path), "--head", "not-a-head"])[0] == 2
    blank = tmp_path / "blank.key"
    blank.write_text("  \n", encoding="utf-8")
    assert run_main(mod, ["verify", str(path), "--key-file", str(blank)])[0] == 2
    mixed = tmp_path / "mixed.jsonl"
    mixed.write_text('{"a": 1}\n[3]\n', encoding="utf-8")
    rc, _, err = run_main(mod, ["seal", str(mixed)])
    assert rc == 2 and "line 2" in err
    rc, _, err = run_main(mod, ["coverage", str(path)])
    assert rc == 2 and "no expected action ids" in err


def test_help_documents_exit_codes():
    rc, out, _ = run_main(mod, ["--help"])
    assert rc == 0 and "usage:" in out and "Exit codes: 0" in out
