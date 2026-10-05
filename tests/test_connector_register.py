"""Tests for connector_register.py. Registers, tool listings and manifests are synthetic and written per test."""

from __future__ import annotations

from conftest import load_script, run_json, run_main, write_files, write_json

mod = load_script("connector-register", "connector_register.py")
AS_OF = ["--as-of", "2026-10-05"]

YAML = """
    # Approved connectors, reviewed by the platform team
    connectors:
      - name: tickets-mcp
        kind: mcp-server
        owner: sam@example.com
        purpose: "read and update support tickets"   # quoted, with a comment
        data_classification: confidential
        permissions: [tickets:read, tickets:write]
        review_date: 2026-12-01
        tools:
          - list_tickets
          - update_ticket
      - name: wiki-search
        kind: connector
        owner: ''
        purpose: search the wiki
        data_classification: secret
        permissions: wiki.read
        review_date: 2026-09-01
      - name: old-files-mcp
        kind: mcp-server
        owner: lee@example.com
        purpose: file share access
        data_classification: internal
        permissions:
          - files:read
        review_date: 2027-01-01
    """


def setup(tmp_path):
    folder = write_files(tmp_path, {"register.yaml": YAML})
    write_json(
        folder,
        {
            "tools/tickets-mcp.json": {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"tools": [{"name": "list_tickets"}, {"name": "delete_ticket"}]},
            },
            "tools/shadow-mcp.json": [{"tools": [{"name": "run_shell"}]}, {"tools": [{"name": "read_file"}]}],
            "manifests/tickets-mcp.json": {"name": "tickets-mcp", "scopes": ["tickets:read", "users:read"]},
        },
    )
    return [str(folder / "register.yaml"), "--tools", str(folder / "tools"), "--manifests", str(folder / "manifests")]


def rules(doc, name=None):
    return sorted((f["name"], f["rule"]) for f in doc["findings"] if name in (None, f["name"]))


def test_yaml_subset_is_read(tmp_path):
    _, doc = run_json(mod, [*setup(tmp_path), *AS_OF])
    tickets = doc["entries"][0]
    assert tickets["purpose"] == "read and update support tickets"
    assert tickets["permissions"] == ["tickets:read", "tickets:write"]
    assert tickets["tools"] == ["list_tickets", "update_ticket"]
    assert doc["entries"][1]["permissions"] == ["wiki.read"] and doc["entries"][1]["tools"] is None
    assert doc["entries"][2]["permissions"] == ["files:read"]


def test_register_field_rules(tmp_path):
    rc, doc = run_json(mod, [*setup(tmp_path), *AS_OF])
    assert rc == 1
    assert rules(doc, "wiki-search") == [
        ("wiki-search", "invalid-classification"),
        ("wiki-search", "missing-owner"),
        ("wiki-search", "review-overdue"),
    ]


def test_listing_and_manifest_drift(tmp_path):
    _, doc = run_json(mod, [*setup(tmp_path), *AS_OF])
    assert rules(doc, "tickets-mcp") == [
        ("tickets-mcp", "permission-not-in-manifest"),
        ("tickets-mcp", "tool-gone"),
        ("tickets-mcp", "undeclared-permission"),
        ("tickets-mcp", "unregistered-tool"),
    ]
    details = {f["rule"]: f["detail"] for f in doc["findings"] if f["name"] == "tickets-mcp"}
    assert "'delete_ticket'" in details["unregistered-tool"] and "'update_ticket'" in details["tool-gone"]
    assert "'users:read'" in details["undeclared-permission"]
    assert rules(doc, "old-files-mcp") == [("old-files-mcp", "not-present")]
    assert rules(doc, "shadow-mcp") == [("shadow-mcp", "unregistered-server")]
    assert "2 tool(s)" in next(f["detail"] for f in doc["findings"] if f["name"] == "shadow-mcp")


def test_csv_register_without_listings_and_clean_exit(tmp_path):
    csv_text = (
        "name,kind,owner,purpose,data_classification,permissions,review_date\n"
        "crm,connector,amy@example.com,read accounts,internal,crm.read;crm.notes,2027-01-01\n"
        "crm,connector,amy@example.com,read accounts,internal,crm.read,2027-01-01\n"
    )
    write_files(tmp_path, {"reg.csv": csv_text})
    rc, doc = run_json(mod, [str(tmp_path / "reg.csv"), *AS_OF])
    assert rc == 1 and rules(doc) == [("crm", "duplicate-name")]
    assert doc["findings"][0]["line"] == 3 and doc["entries"][0]["permissions"] == ["crm.read", "crm.notes"]
    write_files(tmp_path, {"one.csv": csv_text.rsplit("crm,", 1)[0]})
    rc, out, _ = run_main(mod, [str(tmp_path / "one.csv"), *AS_OF])
    assert rc == 0 and "No findings" in out


def test_json_register_markdown_and_classification_option(tmp_path):
    write_json(
        tmp_path,
        {
            "reg.json": [
                {
                    "name": "maps",
                    "owner": "kim@example.com",
                    "purpose": "geocode",
                    "data_classification": "OFFICIAL",
                    "permissions": ["maps.read"],
                    "review_date": "next year",
                }
            ]
        },
    )
    rc, out, _ = run_main(mod, [str(tmp_path / "reg.json"), *AS_OF])
    assert rc == 1 and "[invalid-review-date]" in out and "[invalid-classification]" in out
    assert out.startswith("# Connector and MCP server register check")
    _, doc = run_json(mod, [str(tmp_path / "reg.json"), *AS_OF, "--classifications", "official,secret"])
    assert rules(doc) == [("maps", "invalid-review-date")]


def test_out_writes_file(tmp_path):
    args = setup(tmp_path)
    out = tmp_path / "check.md"
    rc, stdout, _ = run_main(mod, [*args, *AS_OF, "--out", str(out)])
    assert rc == 1 and stdout == "" and "unregistered-server" in out.read_text(encoding="utf-8")


def test_bad_input_exits_2(tmp_path):
    write_files(
        tmp_path,
        {
            "anchor.yaml": "- name: a\n  owner: &x sam\n",
            "noname.csv": "owner\nsam\n",
            "empty.yaml": "# nothing\n",
            "scalar.yaml": "just text\n",
            "tools/bad.json": "{",
        },
    )
    for name in ("anchor.yaml", "noname.csv", "empty.yaml", "scalar.yaml", "missing.yaml"):
        assert run_main(mod, [str(tmp_path / name), *AS_OF])[0] == 2, name
    write_files(tmp_path, {"ok.csv": "name\nx\n"})
    assert run_main(mod, [str(tmp_path / "ok.csv"), "--tools", str(tmp_path / "tools"), *AS_OF])[0] == 2
    assert run_main(mod, [str(tmp_path / "ok.csv"), "--tools", str(tmp_path / "nope"), *AS_OF])[0] == 2
    assert run_main(mod, [str(tmp_path / "ok.csv"), "--as-of", "2026-13-01"])[0] == 2
