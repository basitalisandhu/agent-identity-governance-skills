"""Tests for credential_expiry_radar.py. Exports are synthetic and written in each test; ids are made up."""

from __future__ import annotations

from conftest import load_script, run_json, run_main, write_files, write_json

mod = load_script("credential-expiry-radar", "credential_expiry_radar.py")
AS_OF = ["--as-of", "2026-10-05"]

APPS = {
    "value": [
        {
            "appId": "app-1",
            "displayName": "invoice-agent",
            "owners": [{"userPrincipalName": "sam@example.com"}],
            "passwordCredentials": [
                {"keyId": "11111111-0000-0000-0000-00000000aaaa", "endDateTime": "2026-10-01T00:00:00Z"},
                {"keyId": "11111111-0000-0000-0000-00000000bbbb", "endDateTime": "2026-10-10T00:00:00Z"},
            ],
            "keyCredentials": [
                {"keyId": "11111111-0000-0000-0000-00000000cccc", "endDateTime": "2026-12-01T00:00:00Z"}
            ],
        },
        {
            "appId": "app-2",
            "displayName": "report-bot",
            "passwordCredentials": [
                {"keyId": "11111111-0000-0000-0000-00000000dddd", "endDateTime": "2028-01-01T00:00:00Z"}
            ],
        },
    ]
}


def entra(tmp_path):
    return str(write_json(tmp_path / "exports", {"entra-applications.json": APPS}))


def test_entra_buckets_and_masking(tmp_path):
    rc, doc = run_json(mod, [entra(tmp_path), *AS_OF])
    assert rc == 1
    got = {r["key_id"]: (r["bucket"], r["days_left"]) for r in doc["credentials"]}
    assert got == {
        "****aaaa": ("expired", -4),
        "****bbbb": ("7", 5),
        "****cccc": ("90", 57),
        "****dddd": ("later", 453),
    }
    assert doc["counts"] == {"expired": 1, "7": 1, "30": 0, "90": 1, "later": 1, "no-expiry": 0}
    _, out, _ = run_main(mod, [entra(tmp_path), *AS_OF, "--json"])
    assert "00000000aaaa" not in out


def test_owner_action_list_excludes_later_and_orders_by_due(tmp_path):
    _, doc = run_json(mod, [entra(tmp_path), *AS_OF])
    assert list(doc["by_owner"]) == ["sam@example.com"]
    assert [r["key_id"] for r in doc["by_owner"]["sam@example.com"]] == ["****aaaa", "****bbbb", "****cccc"]
    assert doc["by_owner"]["sam@example.com"][0]["action"].startswith("remove it")
    _, out, _ = run_main(mod, [entra(tmp_path), *AS_OF])
    assert "### sam@example.com" in out and "rotate before 2026-10-10" in out


def test_aws_keys_due_by_age_with_owner_tag(tmp_path):
    folder = write_json(
        tmp_path,
        {
            "aws-access-keys.json": [
                {
                    "AccessKeyMetadata": [
                        {
                            "UserName": "ci-deployer",
                            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                            "Status": "Active",
                            "CreateDate": "2026-07-01T00:00:00Z",
                        },
                        {
                            "UserName": "ci-deployer",
                            "AccessKeyId": "KEYID0000000000OLD1",
                            "Status": "Inactive",
                            "CreateDate": "2025-01-01T00:00:00Z",
                        },
                    ]
                }
            ],
            "aws-authorization-details.json": {
                "UserDetailList": [{"UserName": "ci-deployer", "Tags": [{"Key": "owner", "Value": "ops@example.com"}]}]
            },
        },
    )
    rc, doc = run_json(mod, [str(folder), *AS_OF])
    assert len(doc["credentials"]) == 1
    r = doc["credentials"][0]
    assert r["key_id"] == "****MPLE" and r["due"] == "2026-09-29" and r["bucket"] == "expired"
    assert r["owners"] == ["ops@example.com"] and "90 days" in r["basis"] and rc == 1
    _, doc = run_json(mod, [str(folder), *AS_OF, "--max-key-age", "180"])
    assert doc["credentials"][0]["bucket"] == "90"


def test_credential_report_fallback_github_tokens_and_other_keys(tmp_path):
    folder = write_files(
        tmp_path,
        {
            "aws-credential-report.csv": "user,access_key_1_active,access_key_1_last_rotated,access_key_2_active,"
            "access_key_2_last_rotated\nbuild,true,2026-09-20T00:00:00+00:00,false,N/A\n",
            "other-keys.csv": "name,system,owner,key_id,created,expires\n"
            "search api,vendor,amy@example.com,KEY-0000-9z9z,2026-01-01,\n"
            "maps api,vendor,amy@example.com,KEY-0000-8y8y,2026-01-01,2026-10-30\n",
        },
    )
    write_json(
        folder,
        {
            "github-fine-grained-tokens.json": [
                {
                    "id": 501,
                    "token_name": "release-bot",
                    "owner": {"login": "octo-lee"},
                    "token_expires_at": "2026-10-08T00:00:00Z",
                }
            ]
        },
    )
    rc, doc = run_json(mod, [str(folder), *AS_OF])
    got = {(r["system"], r["key_id"]): r["bucket"] for r in doc["credentials"]}
    assert got == {
        ("aws", "slot 1"): "90",
        ("github", "****501"): "7",
        ("vendor", "****9z9z"): "no-expiry",
        ("vendor", "****8y8y"): "30",
    }
    assert rc == 1
    assert "octo-lee" in doc["by_owner"] and "(no owner recorded)" in doc["by_owner"]


def test_clean_exit_zero_and_out_file(tmp_path):
    folder = write_files(tmp_path, {"other-keys.csv": "name,owner,expires\nfar key,amy@example.com,2027-06-01\n"})
    out = tmp_path / "radar.md"
    rc, stdout, _ = run_main(mod, [str(folder), *AS_OF, "--out", str(out)])
    assert rc == 0 and stdout == ""
    assert "Nothing is expired, undated or due within 90 days." in out.read_text(encoding="utf-8")
    rc, _, _ = run_main(mod, [str(folder), *AS_OF, "--fail-within", "400"])
    assert rc == 1


def test_redact_hides_owner_addresses_including_keys(tmp_path):
    _, doc = run_json(mod, [entra(tmp_path), *AS_OF, "--redact"])
    assert "sam@example.com" not in str(doc)
    assert all(k.endswith("@redacted.invalid") for k in doc["by_owner"])


def test_bad_input_exits_2(tmp_path):
    assert run_main(mod, [str(tmp_path / "missing"), *AS_OF])[0] == 2
    (tmp_path / "empty").mkdir()
    assert run_main(mod, [str(tmp_path / "empty"), *AS_OF])[0] == 2
    write_files(tmp_path / "a", {"other-keys.csv": "name,expires\nk,someday\n"})
    assert run_main(mod, [str(tmp_path / "a"), *AS_OF])[0] == 2
    write_files(tmp_path / "b", {"entra-applications.json": "{"})
    assert run_main(mod, [str(tmp_path / "b"), *AS_OF])[0] == 2
    assert run_main(mod, [entra(tmp_path), "--as-of", "tomorrow"])[0] == 2
    assert run_main(mod, [entra(tmp_path), *AS_OF, "--max-key-age", "0"])[0] == 2
