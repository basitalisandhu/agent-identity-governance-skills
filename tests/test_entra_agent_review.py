"""Tests for entra_agent_review.py. Graph exports are synthetic and written in each test; ids are made up."""

from __future__ import annotations

from conftest import load_script, run_json, run_main, write_files, write_json

mod = load_script("entra-agent-id-review", "entra_agent_review.py")
AS_OF = ["--as-of", "2026-10-05"]
AGENT_APP = "00000000-0000-0000-0000-0000000000a1"
PLAIN_APP = "00000000-0000-0000-0000-0000000000b2"
BLUEPRINT_APP = "00000000-0000-0000-0000-0000000000c3"

SPS = {
    "value": [
        {
            "id": "sp-agent",
            "appId": AGENT_APP,
            "displayName": "Invoice Agent",
            "servicePrincipalType": "Application",
            "owners": [{"userPrincipalName": "sam@example.com"}],
        },
        {
            "id": "sp-plain",
            "appId": PLAIN_APP,
            "displayName": "HR portal",
            "servicePrincipalType": "Application",
            "owners": [{"userPrincipalName": "amy@example.com"}],
        },
    ]
}
APPS = {
    "value": [
        {
            "appId": AGENT_APP,
            "displayName": "Invoice Agent",
            "signInAudience": "AzureADMyOrg",
            "passwordCredentials": [
                {
                    "keyId": "11111111-0000-0000-0000-00000000aaaa",
                    "startDateTime": "2026-01-01T00:00:00Z",
                    "endDateTime": "2027-12-31T00:00:00Z",
                },
                {
                    "keyId": "11111111-0000-0000-0000-00000000bbbb",
                    "startDateTime": "2026-01-01T00:00:00Z",
                    "endDateTime": "2026-10-20T00:00:00Z",
                },
            ],
            "web": {
                "redirectUris": [
                    "http://invoices.example.com/callback",
                    "https://*.example.com/auth",
                    "http://localhost:8080/cb",
                ]
            },
        },
    ]
}
RESOURCES = {
    "value": [
        {
            "id": "res-graph",
            "displayName": "Microsoft Graph",
            "appRoles": [{"id": "r-mail", "value": "Mail.Send"}, {"id": "r-user", "value": "User.Read.All"}],
        }
    ]
}
ASSIGNMENTS = {
    "value": [
        {"principalId": "sp-agent", "resourceId": "res-graph", "appRoleId": "r-mail"},
        {"principalId": "sp-agent", "resourceId": "res-graph", "appRoleId": "r-user"},
    ]
}
GRANTS = {
    "value": [
        {
            "clientId": "sp-agent",
            "consentType": "AllPrincipals",
            "resourceId": "res-graph",
            "scope": "User.Read Files.Read.All",
        }
    ]
}


def folder(tmp_path, **extra):
    files = {
        "entra-service-principals.json": SPS,
        "entra-applications.json": APPS,
        "entra-resource-sps.json": RESOURCES,
        "entra-app-role-assignments.json": ASSIGNMENTS,
        "entra-oauth2-grants.json": GRANTS,
    }
    files.update(extra)
    return str(write_json(tmp_path / "exports", files))


def rules(record):
    return sorted({f["rule"] for f in record["findings"]})


def test_selects_agents_by_name_and_reports_permissions(tmp_path):
    rc, doc = run_json(mod, [folder(tmp_path), *AS_OF])
    assert rc == 1
    assert [r["display_name"] for r in doc["reviewed"]] == ["Invoice Agent"]
    r = doc["reviewed"][0]
    assert r["selected_because"] == ["name pattern"]
    assert {p["permission"]: p["high_risk"] for p in r["application_permissions"]} == {
        "Mail.Send": True,
        "User.Read.All": False,
    }
    sev = {f["detail"]: f["severity"] for f in r["findings"] if "permission" in f["rule"]}
    assert sev == {
        "Microsoft Graph: Mail.Send (application)": "HIGH",
        "Microsoft Graph: Files.Read.All (all users)": "MEDIUM",
    }


def test_credentials_redirect_uris_and_masking(tmp_path):
    rc, out, _ = run_main(mod, [folder(tmp_path), *AS_OF, "--json"])
    assert "11111111-0000-0000-0000-00000000aaaa" not in out and "****aaaa" in out
    _, doc = run_json(mod, [folder(tmp_path), *AS_OF])
    r = doc["reviewed"][0]
    found = {(f["rule"], f["detail"]) for f in r["findings"]}
    assert ("redirect-uri-insecure", "http://invoices.example.com/callback") in found
    assert ("redirect-uri-wildcard", "https://*.example.com/auth") in found
    assert not any("localhost" in d for _, d in found)
    assert "credential-expiring" in rules(r) and "long-lived-secret" in rules(r)


def test_conditional_access_coverage(tmp_path):
    policies = {
        "value": [
            {
                "displayName": "Block risky workload sign-ins",
                "state": "enabledForReportingButNotEnforced",
                "conditions": {"clientApplications": {"includeServicePrincipals": ["ServicePrincipalsInMyTenant"]}},
            }
        ]
    }
    _, doc = run_json(mod, [folder(tmp_path, **{"entra-ca-policies.json": policies}), *AS_OF])
    assert doc["reviewed"][0]["conditional_access"]["status"] == "report-only"
    policies["value"][0]["state"] = "enabled"
    policies["value"][0]["conditions"]["clientApplications"]["excludeServicePrincipals"] = ["sp-agent"]
    _, doc = run_json(mod, [folder(tmp_path, **{"entra-ca-policies.json": policies}), *AS_OF])
    assert "ca-not-covered" in rules(doc["reviewed"][0])
    del policies["value"][0]["conditions"]["clientApplications"]["excludeServicePrincipals"]
    _, doc = run_json(mod, [folder(tmp_path, **{"entra-ca-policies.json": policies}), *AS_OF])
    assert doc["reviewed"][0]["conditional_access"] == {
        "status": "covered",
        "policies": ["Block risky workload sign-ins"],
    }


def test_agent_identity_objects_and_blueprint_credentials(tmp_path):
    agents = {
        "value": [
            {
                "@odata.type": "#microsoft.graph.agentIdentity",
                "id": "sp-ai",
                "appId": "ai-1",
                "displayName": "Ledger worker",
                "agentIdentityBlueprintId": BLUEPRINT_APP,
                "sponsors": [{"userPrincipalName": "kim@example.com"}],
            }
        ]
    }
    blueprints = {
        "value": [
            {
                "appId": BLUEPRINT_APP,
                "displayName": "Finance blueprint",
                "keyCredentials": [
                    {
                        "keyId": "22222222-0000-0000-0000-00000000cccc",
                        "usage": "Verify",
                        "startDateTime": "2026-01-01T00:00:00Z",
                        "endDateTime": "2026-09-01T00:00:00Z",
                    }
                ],
            }
        ]
    }
    _, doc = run_json(
        mod,
        [
            folder(tmp_path, **{"entra-agent-identities.json": agents, "entra-agent-blueprints.json": blueprints}),
            *AS_OF,
        ],
    )
    r = next(x for x in doc["reviewed"] if x["display_name"] == "Ledger worker")
    assert r["type"] == "agent identity" and r["blueprint"] == "Finance blueprint"
    assert r["sponsors"] == ["kim@example.com"] and "no-owner" not in rules(r)
    assert r["credentials"][0]["on"] == "blueprint" and r["credentials"][0]["status"] == "expired"


def test_dormant_tag_selection_and_include_all(tmp_path):
    activity = {"value": [{"appId": AGENT_APP, "lastSignInActivity": {"lastSignInDateTime": "2026-01-01T00:00:00Z"}}]}
    _, doc = run_json(mod, [folder(tmp_path / "a", **{"entra-sign-in-activity.json": activity}), *AS_OF])
    assert "dormant" in rules(doc["reviewed"][0])
    _, doc = run_json(mod, [folder(tmp_path), *AS_OF, "--include-all"])
    assert len(doc["reviewed"]) == 2
    _, doc = run_json(mod, [folder(tmp_path), *AS_OF, "--name-pattern", "^nomatch$", "--app-id", PLAIN_APP])
    assert [r["app_id"] for r in doc["reviewed"]] == [PLAIN_APP]
    assert doc["reviewed"][0]["findings"] == []


def test_markdown_bolds_high_risk_and_fail_on(tmp_path):
    rc, out, _ = run_main(mod, [folder(tmp_path), *AS_OF])
    assert out.startswith("# Entra agent identity review") and "**Mail.Send**" in out
    assert "Owner decision" in out and rc == 1
    rc, _, _ = run_main(mod, [folder(tmp_path), *AS_OF, "--name-pattern", "^HR portal$"])
    assert rc == 0


def test_no_match_message_and_redact(tmp_path):
    _, out, _ = run_main(mod, [folder(tmp_path), *AS_OF, "--name-pattern", "^zzz$"])
    assert "No identity matched" in out
    _, doc = run_json(mod, [folder(tmp_path), *AS_OF, "--redact"])
    assert "sam@example.com" not in str(doc)


def test_bad_input_exits_2(tmp_path):
    assert run_main(mod, [str(tmp_path / "nope"), *AS_OF])[0] == 2
    write_files(tmp_path / "x", {"entra-applications.json": "{}"})
    assert run_main(mod, [str(tmp_path / "x"), *AS_OF])[0] == 2
    assert run_main(mod, [folder(tmp_path), "--name-pattern", "("])[0] == 2
    write_files(tmp_path / "y", {"entra-service-principals.json": "[oops"})
    assert run_main(mod, [str(tmp_path / "y"), *AS_OF])[0] == 2
