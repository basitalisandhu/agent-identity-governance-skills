"""Seeded fuzz tests for every script that reads exports, registers, logs or inventories from outside.

Each case copies the bundled examples (plugins/agent-identity-governance/examples), damages one of the files that
case reads in a random but repeatable way (a value of the wrong type, a missing key, a truncated file, a different
top-level shape, bytes that are not UTF-8, a broken CSV or JSON line) and runs the script. Bad input may change the
result or exit 2 with a message on stderr; it must never raise a traceback.

The seed is fixed so a failure reproduces. FUZZ_ITERATIONS (default 30) sets the cases per script; raise it locally
for a deeper run, for example FUZZ_ITERATIONS=500 python -m pytest tests/test_fuzz_inputs.py.
"""

from __future__ import annotations

import copy
import json
import os
import random
import shutil
from pathlib import Path

import pytest
from conftest import ROOT, load_script, run_main

ITERATIONS = int(os.environ.get("FUZZ_ITERATIONS", "30"))
EX = ROOT / "plugins" / "agent-identity-governance" / "examples"
AS_OF = ["--as-of", "2026-10-05"]
ENTRA_AGENT = "entra:00000000-0000-0000-0000-0000000000e5"

# (skill, script, argv with {ex} for the copied examples folder, files or folders under it that may be damaged)
CASES = [
    ("nhi-inventory", "nhi_inventory.py", ["{ex}/exports", *AS_OF], ["exports"]),
    ("entra-agent-id-review", "entra_agent_review.py", ["{ex}/exports", *AS_OF], ["exports"]),
    ("credential-expiry-radar", "credential_expiry_radar.py", ["{ex}/exports", *AS_OF], ["exports"]),
    (
        "agent-recertification",
        "agent_recertification.py",
        ["{ex}/inventory.json", "--attestations", "{ex}/attestations.csv", "--users", "{ex}/users.json", *AS_OF],
        ["inventory.json", "attestations.csv", "users.json"],
    ),
    (
        "connector-register",
        "connector_register.py",
        ["{ex}/register.yaml", "--tools", "{ex}/tools", "--manifests", "{ex}/manifests", *AS_OF],
        ["register.yaml", "tools", "manifests"],
    ),
    (
        "agent-action-timeline",
        "agent_action_timeline.py",
        [
            "--identity",
            "ci-deployer",
            "--cloudtrail",
            "{ex}/logs/cloudtrail.json",
            "--allow-list",
            "{ex}/logs/allow.txt",
        ],
        ["logs"],
    ),
    (
        "agent-action-timeline",
        "agent_action_timeline.py",
        ["--identity", "00000000-0000-0000-0000-0000000000c3", "--azure-activity", "{ex}/logs/azure-activity.json"],
        ["logs/azure-activity.json"],
    ),
    (
        "agent-kill-switch-runbook",
        "kill_switch_runbook.py",
        ["{ex}/inventory.json", "--identity", ENTRA_AGENT, *AS_OF],
        ["inventory.json"],
    ),
    (
        "leaked-credential-response",
        "leaked_credential_response.py",
        [
            "{ex}/inventory.json",
            "--identity",
            "aws-user:ci-deployer",
            "--credential",
            "MPLE",
            "--leaked-at",
            "2026-10-02T01:30:00Z",
            "--cloudtrail",
            "{ex}/logs/cloudtrail.json",
        ],
        ["inventory.json", "logs/cloudtrail.json"],
    ),
    (
        "agent-audit-log-integrity",
        "audit_chain.py",
        ["verify", "{ex}/audit/agent-actions.sealed.jsonl", "--head-file", "{ex}/audit/head.txt"],
        ["audit/agent-actions.sealed.jsonl", "audit/head.txt"],
    ),
    (
        "agent-audit-log-integrity",
        "audit_chain.py",
        ["coverage", "{ex}/audit/agent-actions.sealed.jsonl", "--transcript", "{ex}/audit/session.jsonl"],
        ["audit/agent-actions.sealed.jsonl", "audit/session.jsonl"],
    ),
    (
        "agent-audit-log-integrity",
        "audit_chain.py",
        ["seal", "{ex}/audit/session.jsonl"],
        ["audit/session.jsonl"],
    ),
]

ODD_VALUES = [
    None,
    0,
    -1,
    3.5,
    True,
    False,
    "",
    "x",
    "not-a-date",
    "0001-01-01T00:00:00Z",
    "9999-12-31T23:59:59Z",
    [],
    {},
    [1, 2],
    {"a": 1},
    ["x"],
    [None],
    "a|b`c\nd",
    10**20,
]


def _slots(node):
    if isinstance(node, dict):
        for k, v in node.items():
            yield node, k
            yield from _slots(v)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield node, i
            yield from _slots(v)


def mutate_json(data, rng: random.Random):
    data = copy.deepcopy(data)
    slots = list(_slots(data))
    roll = rng.random()
    if not slots or roll < 0.08:
        return rng.choice([*ODD_VALUES, [data], {"value": data}, {"value": {"id": 1}}])
    container, key = rng.choice(slots)
    if roll < 0.25 and isinstance(container, dict):
        del container[key]
    elif roll < 0.35 and isinstance(container, list):
        container.append(rng.choice(ODD_VALUES))
    else:
        container[key] = rng.choice(ODD_VALUES)
    return data


def mutate_text(text: str, rng: random.Random) -> bytes:
    roll = rng.random()
    raw = text.encode("utf-8")
    if roll < 0.3:
        return raw[: rng.randrange(0, max(1, len(raw)))]
    if roll < 0.45:
        return b"\xff\xfe\x00garbage" + raw[:20]
    lines = text.splitlines(keepends=True)
    if lines:
        i = rng.randrange(len(lines))
        lines[i] = rng.choice(
            ["", ",,,,\n", '"unterminated\n', "a,b\n", lines[i] * 3, "\x00\n", "{}\n", "[1]\n", "null\n"]
        )
    return "".join(lines).encode("utf-8")


def mutate_jsonl(text: str, rng: random.Random) -> bytes | None:
    lines = text.splitlines()
    if not lines:
        return None
    i = rng.randrange(len(lines))
    try:
        obj = json.loads(lines[i])
    except ValueError:
        return None
    lines[i] = json.dumps(mutate_json(obj, rng))
    return ("\n".join(lines) + "\n").encode("utf-8")


def damage(work: Path, targets: list[str], rng: random.Random) -> str:
    files = []
    for t in targets:
        p = work / t
        files += sorted(x for x in p.rglob("*") if x.is_file()) if p.is_dir() else [p]
    target = rng.choice(files)
    text = target.read_text(encoding="utf-8")
    if rng.random() < 0.7:
        if target.suffix == ".json":
            try:
                target.write_text(json.dumps(mutate_json(json.loads(text), rng)), encoding="utf-8")
                return f"{target.name}: json mutation"
            except ValueError:
                pass
        if target.suffix == ".jsonl":
            new = mutate_jsonl(text, rng)
            if new is not None:
                target.write_bytes(new)
                return f"{target.name}: json line mutation"
    target.write_bytes(mutate_text(text, rng))
    return f"{target.name}: text mutation"


@pytest.fixture(scope="module")
def examples(tmp_path_factory) -> Path:
    """The bundled examples plus the inventory JSON the downstream skills read."""
    root = tmp_path_factory.mktemp("examples") / "ex"
    shutil.copytree(EX, root)
    inv = load_script("nhi-inventory", "nhi_inventory.py")
    rc, _, err = run_main(inv, [str(root / "exports"), *AS_OF, "--json", "--out", str(root / "inventory.json")])
    assert rc in (0, 1), err
    return root


@pytest.mark.parametrize(
    "case", CASES, ids=[f"{c[0]}:{c[2][0] if c[2][0] in ('seal', 'verify', 'coverage') else ''}" for c in CASES]
)
def test_damaged_inputs_never_raise(case, examples, tmp_path):
    skill, script, argv, targets = case
    mod = load_script(skill, script)
    rng = random.Random(f"{skill}:{argv[0]}:{argv[-1]}")
    for i in range(ITERATIONS):
        work = tmp_path / f"run{i}"
        shutil.copytree(examples, work)
        what = f"seed {skill}:{argv[0]} iteration {i}, " + damage(work, targets, rng)
        args = [a.replace("{ex}", str(work)) for a in argv] + ["--json"]
        try:
            rc, _, err = run_main(mod, args)
        except Exception as exc:  # noqa: BLE001 (the point of the test)
            pytest.fail(f"{what}: traceback {type(exc).__name__}: {exc}")
        assert rc in (0, 1, 2), f"{what}: exit {rc}"
        if rc == 2:
            assert err.strip(), f"{what}: exit 2 with no message"


@pytest.mark.parametrize("skill,script", [(c[0], c[1]) for c in CASES[:3]], ids=[c[0] for c in CASES[:3]])
def test_json_nested_too_deep_exits_2(skill, script, examples, tmp_path):
    """JSON nested deeper than Python's recursion limit raised RecursionError from json.loads."""
    mod = load_script(skill, script)
    work = tmp_path / "ex"
    shutil.copytree(examples, work)
    (work / "exports" / "entra-applications.json").write_text("[" * 100_000 + "]" * 100_000, encoding="utf-8")
    rc, _, err = run_main(mod, [str(work / "exports"), *AS_OF])
    assert rc == 2 and "RecursionError" in err, err


def test_epoch_beyond_the_platform_range_is_an_unreadable_time(tmp_path):
    """An epoch such as 10**20 raised OverflowError or OSError from datetime.fromtimestamp; it is now no time at all."""
    mod = load_script("agent-action-timeline", "agent_action_timeline.py")
    log = tmp_path / "app.jsonl"
    log.write_text(
        json.dumps({"ts": 10**20, "agent": "a", "tool": "x"})
        + "\n"
        + json.dumps({"ts": 1790000000, "agent": "a", "tool": "y"})
        + "\n",
        encoding="utf-8",
    )
    rc, out, err = run_main(mod, ["--identity", "a", "--app-log", str(log), "--json"])
    assert rc == 0, err
    assert [e["action"] for e in json.loads(out)["events"]] == ["app:y"]
