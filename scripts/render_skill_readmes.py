#!/usr/bin/env python3
"""Write plugins/agent-identity-governance/skills/<skill>/README.md for every skill, with a real sample.

Each README holds a short summary, the commands that run the skill's script on the bundled examples, and the first
lines of what the script actually printed. Nothing in a sample is typed by hand: this script runs the commands and
pastes the output, so the samples stay true when a check changes.

    python3 scripts/render_skill_readmes.py           rewrite the READMEs
    python3 scripts/render_skill_readmes.py --check   exit 1 if any README differs from what would be written

The commands run in a temporary folder (skills that read an inventory first build inventory.json there), with paths
shown relative to the repository root. Standard library only; no network.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "plugins" / "agent-identity-governance" / "skills"
EX = "plugins/agent-identity-governance/examples"
AS_OF = ["--as-of", "2026-10-05"]
MAX_LINES = 40
INVENTORY = ("nhi-inventory", "nhi_inventory.py", [f"{EX}/exports", *AS_OF, "--json", "--out", "inventory.json"])

# skill: (summary, needs the inventory first, script, arguments; paths relative to the repository root)
SAMPLES: dict[str, tuple[str, bool, str, list[str]]] = {
    "nhi-inventory": (
        "Lists every non-human identity agents and automations run as, across Entra ID (with Agent ID), AWS IAM, "
        "GitHub and a hand-kept register, with owner, last use, credential count and oldest credential, and flags "
        "the ownerless and the unused.",
        False,
        "nhi_inventory.py",
        [f"{EX}/exports", *AS_OF],
    ),
    "entra-agent-id-review": (
        "Reviews the Entra identities AI agents use: owner or sponsor, permissions (including those inherited from an "
        "Agent ID blueprint), credentials, redirect URIs and Conditional Access cover, with high-risk permissions "
        "from a fixed list.",
        False,
        "entra_agent_review.py",
        [f"{EX}/exports", *AS_OF],
    ),
    "credential-expiry-radar": (
        "Finds secrets, certificates, access keys and tokens that have expired or soon will, across Entra apps and "
        "Agent ID blueprints, AWS IAM, GitHub tokens and a CSV of other keys, bucketed at 7, 30 and 90 days with an "
        "action list per owner.",
        False,
        "credential_expiry_radar.py",
        [f"{EX}/exports", *AS_OF],
    ),
    "agent-recertification": (
        "Prepares the quarterly recertification of agent and workload identities: one review sheet per owner and a "
        "tracking CSV, flagging identities never attested, stale attestations, owners who left and removals not done.",
        True,
        "agent_recertification.py",
        ["inventory.json", "--attestations", f"{EX}/attestations.csv", "--users", f"{EX}/users.json", *AS_OF],
    ),
    "connector-register": (
        "Checks the approved register of MCP servers, connectors and plugins: every entry has an owner, purpose, data "
        "classification, permissions and review date, and saved tool listings and manifests match it.",
        False,
        "connector_register.py",
        [f"{EX}/register.yaml", "--tools", f"{EX}/tools", "--manifests", f"{EX}/manifests", *AS_OF],
    ),
    "agent-action-timeline": (
        "Puts what one agent identity did in time order from saved sign-in, audit, CloudTrail, GitHub and application "
        "logs, and flags bursts, first-seen actions and actions outside an allow list.",
        False,
        "agent_action_timeline.py",
        [
            "--identity",
            "ci-deployer",
            "--cloudtrail",
            f"{EX}/logs/cloudtrail.json",
            "--allow-list",
            f"{EX}/logs/allow.txt",
        ],
    ),
    "agent-kill-switch-runbook": (
        "Writes the ordered runbook to switch one agent identity off fast, each step with a read-only verification "
        "command, and checks every credential and assignment in the inventory has a step.",
        True,
        "kill_switch_runbook.py",
        ["inventory.json", "--identity", "entra:00000000-0000-0000-0000-0000000000e5", *AS_OF],
    ),
    "leaked-credential-response": (
        "Responds to a leaked agent credential: what it could reach, what was done with it after the leak time, which "
        "credentials to replace first, and an evidence folder with SHA-256 hashes.",
        True,
        "leaked_credential_response.py",
        [
            "inventory.json",
            "--identity",
            "aws-user:ci-deployer",
            "--credential",
            "MPLE",
            "--leaked-at",
            "2026-10-02T01:30:00Z",
            "--cloudtrail",
            f"{EX}/logs/cloudtrail.json",
        ],
    ),
    "agent-audit-log-integrity": (
        "Seals an agent's audit log as a SHA-256 or HMAC hash chain, verifies it later for edited, deleted, inserted "
        "or reordered lines and truncation, and lists actions the log never recorded.",
        False,
        "audit_chain.py",
        ["verify", f"{EX}/audit/agent-actions.tampered.jsonl", "--head-file", f"{EX}/audit/head.txt"],
    ),
}


def absolute(args: list[str]) -> list[str]:
    return [str(ROOT / a) if a.startswith("plugins/") else a for a in args]


def run(skill: str, script: str, args: list[str], cwd: Path) -> tuple[int, str]:
    path = SKILLS / skill / "scripts" / script
    proc = subprocess.run(
        [sys.executable, str(path), *absolute(args)],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )
    if proc.returncode not in (0, 1):
        raise SystemExit(f"{skill}: {script} exited {proc.returncode}: {proc.stderr.strip()}")
    return proc.returncode, proc.stdout.replace(str(ROOT) + "/", "").replace(str(cwd) + "/", "")


def command(skill: str, script: str, args: list[str]) -> str:
    return " ".join(["python3", f"plugins/agent-identity-governance/skills/{skill}/scripts/{script}", *args])


def render(skill: str) -> str:
    summary, needs_inventory, script, args = SAMPLES[skill]
    commands = []
    with tempfile.TemporaryDirectory() as tmp:
        cwd = Path(tmp)
        if needs_inventory:
            run(*INVENTORY, cwd)
            commands.append(command(*INVENTORY))
        rc, out = run(skill, script, args, cwd)
        commands.append(command(skill, script, args))
    lines = out.rstrip("\n").splitlines()
    shown, more = lines[:MAX_LINES], max(0, len(lines) - MAX_LINES)
    body = "\n".join(shown) + (f"\n\n... ({more} more lines)" if more else "")
    return "\n".join(
        [
            f"# {skill}",
            "",
            summary,
            "",
            f"How to export the inputs, run it and read the result: [SKILL.md](SKILL.md). Every option: "
            f"`python3 scripts/{script} --help`.",
            "",
            "## Sample",
            "",
            "Run from the repository root on the bundled synthetic examples (every name, address and id in them is "
            f"invented). Exit code {rc}" + (" (something needs a person)." if rc == 1 else "."),
            "",
            "```bash",
            *commands,
            "```",
            "",
            "Output, as printed" + (f" (first {MAX_LINES} lines)" if more else "") + ":",
            "",
            "````markdown",
            body,
            "````",
            "",
            "This file is generated by `python3 scripts/render_skill_readmes.py`; edit that script, not this file.",
            "",
        ]
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="exit 1 if a README is missing or out of date; write nothing")
    args = ap.parse_args(argv)
    missing = sorted({d.name for d in SKILLS.iterdir() if (d / "SKILL.md").is_file()} - set(SAMPLES))
    if missing:
        print(f"error: no sample defined for {', '.join(missing)}", file=sys.stderr)
        return 1
    stale = []
    for skill in sorted(SAMPLES):
        text = render(skill)
        target = SKILLS / skill / "README.md"
        current = target.read_text(encoding="utf-8").replace("\r\n", "\n") if target.is_file() else None
        if current == text:
            continue
        if args.check:
            stale.append(skill)
        else:
            target.write_text(text, encoding="utf-8", newline="\n")
            print(f"wrote {target.relative_to(ROOT).as_posix()}")
    if stale:
        print(f"out of date: {', '.join(stale)}; run python3 scripts/render_skill_readmes.py", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
