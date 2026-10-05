#!/usr/bin/env python3
"""agent-identity-governance: one command for the agent identity governance skill scripts.

    agent-identity-governance <subcommand> [args]    run one skill script with the given arguments
    agent-identity-governance <subcommand> --help    that script's own help
    agent-identity-governance --help                 list the subcommands

Each subcommand runs plugins/agent-identity-governance/skills/<skill>/scripts/<script>.py unchanged, in a child
process with the same Python, stdin, stdout, stderr and exit code. Standard library only. This is the entrypoint of
the container image ghcr.io/basitalisandhu/agent-identity-governance-skills and of the
agent-identity-governance-skills Python package. To add a skill, add one entry to COMMANDS.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

__version__ = "0.1.0"

PROG = "agent-identity-governance"
HERE = Path(__file__).resolve().parent
# In a checkout or the container image the skills sit at <root>/plugins/agent-identity-governance/skills; in the
# installed Python package they sit next to this file, at agent_identity_governance_skills/skills.
SKILLS = next(
    (p for p in (HERE.parent / "plugins" / "agent-identity-governance" / "skills", HERE / "skills") if p.is_dir()),
    HERE.parent / "plugins" / "agent-identity-governance" / "skills",
)

# subcommand: (skill directory, script, one-line summary)
COMMANDS: dict[str, tuple[str, str, str]] = {
    "inventory": (
        "nhi-inventory",
        "nhi_inventory.py",
        "One inventory of non-human identities from Entra, AWS, GitHub and register exports",
    ),
    "agent-review": (
        "entra-agent-id-review",
        "entra_agent_review.py",
        "Review Entra agent identities: permissions, credentials, redirect URIs, owners, Conditional Access",
    ),
    "recertify": (
        "agent-recertification",
        "agent_recertification.py",
        "Quarterly recertification sheets per owner and a tracking CSV",
    ),
    "expiry-radar": (
        "credential-expiry-radar",
        "credential_expiry_radar.py",
        "Expired and expiring secrets, certificates, keys and tokens, grouped by owner",
    ),
    "connector-register": (
        "connector-register",
        "connector_register.py",
        "Check an MCP server and connector register against tool listings and manifests",
    ),
    "timeline": (
        "agent-action-timeline",
        "agent_action_timeline.py",
        "Ordered timeline of one agent identity's actions from audit exports",
    ),
    "kill-switch": (
        "agent-kill-switch-runbook",
        "kill_switch_runbook.py",
        "Ordered switch-off runbook for one identity, with a coverage check",
    ),
    "leaked-credential": (
        "leaked-credential-response",
        "leaked_credential_response.py",
        "Checklist, rotation order and hashed evidence folder for a leaked credential",
    ),
}


def script_path(name: str) -> Path:
    skill, script, _ = COMMANDS[name]
    return SKILLS / skill / "scripts" / script


def usage() -> str:
    width = max(len(n) for n in COMMANDS)
    lines = [
        f"usage: {PROG} <subcommand> [args]",
        "",
        f"Runs one of the agent identity governance skill scripts over files you saved (no network). "
        f"Use '{PROG} <subcommand> --help' for its options.",
        "",
        "subcommands:",
    ]
    lines += [f"  {n.ljust(width)}  {h} ({script})" for n, (_, script, h) in COMMANDS.items()]
    lines += ["", "options:", "  -h, --help     show this help and exit", "  --version      show the version and exit"]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(usage(), file=sys.stderr)
        return 2
    first, rest = args[0], args[1:]
    if first in ("-h", "--help", "help") and not rest:
        print(usage())
        return 0
    if first == "help":
        first, rest = rest[0], ["--help"]
    if first == "--version":
        print(f"{PROG} {__version__}")
        return 0
    if first not in COMMANDS:
        print(f"{PROG}: unknown subcommand {first!r}\n\n{usage()}", file=sys.stderr)
        return 2
    return subprocess.call([sys.executable, str(script_path(first)), *rest])


if __name__ == "__main__":
    sys.exit(main())
