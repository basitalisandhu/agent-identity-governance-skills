import re
import subprocess
import sys

from conftest import ROOT


def test_repository_passes_its_own_validator():
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "validate_plugin.py")],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    skills = len(list(ROOT.glob("plugins/*/skills/*/SKILL.md")))
    assert re.search(rf"^{skills} skills, 0 error\(s\)$", proc.stdout, re.MULTILINE), proc.stdout


def test_every_script_has_at_least_six_tests():
    for script in sorted(ROOT.glob("plugins/*/skills/*/scripts/[a-z]*.py")):
        tests = ROOT / "tests" / f"test_{script.stem}.py"
        count = len(re.findall(r"^def test_", tests.read_text(encoding="utf-8"), re.MULTILINE))
        assert count >= 6, f"{tests.name} has {count} tests"


def _validator():
    import importlib.util

    spec = importlib.util.spec_from_file_location("validate_plugin", ROOT / "scripts" / "validate_plugin.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_description_needs_a_double_quoted_trigger_phrase_of_two_to_eight_words():
    vp = _validator()
    ok = '"Check it. Use when asked \\"is this agent still needed?\\". Not for people."'
    assert vp.description_problems(ok) == []
    for phrase in ("needed?", "one two three four five six seven eight nine"):
        assert vp.description_problems(f'"Check it. Use when asked \\"{phrase}\\". Not for people."')
    single = "\"Check it. Use when asked 'is this agent still needed?'. Not for people.\""
    assert any("double quotes" in p for p in vp.description_problems(single))
    assert vp.trigger_phrases('Use when asked "who owns this?" or "why".') == ["who owns this?"]


def test_description_keeps_its_other_rules():
    vp = _validator()
    phrase = '\\"is this agent still needed?\\"'
    assert vp.description_problems(f"Check it. Use when asked {phrase}. Not for people.")
    assert vp.description_problems(f'"Check it. Use when asked {phrase}."')
    assert vp.description_problems(f'"the check. Use when asked {phrase}. Not for people."')
    assert vp.description_problems('"' + "x" * 601 + '"')
