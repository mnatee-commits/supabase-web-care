import re

from conftest import ROOT


def test_action_inputs_never_reach_a_shell_command_directly():
    text = (ROOT / "action.yml").read_text()
    run_blocks = re.findall(r"run: \|\n((?:        .*\n)+)", text) + re.findall(r"run: (.+)", text)
    assert run_blocks
    for block in run_blocks:
        assert "${{" not in block, block
    assert re.search(r"uses: actions/setup-python@[0-9a-f]{40}", text)  # pinned to a commit
    assert "--skip live" in text and "--skip probe" in text  # the action contacts nothing


def test_pre_commit_hooks_contact_nothing():
    text = (ROOT / ".pre-commit-hooks.yaml").read_text()
    assert "id: webcare-secrets" in text and "id: webcare-migrations" in text
    assert "--profile quick" in text and "--target" not in text


def _run_action(tmp_path, **inputs):
    """Run the action's check script with a stand-in python that prints its arguments."""
    import os
    import subprocess

    text = (ROOT / "action.yml").read_text()
    script = re.search(r"      run: \|\n((?:        .*\n)+)", text.split("- name: Check", 1)[1]).group(1)
    script = "\n".join(line[8:] for line in script.splitlines())
    fake = tmp_path / "bin"
    fake.mkdir(exist_ok=True)
    (fake / "python").write_text('#!/bin/sh\nfor a in "$@"; do echo "ARG:$a"; done\n')
    (fake / "python").chmod(0o755)
    env = {"PATH": f"{fake}:{os.environ['PATH']}", "GITHUB_ACTION_PATH": str(ROOT),
           "WC_MIGRATIONS": "supabase/migrations", "WC_REPO": ".", "WC_BASELINE": "", "WC_CHANGED_SINCE": "",
           "WC_FAIL_ON": "high", "WC_SARIF": "false", "WC_LANG": "en"}
    env.update(inputs)
    done = subprocess.run(["bash", "-c", script], cwd=tmp_path, env=env, capture_output=True, text=True)
    return done.returncode, [line[4:] for line in done.stdout.splitlines() if line.startswith("ARG:")], done.stdout


def test_action_keeps_values_that_start_with_a_dash_as_values(tmp_path):
    code, args, _ = _run_action(tmp_path, WC_BASELINE="--no-fail-on-findings", WC_REPO="-x")
    assert code == 0 and "--baseline=--no-fail-on-findings" in args and "--repo=-x" in args


def test_action_refuses_a_missing_migrations_folder_named_on_purpose(tmp_path):
    code, args, out = _run_action(tmp_path, WC_MIGRATIONS="db/migration")
    assert code == 2 and not args and "migrations folder not found" in out
    code, args, _ = _run_action(tmp_path)  # the default folder may be absent: files-only sites
    assert code == 0 and not any(a.startswith("--migrations") for a in args)
    (tmp_path / "db" / "migration").mkdir(parents=True)
    code, args, _ = _run_action(tmp_path, WC_MIGRATIONS="db/migration")
    assert code == 0 and "--migrations=db/migration" in args


def test_action_refuses_a_sarif_value_it_does_not_know(tmp_path):
    code, _, out = _run_action(tmp_path, WC_SARIF="yes")
    assert code == 2 and "sarif must be true or false" in out
