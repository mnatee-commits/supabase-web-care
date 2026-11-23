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
