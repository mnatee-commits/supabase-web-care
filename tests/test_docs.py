from conftest import ROOT
from webcare import PINNED_PGRLS_VERSION, __version__


def test_chat_instructions_match_the_skill_body():
    skill = (ROOT / "skills" / "supabase-web-care" / "SKILL.md").read_text()
    body = skill.split("---\n", 2)[2].lstrip("\n")
    assert (ROOT / "CHAT-INSTRUCTIONS.md").read_text() == body


def test_versions_agree_across_files():
    skill = (ROOT / "skills" / "supabase-web-care" / "SKILL.md").read_text()
    assert f'version: "{__version__}"' in skill
    assert (ROOT / "requirements.txt").read_text().splitlines()[0] == f"pgrls=={PINNED_PGRLS_VERSION}"
    project = (ROOT / "pyproject.toml").read_text()
    assert f'version = "{__version__}"' in project
    for line in (ROOT / "requirements.txt").read_text().splitlines():
        assert f'"{line}"' in project  # the package declares the same pins
        name, version = line.split("[")[0].split("==")[0], line.split("==")[1]
        assert f"{name}=={version} " in (ROOT / "requirements.lock").read_text()
    assert f"pgrls=={PINNED_PGRLS_VERSION} " in (ROOT / "requirements.lock").read_text()
    assert f"pgrls {PINNED_PGRLS_VERSION}" in skill
