import pytest

from webcare import setup_init
from webcare.cli import main
from webcare.model import Refusal
from webcare.targets import load_targets


def test_flags_write_a_target_that_loads(tmp_path, capsys):
    config = tmp_path / "webcare.toml"
    assert main(["init", "--config", str(config), "--name", "staging", "--env", "staging",
                 "--real-data", "no", "--project-ref", "a" * 20, "--lang", "th"]) == 0
    target = load_targets(config)["staging"]
    assert (target.env, target.data, target.project_ref, target.lang) == ("staging", "synthetic", "a" * 20, "th")
    out = capsys.readouterr().out
    assert "Database Read" in out and "--owner-approved" not in out
    assert main(["init", "--config", str(config), "--name", "trial", "--env", "production",
                 "--project-ref", "b" * 20]) == 0
    trial = load_targets(config)["trial"]
    assert trial.data == "real"  # not asked, so the safe answer
    assert "--owner-approved" in capsys.readouterr().out
    assert "[[target]]" in config.read_text() and config.read_text().count("[[target]]") == 2


def test_wrong_answers_and_a_taken_name_are_refused_and_nothing_is_written(tmp_path):
    config = tmp_path / "webcare.toml"
    for bad in (["--name", "Bad Name"], ["--name", "x", "--project-ref", "short"], ["--name", "x", "--schema", "a;b"]):
        assert main(["init", "--config", str(config), *bad]) == 2
    assert not config.exists()
    main(["init", "--config", str(config), "--name", "staging", "--real-data", "no"])
    before = config.read_text()
    assert main(["init", "--config", str(config), "--name", "staging", "--real-data", "no"]) == 2
    assert config.read_text() == before
    assert not list(tmp_path.glob(".*.new"))


def test_a_person_is_asked_for_what_is_missing(tmp_path):
    answers = iter(["staging", "staging", "", ""])
    message = setup_init.run(tmp_path / "w.toml", None, None, None, None, None, "en", True,
                             ask=lambda prompt: next(answers))
    target = load_targets(tmp_path / "w.toml")["staging"]
    assert target.data == "real" and "wrote target 'staging'" in message  # empty answer means yes
    with pytest.raises(Refusal):
        setup_init.run(tmp_path / "x.toml", None, None, None, None, None, "en", False)
