import io
import sys

from webcare.cli import main


class Terminal(io.StringIO):
    def isatty(self):
        return True


def config(tmp_path):
    path = tmp_path / "webcare.toml"
    path.write_text('[[target]]\nname = "prod"\nenv = "production"\ndata = "real"\nproject_ref = "' + "a" * 20 + '"\n')
    return path


def test_no_terminal_means_the_usual_refusal(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO("yes\n"))  # not a terminal: the answer is never read
    monkeypatch.delenv("WEBCARE_ACCESS_TOKEN", raising=False)
    main(["check", "--target", "prod", "--via-api", "--config", str(config(tmp_path)), "--out-dir", str(tmp_path / "o")])
    err = capsys.readouterr().err
    assert "Type yes" not in err


def test_at_a_terminal_a_no_stops_before_anything_is_contacted(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", Terminal("no\n"))
    code = main(["check", "--target", "prod", "--via-api", "--with-backups", "--config", str(config(tmp_path)),
                 "--out-dir", str(tmp_path / "o")])
    captured = capsys.readouterr()
    err = captured.err
    assert code == 2 and "Type yes" in captured.out and "stopped; nothing was contacted" in err
    assert "GET backup list" in err and "no table row" in err
    assert not (tmp_path / "o").exists()


def test_at_a_terminal_a_yes_counts_as_the_owner_approval(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", Terminal("yes\n"))
    monkeypatch.delenv("WEBCARE_ACCESS_TOKEN", raising=False)
    main(["check", "--target", "prod", "--via-api", "--config", str(config(tmp_path)), "--out-dir", str(tmp_path / "o")])
    text = (tmp_path / "o" / "report.json").read_text()
    assert "need the owner's own go-ahead" not in text  # past the approval guard...
    assert "WEBCARE_ACCESS_TOKEN" in text  # ...and stopped at the missing token instead
