import io
import sys

from webcare.cli import main


class Terminal(io.StringIO):
    def isatty(self):
        return True


def config(tmp_path, extra=""):
    path = tmp_path / "webcare.toml"
    path.write_text('[[target]]\nname = "prod"\nenv = "production"\ndata = "real"\nproject_ref = "' + "a" * 20 + '"\n'
                    + extra)
    return path


def at_terminal(monkeypatch, answer):
    monkeypatch.setattr(sys, "stdin", Terminal(answer))
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)


def test_no_terminal_means_the_usual_refusal(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", io.StringIO("yes\n"))  # not a terminal: the answer is never read
    monkeypatch.delenv("WEBCARE_ACCESS_TOKEN", raising=False)
    main(["check", "--target", "prod", "--via-api", "--config", str(config(tmp_path)), "--out-dir", str(tmp_path / "o")])
    err = capsys.readouterr().err
    assert "Type yes" not in err


def test_at_a_terminal_a_no_stops_before_anything_is_contacted(tmp_path, monkeypatch, capsys):
    at_terminal(monkeypatch, "no\n")
    code = main(["check", "--target", "prod", "--via-api", "--with-backups", "--config", str(config(tmp_path)),
                 "--out-dir", str(tmp_path / "o")])
    captured = capsys.readouterr()
    err = captured.err
    assert code == 2 and "Type yes" in err and "stopped; nothing was contacted" in err
    assert "Type yes" not in captured.out  # never mixed into redirected output
    assert "GET backup list" in err and "no table row" in err
    assert not (tmp_path / "o").exists()


def test_at_a_terminal_a_yes_counts_as_the_owner_approval(tmp_path, monkeypatch, capsys):
    at_terminal(monkeypatch, "yes\n")
    monkeypatch.delenv("WEBCARE_ACCESS_TOKEN", raising=False)
    main(["check", "--target", "prod", "--via-api", "--config", str(config(tmp_path)), "--out-dir", str(tmp_path / "o")])
    text = (tmp_path / "o" / "report.json").read_text()
    assert "need the owner's own go-ahead" not in text  # past the approval guard...
    assert "WEBCARE_ACCESS_TOKEN" in text  # ...and stopped at the missing token instead


def test_no_question_when_only_stdin_is_a_terminal(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", Terminal("yes\n"))  # stderr redirected: nobody would see the warning
    monkeypatch.delenv("WEBCARE_ACCESS_TOKEN", raising=False)
    main(["check", "--target", "prod", "--via-api", "--config", str(config(tmp_path)), "--out-dir", str(tmp_path / "o")])
    assert "Type yes" not in capsys.readouterr().err
    assert "need the owner's own go-ahead" in (tmp_path / "o" / "report.json").read_text()


def test_checks_switched_on_in_the_target_file_are_listed(tmp_path, monkeypatch, capsys):
    at_terminal(monkeypatch, "no\n")
    main(["check", "--target", "prod", "--via-api", "--config", str(config(tmp_path, 'checks = ["platform"]\n')),
          "--out-dir", str(tmp_path / "o")])
    assert "GET SSL enforcement and network restrictions" in capsys.readouterr().err


def test_a_snapshot_file_alone_asks_nothing(tmp_path, monkeypatch, capsys):
    at_terminal(monkeypatch, "no\n")
    snap = tmp_path / "snap.json"
    snap.write_text("{}")
    main(["check", "--target", "prod", "--snapshot", str(snap), "--config", str(config(tmp_path)),
          "--out-dir", str(tmp_path / "o")])
    assert "Type yes" not in capsys.readouterr().err


def test_a_snapshot_with_the_anonymous_probe_asks_about_the_probe_only(tmp_path, monkeypatch, capsys):
    at_terminal(monkeypatch, "no\n")
    snap = tmp_path / "snap.json"
    snap.write_text("{}")
    code = main(["check", "--target", "prod", "--snapshot", str(snap),
                 "--config", str(config(tmp_path, 'rest = "https://' + "a" * 20 + '.supabase.co"\n')),
                 "--out-dir", str(tmp_path / "o")])
    err = capsys.readouterr().err
    assert code == 2 and "HEAD requests to the Data API" in err
    assert "direct connection" not in err and "SELECT statements" not in err
