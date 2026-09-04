"""Tests for onboarding: the `help` welcome screen and the first-run walkthrough."""
import io

from rich.console import Console

from ghostops import onboarding


def _console() -> Console:
    # non-terminal sink: rich strips markup -> plain text we can assert on
    return Console(file=io.StringIO(), force_terminal=False, width=100)


def test_welcome_lists_real_commands_and_warning():
    c = _console()
    onboarding.welcome(c)
    out = c.file.getvalue()
    for token in ("engage", "scan", "report", "setup", "model", "next", "help"):
        assert token in out
    assert "Authorized use only" in out


def test_first_run_detection_toggles_with_flag(tmp_path, monkeypatch):
    flag = tmp_path / ".onboarded"
    monkeypatch.setattr(onboarding, "_flag_path", lambda: flag)
    assert onboarding.is_first_run() is True
    onboarding.mark_onboarded()
    assert flag.exists()
    assert onboarding.is_first_run() is False


def test_walkthrough_gating(tmp_path, monkeypatch):
    flag = tmp_path / ".onboarded"
    monkeypatch.setattr(onboarding, "_flag_path", lambda: flag)

    # interactive + first run -> show
    monkeypatch.setattr(onboarding, "_interactive", lambda: True)
    assert onboarding.should_show_walkthrough() is True

    # non-interactive / piped -> never
    monkeypatch.setattr(onboarding, "_interactive", lambda: False)
    assert onboarding.should_show_walkthrough() is False

    # interactive but explicitly skipped
    monkeypatch.setattr(onboarding, "_interactive", lambda: True)
    assert onboarding.should_show_walkthrough(no_intro=True) is False
    monkeypatch.setenv("GHOSTOPS_NO_INTRO", "1")
    assert onboarding.should_show_walkthrough() is False
    monkeypatch.delenv("GHOSTOPS_NO_INTRO")

    # once onboarded -> never again
    onboarding.mark_onboarded()
    assert onboarding.should_show_walkthrough() is False


def test_first_run_offers_setup_on_bare_and_launches_on_yes(monkeypatch):
    called = {"setup": False}
    monkeypatch.setattr("ghostops.setup_wizard.run_setup",
                        lambda: called.__setitem__("setup", True))
    monkeypatch.setattr("rich.prompt.Confirm.ask", lambda *a, **k: True)
    onboarding.first_run_walkthrough(_console(), invoked_subcommand=None)
    assert called["setup"] is True


def test_first_run_decline_exits_clean_without_setup(monkeypatch):
    called = {"setup": False}
    monkeypatch.setattr("ghostops.setup_wizard.run_setup",
                        lambda: called.__setitem__("setup", True))
    monkeypatch.setattr("rich.prompt.Confirm.ask", lambda *a, **k: False)
    onboarding.first_run_walkthrough(_console(), invoked_subcommand=None)
    assert called["setup"] is False


def test_first_run_with_subcommand_does_not_prompt(monkeypatch):
    # a command was given -> no setup prompt at all
    def boom(*a, **k):
        raise AssertionError("prompted even though a subcommand was invoked")
    monkeypatch.setattr("rich.prompt.Confirm.ask", boom)
    onboarding.first_run_walkthrough(_console(), invoked_subcommand="engage")


# ---- CLI-level: non-interactive never prompts, help renders ----

def test_help_command_renders(monkeypatch, tmp_path):
    from typer.testing import CliRunner
    from ghostops.cli import app
    monkeypatch.setattr(onboarding, "_flag_path", lambda: tmp_path / ".onboarded")
    r = CliRunner().invoke(app, ["help"])
    assert r.exit_code == 0
    assert "engage" in r.output and "Authorized use only" in r.output


def test_bare_invocation_noninteractive_shows_welcome_no_prompt(monkeypatch, tmp_path):
    from typer.testing import CliRunner
    from ghostops.cli import app
    monkeypatch.setattr(onboarding, "_flag_path", lambda: tmp_path / ".onboarded")
    # CliRunner streams are non-TTY -> walkthrough must NOT fire
    r = CliRunner().invoke(app, [])
    assert r.exit_code == 0
    assert "engage" in r.output              # welcome shown
    assert "Run setup now" not in r.output   # no interactive prompt
