"""Packaging smoke tests: the `ghostops` console entry point resolves.

These guard the pipx/console_scripts wiring - if the entry point breaks, a fresh
`pipx install` would ship a `ghostops` command that can't start.
"""
import pytest


def test_app_importable_and_callable():
    from ghostops.cli import app
    assert callable(app)          # Typer app -> setuptools calls app()


def test_console_script_registered_and_resolves():
    from importlib.metadata import entry_points
    from ghostops.cli import app
    eps = [e for e in entry_points(group="console_scripts") if e.name == "ghostops"]
    if not eps:
        pytest.skip("ghostops has no installed metadata (needs editable/pipx install)")
    assert eps[0].value == "ghostops.cli:app"
    assert eps[0].load() is app   # the shim really points at our CLI
