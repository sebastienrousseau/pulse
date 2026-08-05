"""Shared pytest fixtures."""

from __future__ import annotations

import subprocess
from collections.abc import Iterator
from typing import Any

import pytest

TOKEN_ENV_VARS = ("GITHUB_TOKEN", "GH_TOKEN", "PULSE_GITHUB_TOKEN")


@pytest.fixture
def no_ambient_github_token(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Make the machine look like it has no GitHub credentials at all.

    PulseConfig.get_github_token() reads three environment variables and then
    shells out to `gh auth token`. Clearing only the environment leaves the
    `gh` fallback live, so on any developer machine with an authenticated gh
    CLI these tests fail -- and print the real token into the assertion diff.
    CI has no gh auth, which is why they passed there and nowhere else.

    monkeypatch restores the environment afterwards; the previous approach used
    os.environ.pop() with no restore, leaking the cleared state into later tests.
    """
    for var in TOKEN_ENV_VARS:
        monkeypatch.delenv(var, raising=False)

    real_run = subprocess.run

    def fake_run(cmd: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(cmd, (list, tuple)) and list(cmd[:2]) == ["gh", "auth"]:
            raise FileNotFoundError("gh is unavailable in this test")
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", fake_run)
    yield
