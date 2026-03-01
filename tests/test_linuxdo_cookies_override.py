import sys
from pathlib import Path

import pytest


project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from utils.linuxdo_cookies_override import apply_linuxdo_cookies_override


def test_apply_global_cookie_dict(monkeypatch: pytest.MonkeyPatch):
    accounts = [{"name": "a1"}, {"name": "a2", "linux.do": {"username": "u", "password": "p"}}]
    monkeypatch.setenv("LINUXDO_COOKIES", '{"_t":"tt","_forum_session":"ss"}')

    applied = apply_linuxdo_cookies_override(accounts, accounts_env_key="ACCOUNTS")

    assert applied == 2
    assert accounts[0]["linux.do"]["cookies"]["_t"] == "tt"
    assert accounts[1]["linux.do"]["cookies"]["_forum_session"] == "ss"


def test_apply_by_workflow_key(monkeypatch: pytest.MonkeyPatch):
    accounts = [{"name": "a1"}, {"name": "a2"}]
    monkeypatch.setenv(
        "LINUXDO_COOKIES",
        '{"ACCOUNTS":{"_t":"main"},"ACCOUNTS_KFC":{"_t":"kfc"}}',
    )

    applied = apply_linuxdo_cookies_override(accounts, accounts_env_key="ACCOUNTS_KFC")

    assert applied == 2
    assert accounts[0]["linux.do"]["cookies"]["_t"] == "kfc"


def test_apply_by_index_array(monkeypatch: pytest.MonkeyPatch):
    accounts = [{"name": "a1"}, {"name": "a2"}]
    monkeypatch.setenv(
        "LINUXDO_COOKIES",
        '[{"_t":"a1t"}, {"_t":"a2t"}]',
    )

    applied = apply_linuxdo_cookies_override(accounts, accounts_env_key="ACCOUNTS")

    assert applied == 2
    assert accounts[0]["linux.do"]["cookies"]["_t"] == "a1t"
    assert accounts[1]["linux.do"]["cookies"]["_t"] == "a2t"

