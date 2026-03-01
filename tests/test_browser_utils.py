import sys
from pathlib import Path


project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from utils.browser_utils import parse_cookies


def test_parse_cookies_from_dict():
    data = {"session": "abc", "_t": "123"}
    assert parse_cookies(data) == {"session": "abc", "_t": "123"}


def test_parse_cookies_from_cookie_string():
    data = "session=abc; _t=123"
    assert parse_cookies(data) == {"session": "abc", "_t": "123"}


def test_parse_cookies_from_browser_export_list():
    data = [
        {"domain": "linux.do", "name": "_t", "value": "token_value", "httpOnly": True},
        {"domain": "linux.do", "name": "_forum_session", "value": "session_value", "httpOnly": True},
    ]
    assert parse_cookies(data) == {"_t": "token_value", "_forum_session": "session_value"}

