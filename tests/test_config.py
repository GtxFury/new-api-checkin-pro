import sys
from pathlib import Path

import pytest

# 添加项目根目录到 PATH
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from utils.config import AppConfig


def test_default_providers_include_kfc(monkeypatch: pytest.MonkeyPatch):
	monkeypatch.delenv('PROVIDERS', raising=False)
	cfg = AppConfig.load_from_env()

	provider = cfg.get_provider('kfc')
	assert provider is not None
	assert provider.origin == 'https://kfc-api.sxxe.net'
	assert provider.sign_in_path is None
	assert provider.checkin_mode == 'newapi_console_personal'


def test_default_providers_include_neb(monkeypatch: pytest.MonkeyPatch):
	monkeypatch.delenv('PROVIDERS', raising=False)
	cfg = AppConfig.load_from_env()

	provider = cfg.get_provider('neb')
	assert provider is not None
	assert provider.origin == 'https://ai.zzhdsgsss.xyz'
	assert provider.sign_in_path is None
	assert provider.checkin_mode == 'newapi_console_personal'


def test_default_providers_include_huan(monkeypatch: pytest.MonkeyPatch):
	monkeypatch.delenv('PROVIDERS', raising=False)
	cfg = AppConfig.load_from_env()

	provider = cfg.get_provider('huan')
	assert provider is not None
	assert provider.origin == 'https://ai.huan666.de'
	assert provider.sign_in_path == '/api/user/checkin'
	assert provider.checkin_mode == 'new_api_post'


def test_default_providers_include_taizi(monkeypatch: pytest.MonkeyPatch):
	monkeypatch.delenv('PROVIDERS', raising=False)
	cfg = AppConfig.load_from_env()

	provider = cfg.get_provider('taizi')
	assert provider is not None
	assert provider.origin == 'https://api.codeme.me'
	assert provider.sign_in_path == '/api/user/checkin'
	assert provider.checkin_mode == 'new_api_post'


def test_default_providers_include_mu(monkeypatch: pytest.MonkeyPatch):
	monkeypatch.delenv('PROVIDERS', raising=False)
	cfg = AppConfig.load_from_env()

	provider = cfg.get_provider('mu')
	assert provider is not None
	assert provider.origin == 'https://demo.awa1.fun'
	assert provider.sign_in_path == '/api/user/checkin'
	assert provider.checkin_mode == 'new_api_post'


def test_default_providers_include_daiju(monkeypatch: pytest.MonkeyPatch):
	monkeypatch.delenv('PROVIDERS', raising=False)
	cfg = AppConfig.load_from_env()

	provider = cfg.get_provider('daiju')
	assert provider is not None
	assert provider.origin == 'https://api.daiju.live'
	assert provider.sign_in_path is None
	assert provider.checkin_mode == 'newapi_console_personal'
