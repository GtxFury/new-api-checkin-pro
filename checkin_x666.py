#!/usr/bin/env python3
"""
x666.me 自动签到

- 旧流程（兼容保留）：qd.x666.me 抽奖拿 CDK，然后到 x666.me 充值
- 新流程：qd.x666.me 使用 linux.do OAuth 登录并点击“签到”，再登录 x666.me 获取余额
"""

import json
import os
import hashlib
import time
from pathlib import Path
from datetime import datetime

import httpx


class X666CheckIn:
	"""x666 签到管理类"""

	QD_ORIGIN = 'https://qd.x666.me'
	UP_ORIGIN = 'https://up.x666.me'
	X666_ORIGIN = 'https://x666.me'

	def __init__(self, account_name: str, *, proxy_config: dict | None = None):
		self.account_name = account_name
		self.safe_account_name = ''.join(c if c.isalnum() else '_' for c in account_name)

		self.http_proxy_config = self._get_http_proxy(proxy_config)

	def _new_httpx_client(self, *, http2: bool = False, timeout: float = 30.0) -> httpx.Client:
		kwargs: dict = {'http2': http2, 'timeout': timeout}
		proxy = self.http_proxy_config
		if proxy is not None:
			kwargs['proxy'] = proxy
		return httpx.Client(**kwargs)

	@staticmethod
	def _get_http_proxy(proxy_config: dict | None = None) -> httpx.URL | None:
		if not proxy_config:
			return None
		proxy_url = proxy_config.get('server')
		if not proxy_url:
			return None
		username = proxy_config.get('username')
		password = proxy_config.get('password')
		if username and password:
			parsed = httpx.URL(proxy_url)
			return parsed.copy_with(username=username, password=password)
		return httpx.URL(proxy_url)

	def _check_and_handle_response(self, response: httpx.Response, context: str = 'response') -> dict | None:
		logs_dir = 'logs'
		os.makedirs(logs_dir, exist_ok=True)

		try:
			return response.json()
		except json.JSONDecodeError as e:
			print(f'❌ {self.account_name}: Failed to parse JSON response: {e}')

			timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
			safe_context = ''.join(c if c.isalnum() else '_' for c in context)
			content_type = response.headers.get('content-type', '').lower()

			if 'text/html' in content_type or 'text/plain' in content_type:
				filename = f'{self.safe_account_name}_{timestamp}_{safe_context}.html'
			else:
				filename = f'{self.safe_account_name}_{timestamp}_{safe_context}_invalid.txt'

			filepath = os.path.join(logs_dir, filename)
			try:
				with open(filepath, 'w', encoding='utf-8') as f:
					f.write(response.text)
				print(f'⚠️ {self.account_name}: Invalid/HTML response saved to: {filepath}')
			except Exception:
				pass
			return None
		except Exception as e:
			print(f'❌ {self.account_name}: Error occurred while checking response: {e}')
			return None

	def get_user_info(self, client: httpx.Client, headers: dict, auth_token: str) -> tuple[bool, bool, str, float, float]:
		print(f'ℹ️ {self.account_name}: Getting user info')

		info_headers = headers.copy()
		info_headers.update(
			{
				'authorization': f'Bearer {auth_token}',
				'content-length': '0',
				'content-type': 'application/json',
				'origin': 'https://qd.x666.me',
				'referer': 'https://qd.x666.me/',
				'sec-fetch-dest': 'empty',
				'sec-fetch-mode': 'cors',
				'sec-fetch-site': 'same-origin',
			}
		)

		resp = client.post('https://qd.x666.me/api/user/info', headers=info_headers, timeout=30)
		print(f'📨 {self.account_name}: User info response status code {resp.status_code}')

		if resp.status_code != 200:
			return False, False, '', 0.0, 0.0

		json_data = self._check_and_handle_response(resp, 'x666_get_user_info')
		if not isinstance(json_data, dict) or not json_data.get('success'):
			return False, False, '', 0.0, 0.0

		data = json_data.get('data', {}) or {}
		can_spin = bool(data.get('can_spin', False))
		today_record = data.get('today_record')
		cdk = today_record.get('cdk', '') if isinstance(today_record, dict) else ''
		quota_amount = today_record.get('quota_amount', 0) if isinstance(today_record, dict) else 0

		user = data.get('user', {}) or {}
		username = user.get('username', 'Unknown')
		total_quota = user.get('total_quota', 0)
		try:
			total_quota_f = float(total_quota) / 500
		except Exception:
			total_quota_f = 0.0
		print(f'✅ {self.account_name}: User: {username}, Total Quota: {total_quota_f}')
		print(f'ℹ️ {self.account_name}: Can spin: {can_spin}, CDK: {cdk}')

		try:
			quota_amount_f = float(quota_amount) / 500
		except Exception:
			quota_amount_f = 0.0
		return True, can_spin, str(cdk or ''), quota_amount_f, total_quota_f

	def execute_spin(self, client: httpx.Client, headers: dict, auth_token: str) -> tuple[bool, str, float]:
		print(f'🎰 {self.account_name}: Executing spin')

		spin_headers = headers.copy()
		spin_headers.update(
			{
				'authorization': f'Bearer {auth_token}',
				'content-length': '0',
				'content-type': 'application/json',
				'origin': 'https://qd.x666.me',
				'referer': 'https://qd.x666.me/',
				'sec-fetch-dest': 'empty',
				'sec-fetch-mode': 'cors',
				'sec-fetch-site': 'same-origin',
			}
		)

		resp = client.post('https://qd.x666.me/api/lottery/spin', headers=spin_headers, timeout=30)
		print(f'📨 {self.account_name}: Spin response status code {resp.status_code}')

		if resp.status_code not in (200, 400):
			return False, '', 0.0

		json_data = self._check_and_handle_response(resp, 'x666_execute_spin')
		if not isinstance(json_data, dict):
			print(f'❌ {self.account_name}: Spin failed - Invalid response format')
			return False, '', 0.0

		message = json_data.get('message', json_data.get('msg', '')) or ''
		if json_data.get('success'):
			data = json_data.get('data', {}) or {}
			label = data.get('label', 'Unknown')
			cdk = data.get('cdk', '')
			quota = data.get('quota', 0)
			print(f'✅ {self.account_name}: Spin successful! Prize: {label}, CDK: {cdk}')
			try:
				quota_f = float(quota) / 500
			except Exception:
				quota_f = 0.0
			return True, str(cdk or ''), quota_f

		if isinstance(message, str) and ('already' in message.lower() or '已经' in message or '已抽' in message):
			print(f'✅ {self.account_name}: Already spun today!')
			return True, '', 0.0

		print(f'❌ {self.account_name}: Spin failed - {message or "Unknown error"}')
		return False, '', 0.0

	def execute_topup(self, client: httpx.Client, headers: dict, cookies: dict, api_user: str | int, cdk: str) -> bool:
		print(f'💰 {self.account_name}: Executing topup with CDK: {cdk}')

		client.cookies.update(cookies or {})

		topup_headers = headers.copy()
		topup_headers.update(
			{
				'accept': 'application/json, text/plain, */*',
				'content-type': 'application/json',
				'cache-control': 'no-store',
				'new-api-user': str(api_user),
				'origin': 'https://x666.me',
				'referer': 'https://x666.me/console/topup',
				'sec-fetch-dest': 'empty',
				'sec-fetch-mode': 'cors',
				'sec-fetch-site': 'same-origin',
			}
		)

		resp = client.post('https://x666.me/api/user/topup', headers=topup_headers, json={'key': cdk}, timeout=30)
		print(f'📨 {self.account_name}: Topup response status code {resp.status_code}')

		if resp.status_code not in (200, 400):
			print(f'❌ {self.account_name}: Topup failed - HTTP {resp.status_code}')
			return False

		json_data = self._check_and_handle_response(resp, 'x666_execute_topup')
		if not isinstance(json_data, dict):
			print(f'❌ {self.account_name}: Topup failed - Invalid response format')
			return False

		message = json_data.get('message', json_data.get('msg', '')) or ''
		if json_data.get('success') or json_data.get('code') == 0:
			print(f'✅ {self.account_name}: Topup successful!')
			return True

		if isinstance(message, str) and ('already' in message.lower() or '已被使用' in message or '已使用' in message):
			print(f'✅ {self.account_name}: Already claimed topup today!')
			return True

		print(f'❌ {self.account_name}: Topup failed - {message or "Unknown error"}')
		return False

	@staticmethod
	def _env_bool(name: str, default: bool = False) -> bool:
		raw = str(os.getenv(name, '') or '').strip().lower()
		if not raw:
			return default
		if raw in {'1', 'true', 'yes', 'on'}:
			return True
		if raw in {'0', 'false', 'no', 'off'}:
			return False
		return default

	def _logs_dir(self) -> str:
		logs_dir = 'logs'
		os.makedirs(logs_dir, exist_ok=True)
		return logs_dir

	async def _take_screenshot(self, page, name: str) -> None:
		try:
			ts = datetime.now().strftime('%Y%m%d_%H%M%S')
			filename = f'{self.safe_account_name}_{ts}_{name}.png'
			path = os.path.join(self._logs_dir(), filename)
			await page.screenshot(path=path, full_page=True)
		except Exception:
			pass

	@staticmethod
	def _parse_amount(raw: object, *, quota_per_unit: float) -> float:
		try:
			v = float(raw)  # type: ignore[arg-type]
		except Exception:
			try:
				s = str(raw or '').replace(',', '').replace('￥', '').replace('$', '').strip()
				v = float(s)
			except Exception:
				return 0.0

		if quota_per_unit > 0 and abs(v) > quota_per_unit * 2:
			return v / quota_per_unit
		return v

	async def _linuxdo_login_if_needed(self, page, username: str, password: str) -> None:
		try:
			cur = page.url or ''
		except Exception:
			cur = ''

		if '/login' not in cur and 'linux.do' not in cur and 'connect.linux.do' not in cur:
			return

		# 若已在授权页且有 approve，则不需要进登录页
		try:
			if await page.query_selector('a[href^="/oauth2/approve"]'):
				return
		except Exception:
			pass

		try:
			await page.goto('https://linux.do/login', wait_until='domcontentloaded')
		except Exception:
			return

		# 尝试复用通用的 CF/Turnstile 处理（可选依赖）
		try:
			from sign_in_with_linuxdo import solve_captcha, _should_try_turnstile_solver  # type: ignore

			try:
				await solve_captcha(page, captcha_type='cloudflare', challenge_type='interstitial')
			except Exception:
				pass
			if _should_try_turnstile_solver():
				try:
					await solve_captcha(page, captcha_type='cloudflare', challenge_type='turnstile')
				except Exception:
					pass
		except Exception:
			pass

		async def _set_value(selectors: list[str], value: str) -> bool:
			for sel in selectors:
				try:
					ok = await page.evaluate(
						"""({ sel, value }) => {
							try {
								const el = document.querySelector(sel);
								if (!el) return false;
								el.focus();
								el.value = value;
								el.dispatchEvent(new Event('input', { bubbles: true }));
								el.dispatchEvent(new Event('change', { bubbles: true }));
								return true;
							} catch (e) {
								return false;
							}
						}""",
						{'sel': sel, 'value': value},
					)
					if ok:
						return True
				except Exception:
					continue
			return False

		user_ok = await _set_value(
			[
				'#login-account-name',
				'#signin_username',
				'input[name="login"]',
				'input[name="username"]',
				'input[type="email"]',
				'input[autocomplete="username"]',
			],
			username,
		)
		pwd_ok = await _set_value(
			[
				'#login-account-password',
				'#signin_password',
				'input[name="password"]',
				'input[type="password"]',
				'input[autocomplete="current-password"]',
			],
			password,
		)
		if not user_ok or not pwd_ok:
			await self._take_screenshot(page, 'linuxdo_login_inputs_not_found')
			raise RuntimeError('linux.do 登录页未找到可输入的账号/密码框')

		clicked = False
		for sel in [
			'#signin-button',
			'#login-button',
			'button:has-text("登录")',
			'button[type="submit"]',
			'input[type="submit"]',
		]:
			try:
				btn = await page.query_selector(sel)
				if btn:
					await btn.click()
					clicked = True
					break
			except Exception:
				continue
		if not clicked:
			try:
				await page.press('#login-account-password', 'Enter')
			except Exception:
				pass

		try:
			await page.wait_for_function(
				"""() => {
					const u = location.href || '';
					if (u.includes('/oauth2/authorize')) return true;
					if (!u.includes('/login')) return true;
					const t = document.body ? (document.body.innerText || '') : '';
					return t.includes('授权') || t.includes('Authorize') || t.includes('/oauth2/approve');
				}""",
				timeout=30000,
			)
		except Exception:
			await self._take_screenshot(page, 'linuxdo_login_timeout')
			raise RuntimeError('linux.do 登录提交超时（可能被 Cloudflare/风控拦截）')

	async def _click_first(self, page, selectors: list[str], *, timeout_ms: int = 6000) -> bool:
		deadline = time.time() + max(0.5, timeout_ms / 1000.0)
		last_err: Exception | None = None
		while time.time() < deadline:
			for sel in selectors:
				try:
					ele = await page.query_selector(sel)
					if not ele:
						continue
					await ele.click()
					return True
				except Exception as e:
					last_err = e
					continue
			await page.wait_for_timeout(250)
		if last_err:
			return False
		return False

	async def _x666_oauth_login_via_ui(self, page, origin: str, *, username: str, password: str) -> None:
		await page.goto(origin, wait_until='domcontentloaded')
		await page.wait_for_timeout(800)

		# 若已登录，通常不会出现明显的“登录/登陆”入口；这里尽量只在能找到入口时点击
		login_clicked = await self._click_first(
			page,
			[
				'button:has-text("登录")',
				'a:has-text("登录")',
				'button:has-text("登陆")',
				'a:has-text("登陆")',
				'a[href*="/login"]',
				'button:has-text("Login")',
				'a:has-text("Login")',
			],
			timeout_ms=2500,
		)
		if login_clicked:
			await page.wait_for_timeout(800)

		# 若出现 provider 选择页/弹窗，点 linux.do
		_ = await self._click_first(
			page,
			[
				'button:has-text("linux.do")',
				'a:has-text("linux.do")',
				'button:has-text("Linux.do")',
				'a:has-text("Linux.do")',
				'button:has-text("Linux")',
				'a:has-text("Linux")',
			],
			timeout_ms=2500,
		)
		await page.wait_for_timeout(500)

		# 进入 linux.do / connect.linux.do 登录/授权流程
		await self._linuxdo_login_if_needed(page, username, password)

		# 授权按钮
		approved = await self._click_first(
			page,
			[
				'a[href^="/oauth2/approve"]',
				'button:has-text("允许")',
				'button:has-text("授权")',
				'button:has-text("Authorize")',
				'button:has-text("Allow")',
			],
			timeout_ms=12000,
		)
		if approved:
			try:
				await page.wait_for_url(f'**{origin}/**', timeout=30000)
			except Exception:
				pass

		# 如果仍停留在 linux.do/connect.linux.do，兜底回站点域名（部分站点授权后会自动跳回其它同系域名，如 up.x666.me）
		try:
			cur = page.url or ''
			if ('linux.do' in cur) or ('connect.linux.do' in cur):
				await page.goto(origin, wait_until='domcontentloaded')
				await page.wait_for_timeout(800)
		except Exception:
			pass

	async def _qd_checkin(self, page) -> tuple[bool, str]:
		# 不要无脑切回 qd.x666.me：OAuth 回调会把 token 写在 up.x666.me 的 localStorage，
		# 如果此处强行 goto qd，会导致 token 丢失（不同 origin 不共享 localStorage）。
		try:
			cur = page.url or ''
		except Exception:
			cur = ''

		if not (cur.startswith(self.QD_ORIGIN) or cur.startswith(self.UP_ORIGIN)):
			await page.goto(f'{self.QD_ORIGIN}/', wait_until='domcontentloaded')
			await page.wait_for_timeout(800)

		# 若当前在 qd 且未拿到 token，尝试跳到 up（很多情况下 token 实际写在 up）
		try:
			is_qd = (page.url or '').startswith(self.QD_ORIGIN)
			if is_qd:
				token = await page.evaluate("() => { try { return localStorage.getItem('token'); } catch(e){ return null; } }")
				if not token:
					await page.goto(f'{self.UP_ORIGIN}/', wait_until='domcontentloaded')
					await page.wait_for_timeout(1200)
		except Exception:
			pass

		# 优先用接口判断状态（避免仅依赖 UI 文案/组件类型）
		can_spin: bool | None = None
		try:
			status_obj = await page.evaluate(
				"""async () => {
					try {
						const r = await fetch('/api/checkin/status', { credentials: 'include' });
						const j = await r.json();
						return j;
					} catch (e) { return null; }
				}"""
			)
			if isinstance(status_obj, dict) and status_obj.get('success'):
				can_spin = bool((status_obj.get('data', {}) or {}).get('can_spin'))
				if can_spin is False:
					return True, '今日已签到'
		except Exception:
			pass

		# 有些 UI 会显示 “已签到/今日已签到”
		try:
			if await page.query_selector('button:has-text("已签到")') or await page.query_selector(
				'button:has-text("今日已签到")'
			):
				return True, '今日已签到'
		except Exception:
			pass

		clicked = await self._click_first(
			page,
			[
				'button:has-text("开始转动")',
				'button:has-text("开始抽奖")',
				'button:has-text("开始")',
				'button:has-text("签到")',
				'a:has-text("签到")',
				'button:has-text("Check")',
				'a:has-text("Check")',
			],
			timeout_ms=8000,
		)
		if not clicked:
			await self._take_screenshot(page, 'qd_checkin_button_not_found')
			return False, '未找到签到按钮'

		# 等待状态变化或 toast；若接口可用，优先等 can_spin 变为 false
		try:
			if can_spin is True:
				await page.wait_for_function(
					"""async () => {
						try {
							const r = await fetch('/api/checkin/status', { credentials: 'include' });
							const j = await r.json();
							if (!j || !j.success) return false;
							const data = j.data || {};
							return data.can_spin === false;
						} catch (e) { return false; }
					}""",
					timeout=30000,
				)
			else:
				await page.wait_for_function(
					"""() => {
						const t = document.body ? (document.body.innerText || '') : '';
						return (
							t.includes('签到成功') ||
							t.includes('已签到') ||
							t.includes('今日已签到') ||
							t.includes('已经签到') ||
							t.includes('恭喜') ||
							t.includes('获得')
						);
					}""",
					timeout=30000,
				)
		except Exception:
			# 可能 UI 不提示；退化为“按钮状态变化”判断
			try:
				if await page.query_selector('button:has-text("已签到")') or await page.query_selector(
					'button:has-text("今日已签到")'
				):
					return True, '今日已签到'
			except Exception:
				pass
			await self._take_screenshot(page, 'qd_checkin_timeout')
			return False, '签到状态未确认（可能需要人工处理验证码/风控）'

		return True, '签到成功'

	async def _x666_get_balance(self, page) -> dict:
		origin = self.X666_ORIGIN
		quota_per_unit = 500000.0
		api_user: str | int | None = None

		# 先尝试 localStorage.user（很多 new-api 会写入）
		try:
			ls_user = await page.evaluate(
				"""() => {
					try {
						const v = localStorage.getItem('user');
						if (!v) return null;
						const obj = JSON.parse(v);
						return obj && typeof obj === 'object' ? obj : null;
					} catch (e) { return null; }
				}"""
			)
		except Exception:
			ls_user = None

		if isinstance(ls_user, dict):
			try:
				qpu = ls_user.get('quota_per_unit')
				if qpu:
					quota_per_unit = float(qpu)
			except Exception:
				pass
			api_user = ls_user.get('id')
			quota = self._parse_amount(ls_user.get('quota', 0), quota_per_unit=quota_per_unit)
			used_quota = self._parse_amount(ls_user.get('used_quota', 0), quota_per_unit=quota_per_unit)
			bonus_quota = self._parse_amount(ls_user.get('bonus_quota', 0), quota_per_unit=quota_per_unit)
			if quota:
				return {
					'success': True,
					'api_user': api_user,
					'quota': round(quota, 2),
					'used_quota': round(used_quota, 2),
					'bonus_quota': round(bonus_quota, 2),
					'display': f'Current balance: {quota:.2f}, Used: {used_quota:.2f}, Bonus: {bonus_quota:.2f}',
				}

		# 再用同源 fetch('/api/user/self')（不依赖 UI）
		try:
			resp = await page.evaluate(
				"""async (apiUser) => {
					try {
						const headers = { 'accept': 'application/json, text/plain, */*', 'cache-control': 'no-store' };
						if (apiUser !== null && apiUser !== undefined && String(apiUser).length > 0) {
							headers['new-api-user'] = String(apiUser);
						}
						const r = await fetch('/api/user/self', { credentials: 'include', headers });
						const status = r.status;
						const text = await r.text();
						return { status, text };
					} catch (e) {
						return { status: 0, text: String(e) };
					}
				}""",
				str(api_user or ''),
			)
		except Exception as e:
			return {'success': False, 'error': f'fetch /api/user/self 失败: {e}'}

		if not isinstance(resp, dict) or int(resp.get('status') or 0) != 200:
			return {
				'success': False,
				'error': f'/api/user/self HTTP {resp.get("status") if isinstance(resp, dict) else "N/A"}',
			}

		try:
			obj = json.loads(resp.get('text') or '{}')
		except Exception:
			return {'success': False, 'error': '解析 /api/user/self JSON 失败'}

		data = obj.get('data', {}) if isinstance(obj, dict) else {}
		qpu = data.get('quota_per_unit')
		try:
			if qpu:
				quota_per_unit = float(qpu)
		except Exception:
			pass

		quota = self._parse_amount(data.get('quota', 0), quota_per_unit=quota_per_unit)
		used_quota = self._parse_amount(data.get('used_quota', 0), quota_per_unit=quota_per_unit)
		bonus_quota = self._parse_amount(data.get('bonus_quota', 0), quota_per_unit=quota_per_unit)
		api_user = data.get('id') or data.get('user_id') or api_user

		return {
			'success': True,
			'api_user': api_user,
			'quota': round(quota, 2),
			'used_quota': round(used_quota, 2),
			'bonus_quota': round(bonus_quota, 2),
			'display': f'Current balance: {quota:.2f}, Used: {used_quota:.2f}, Bonus: {bonus_quota:.2f}',
		}

	async def execute(self, access_token: str, cookies: dict, api_user: str | int) -> tuple[bool, dict]:
		print(f'\n\n⏳ 开始处理 {self.account_name}')
		print(f'ℹ️ {self.account_name}: 执行 x666 签到 (using proxy: {"true" if self.http_proxy_config else "false"})')

		client = self._new_httpx_client(http2=False, timeout=30.0)
		try:
			headers = {
				'accept': '*/*',
				'accept-language': 'en,en-US;q=0.9,zh;q=0.8,en-CN;q=0.7,zh-CN;q=0.6,am;q=0.5',
				'cache-control': 'no-cache',
				'pragma': 'no-cache',
				'priority': 'u=1, i',
				'sec-ch-ua': '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
				'sec-ch-ua-mobile': '?0',
				'sec-ch-ua-platform': '"macOS"',
				'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
				'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
			}

			# 站点需要这个 cookie（原实现如此）
			client.cookies.set('i18next', 'en')

			results = {'spin': False, 'topup': False, 'quota_amount': 0.0, 'total_quota': 0.0}
			cdk = ''
			quota_amount = 0.0
			total_quota = 0.0

			info_success, can_spin, existing_cdk, existing_quota, total_quota = self.get_user_info(
				client, headers, access_token
			)
			if not info_success:
				return False, {'error': '获取用户信息失败（/api/user/info）'}

			results['total_quota'] = total_quota

			if can_spin:
				spin_success, cdk, quota_amount = self.execute_spin(client, headers, access_token)
				results['spin'] = bool(spin_success)
				results['quota_amount'] = quota_amount
				if spin_success:
					total_quota += quota_amount
					results['total_quota'] = total_quota
			else:
				print(f'✅ {self.account_name}: 今日已抽奖，使用已有 CDK')
				results['spin'] = True
				cdk = existing_cdk
				quota_amount = existing_quota
				results['quota_amount'] = quota_amount

			if cdk:
				topup_success = self.execute_topup(client, headers, cookies, api_user, cdk)
				results['topup'] = bool(topup_success)
			else:
				print(f'⚠️ {self.account_name}: 无可用 CDK，跳过 topup')
				results['topup'] = True

			overall_success = bool(results['spin']) and bool(results['topup'])
			return overall_success, results
		except Exception as e:
			return False, {'error': f'x666 签到异常: {e}'}
		finally:
			client.close()

	async def execute_with_linuxdo(self, username: str, password: str) -> tuple[bool, dict]:
		"""新流程：在 qd.x666.me 使用 linux.do OAuth 登录 -> 点击签到 -> 登录 x666.me 获取余额"""
		print(f'\n\n⏳ 开始处理 {self.account_name}')
		print(f'ℹ️ {self.account_name}: 执行 x666 新签到流程（linux.do OAuth）')

		try:
			from camoufox.async_api import AsyncCamoufox
		except Exception as e:
			return False, {'checkin': False, 'error': f'缺少浏览器依赖 camoufox: {e}'}

		headless = self._env_bool('HEADLESS', False)
		storage_dir = Path('storage-states') / 'x666'
		storage_dir.mkdir(parents=True, exist_ok=True)
		username_hash = hashlib.sha256(username.encode('utf-8')).hexdigest()[:8]
		cache_file = str(storage_dir / f'linuxdo_{username_hash}_storage_state.json')

		async with AsyncCamoufox(
			headless=headless,
			humanize=True,
			locale='zh-CN',
			disable_coop=True,
			config={'forceScopeAccess': True},
			i_know_what_im_doing=True,
			window=(1280, 720),
		) as browser:
			storage_state = cache_file if os.path.exists(cache_file) else None
			context = await browser.new_context(storage_state=storage_state)
			page = await context.new_page()

			try:
				# 1) 登录 qd.x666.me 并签到
				await self._x666_oauth_login_via_ui(page, self.QD_ORIGIN, username=username, password=password)
				ok, msg = await self._qd_checkin(page)

				# 保存/更新 linux.do 会话缓存（避免后续频繁触发 CF/风控）
				try:
					if '/login' not in (page.url or ''):
						await context.storage_state(path=cache_file)
				except Exception:
					pass

				if not ok:
					return False, {'checkin': False, 'error': msg}

				# 2) 登录 x666.me 并读取余额
				await self._x666_oauth_login_via_ui(page, self.X666_ORIGIN, username=username, password=password)

				# 尽量落到控制台/主页，确保 localStorage/API 就绪
				for path in ['/console', '/app/me', '/app', '/']:
					try:
						await page.goto(f'{self.X666_ORIGIN}{path}', wait_until='domcontentloaded')
						await page.wait_for_timeout(800)
						break
					except Exception:
						continue

				balance = await self._x666_get_balance(page)
				if not balance.get('success'):
					await self._take_screenshot(page, 'x666_balance_failed')
					return False, {'checkin': True, 'error': balance.get('error', '获取余额失败')}

				return True, {
					'checkin': True,
					'checkin_msg': msg,
					'quota': balance.get('quota', 0.0),
					'used_quota': balance.get('used_quota', 0.0),
					'bonus_quota': balance.get('bonus_quota', 0.0),
					'display': balance.get('display', ''),
				}
			except Exception as e:
				await self._take_screenshot(page, 'x666_flow_exception')
				return False, {'checkin': False, 'error': f'x666 新签到流程异常: {e}'}
			finally:
				try:
					await context.close()
				except Exception:
					pass
