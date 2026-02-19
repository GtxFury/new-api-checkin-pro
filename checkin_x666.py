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
from urllib.parse import quote

import httpx


class _TokenExpiredError(Exception):
	"""storage state 中的 token 已过期，需要清缓存重新登录"""


class X666CheckIn:
	"""x666 签到管理类"""

	QD_ORIGIN = 'https://qd.x666.me'
	UP_ORIGIN = 'https://up.x666.me'
	X666_ORIGIN = 'https://x666.me'
	# qd/up 侧 linux.do OAuth 固定参数（站点改动时可能需要更新）
	QD_LINUXDO_CLIENT_ID = 'p4V7ALyYtjreFlru3Mp5V5enzhpMYxcy'
	QD_LINUXDO_REDIRECT_URI = 'https://up.x666.me/api/auth/callback'

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

		resp = client.post('https://qd.x666.me/api/checkin/spin', headers=spin_headers, timeout=30)
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

	async def _save_page_html(self, page, name: str) -> None:
		try:
			ts = datetime.now().strftime('%Y%m%d_%H%M%S')
			filename = f'{self.safe_account_name}_{ts}_{name}.html'
			path = os.path.join(self._logs_dir(), filename)
			html = await page.content()
			with open(path, 'w', encoding='utf-8') as f:
				f.write(html)
		except Exception:
			pass

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

		# connect.linux.do 无 session 时会重定向到 linux.do/login，但重定向可能还没完成
		if ('connect.linux.do' in cur or 'linux.do' in cur) and 'linux.do/login' not in cur:
			try:
				await page.wait_for_url('**/login*', timeout=15000)
				cur = page.url or ''
			except Exception:
				try:
					cur = page.url or ''
				except Exception:
					cur = ''

		# 仅当确实处于 linux.do 的登录页时才填表；若已登录会被重定向到首页/授权页，此时不应误判失败。
		if 'linux.do/login' not in cur:
			return

		await page.wait_for_timeout(800)
		await self._take_screenshot(page, 'linuxdo_login_page')
		await self._save_page_html(page, 'linuxdo_login_page')

		# 尝试复用通用的 CF Interstitial 处理（可选依赖）。
		# 说明：Turnstile click solver 在部分环境（如 Actions 出口 IP）容易反复超时刷屏，
		# 这里默认不强依赖“点验证码”，而是优先等待页面自己放行/渲染出登录表单。
		try:
			from sign_in_with_linuxdo import solve_captcha  # type: ignore

			try:
				await solve_captcha(page, captcha_type='cloudflare', challenge_type='interstitial')
			except Exception:
				pass
		except Exception:
			pass

		# 等待登录输入框出现（如果停留在 CF/风控页面，这里能更快暴露原因并产出日志）
		try:
			await page.wait_for_function(
				"""() => {
					try {
						// linux.do 登录页近期 UI/属性可能变化：兼容 id/name/autocomplete/aria-label/type=text
						const u =
							document.querySelector(
								'#login-account-name, #signin_username, input[name=\"login\"], input[name=\"username\"], input[autocomplete=\"username\"], input[type=\"email\"], input[type=\"text\"], input[aria-label*=\"邮件\"], input[aria-label*=\"用户名\"]'
							);
						const p =
							document.querySelector(
								'#login-account-password, #signin_password, input[name=\"password\"], input[autocomplete=\"current-password\"], input[type=\"password\"], input[aria-label*=\"密码\"]'
							);
						return !!(u && p);
					} catch (e) { return false; }
				}""",
				timeout=90000,
			)
		except Exception:
			await self._take_screenshot(page, 'linuxdo_login_inputs_wait_timeout')
			await self._save_page_html(page, 'linuxdo_login_inputs_wait_timeout')

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
				'input[type="text"]',
				'input[autocomplete="username"]',
				'input[aria-label*="邮件"]',
				'input[aria-label*="用户名"]',
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
				'input[aria-label*="密码"]',
			],
			password,
		)
		if not user_ok or not pwd_ok:
			try:
				meta = await page.evaluate(
					"""() => {
						try {
							const title = document.title || '';
							const hasCfIframe = !!document.querySelector('iframe[src*=\"challenges.cloudflare.com\"]');
							const body = document.body ? (document.body.innerText || '').slice(0, 400) : '';
							return { title, hasCfIframe, body };
						} catch (e) { return { error: String(e) }; }
					}"""
				)
				print(f'⚠️ {self.account_name}: linux.do 登录页输入框检测失败，页面信息: {meta}')
			except Exception:
				pass
			await self._take_screenshot(page, 'linuxdo_login_inputs_not_found')
			await self._save_page_html(page, 'linuxdo_login_inputs_not_found')
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
			await self._save_page_html(page, 'linuxdo_login_timeout')
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

	async def _click_newapi_linuxdo_continue(self, page) -> bool:
		"""点击 new-api 登录页的「使用 LinuxDO 继续」按钮（逻辑参考 checkin_fovt.py）。"""
		try:
			await page.wait_for_selector('button:has-text("使用 LinuxDO 继续")', timeout=10000)
			print(f'ℹ️ {self.account_name}: LinuxDO continue button appeared')
		except Exception:
			print(f'⚠️ {self.account_name}: Timeout waiting for LinuxDO continue button')

		login_btn = None
		for sel in [
			'button:has-text("使用 LinuxDO 继续")',
			'button:has-text("使用 LinuxDO")',
			'button:has-text("使用 Linux Do 登录")',
			'button:has-text("Linux Do")',
			'button:has-text("LinuxDO")',
			'a:has-text("Linux Do")',
			'a:has-text("使用 Linux Do 登录")',
			'a[href*="linuxdo" i]',
		]:
			try:
				ele = await page.query_selector(sel)
				if ele:
					login_btn = ele
					print(f'ℹ️ {self.account_name}: Found LinuxDO login button: {sel}')
					break
			except Exception:
				continue

		if login_btn:
			try:
				await login_btn.click()
				print(f'ℹ️ {self.account_name}: Clicked LinuxDO login button')
			except Exception:
				try:
					await page.evaluate('(el) => el && el.click && el.click()', login_btn)
					print(f'ℹ️ {self.account_name}: Clicked LinuxDO login button via JS')
				except Exception:
					return False
		else:
			print(f'ℹ️ {self.account_name}: LinuxDO button not found, trying JS fallback...')
			try:
				clicked = await page.evaluate(
					"""() => {
						const buttons = Array.from(document.querySelectorAll('button'));
						const btn = buttons.find(x => {
							const t = x.innerText || '';
							return (t.includes('LinuxDO') || t.includes('Linux Do')) && (t.includes('继续') || t.includes('登录'));
						});
						if (btn) { btn.click(); return true; }
						return false;
					}"""
				)
				if clicked:
					print(f'ℹ️ {self.account_name}: Clicked LinuxDO via JS fallback')
				else:
					return False
			except Exception:
				return False

		await page.wait_for_timeout(1200)
		return True

	async def _switch_to_context_page_by_host(
		self,
		page,
		hosts: tuple[str, ...],
		*,
		timeout_ms: int = 15000,
	) -> object | None:
		"""在同一 browser context 中寻找某个 host 的页面并切换（用于处理 OAuth 打开新标签页）。"""
		try:
			ctx = page.context
		except Exception:
			return None
		deadline = time.time() + max(1.0, timeout_ms / 1000.0)
		while time.time() < deadline:
			try:
				pages = list(getattr(ctx, 'pages', []) or [])
			except Exception:
				pages = []
			for p in pages:
				try:
					u = getattr(p, 'url', '') or ''
					# 避免切到已关闭页
					if not u:
						continue
					for h in hosts:
						if h in u:
							return p
				except Exception:
					continue
			try:
				await page.wait_for_timeout(500)
			except Exception:
				break
		return None

	async def _x666_oauth_login_via_ui(self, page, origin: str, *, username: str, password: str):
		# x666.me 是 new-api 前端首页 iframe 较多；直接进入 /login 更稳
		if origin.rstrip('/') == self.X666_ORIGIN.rstrip('/'):
			try:
				await page.goto(f'{origin}/login', wait_until='domcontentloaded')
			except Exception:
				await page.goto(origin, wait_until='domcontentloaded')
			await page.wait_for_timeout(800)
		else:
			await page.goto(origin, wait_until='domcontentloaded')
			await page.wait_for_timeout(800)

		observed_oauth_urls: list[str] = []
		try:
			def _record_oauth(u: str) -> None:
				try:
					if not u:
						return
					if 'connect.linux.do/oauth2/authorize' in u:
						if u not in observed_oauth_urls:
							observed_oauth_urls.append(u)
				except Exception:
					return

			def on_request(req) -> None:
				try:
					_record_oauth(req.url)
				except Exception:
					return

			def on_frame_navigated(frame) -> None:
				try:
					_record_oauth(frame.url)
				except Exception:
					return

			page.on('request', on_request)
			page.on('framenavigated', on_frame_navigated)
		except Exception:
			pass

		popup_page = None
		try:
			def on_popup(p) -> None:
				nonlocal popup_page
				try:
					popup_page = p
				except Exception:
					pass

			page.on('popup', on_popup)
		except Exception:
			pass

		# 若已登录，通常不会出现明显的“登录/登陆”入口；这里尽量只在能找到入口时点击
		try:
			print(f'ℹ️ {self.account_name}: OAuth/UI login at {origin}, current url: {page.url}')
		except Exception:
			pass

		# 记录页面基础信息，便于排查“没点到按钮/按钮被遮挡/页面没渲染”
		try:
			meta = await page.evaluate(
				"""() => {
					try {
						const title = document.title || '';
						const loginBtn =
							!!document.querySelector('button') &&
							!!Array.from(document.querySelectorAll('button,a')).find(el => (el.innerText || '').includes('登录') || (el.innerText || '').includes('登陆'));
						const hasLogout =
							!!Array.from(document.querySelectorAll('button,a')).find(el => (el.innerText || '').includes('退出'));
						return { title, loginBtn, hasLogout, url: location.href };
					} catch (e) { return { error: String(e), url: location.href }; }
				}"""
			)
			print(f'ℹ️ {self.account_name}: {origin} page meta: {meta}')
		except Exception:
			pass

		# x666.me/new-api：使用专用「使用 LinuxDO 继续」按钮触发 OAuth
		if origin.rstrip('/') == self.X666_ORIGIN.rstrip('/'):
			login_clicked = await self._click_newapi_linuxdo_continue(page)
		else:
			login_clicked = await self._click_first(
				page,
				[
					'button:has-text("登录")',
					'a:has-text("登录")',
					'button:has-text("登陆")',
					'a:has-text("登陆")',
					'a[href*="/login"]',
					'a[href="/login"]',
					'button:has-text("Login")',
					'a:has-text("Login")',
				],
				timeout_ms=2500,
			)
		print(f'ℹ️ {self.account_name}: {origin} login button clicked: {"yes" if login_clicked else "no"}')
		if origin.rstrip('/') == self.X666_ORIGIN.rstrip('/') and not login_clicked:
			# new-api 登录页没找到 LinuxDO 按钮：不要继续“乱点 provider”，直接产出现场便于排查
			await self._take_screenshot(page, 'x666_login_button_not_found')
			await self._save_page_html(page, 'x666_login_button_not_found')
			raise RuntimeError('x666.me 登录页未找到「使用 LinuxDO 继续」按钮')
		if login_clicked:
			await page.wait_for_timeout(800)
			# 如果点击触发了新窗口（popup），切换到 popup 继续流程
			try:
				if popup_page is not None:
					try:
						await popup_page.wait_for_load_state('domcontentloaded', timeout=15000)
					except Exception:
						pass
					page = popup_page
					print(f'ℹ️ {self.account_name}: Switched to popup page for OAuth, url={getattr(page, "url", None) or ""}')
			except Exception:
				pass

			# 等待跳转到 linux.do/connect.linux.do 授权页（否则后续流程会“看似卡住”）。
			# 部分环境 click 可能不触发导航，但仍能在 request 里捕获到 authorize URL；此时用 URL 兜底导航。
			try:
				await page.wait_for_function(
					"""(origin) => {
						try {
							const u = location.href || '';
							if (u.startsWith(origin)) return false;
							return u.includes('connect.linux.do') || u.includes('linux.do') || u.includes('/oauth2/');
						} catch (e) { return false; }
					}""",
					origin,
					timeout=15000,
				)
			except Exception:
				# 如果捕获到了 oauth2/authorize 请求，用它兜底
				try:
					if observed_oauth_urls:
						fallback = observed_oauth_urls[0]
						print(f'⚠️ {self.account_name}: click 后未跳转，使用捕获到的 OAuth URL 兜底导航: {fallback}')
						try:
							await page.goto(fallback, wait_until='domcontentloaded')
							await page.wait_for_timeout(800)
						except Exception as e:
							await self._take_screenshot(page, 'oauth_authorize_goto_failed')
							await self._save_page_html(page, 'oauth_authorize_goto_failed')
							raise RuntimeError(f'OAuth authorize 跳转失败: {e}')
					elif origin.rstrip('/') in {self.QD_ORIGIN.rstrip('/'), self.UP_ORIGIN.rstrip('/')}:
						# qd/up：再兜底一层，直接构造 connect.linux.do authorize URL
						state = str(time.time_ns())
						fallback = (
							'https://connect.linux.do/oauth2/authorize?'
							f'client_id={self.QD_LINUXDO_CLIENT_ID}'
							f'&redirect_uri={quote(self.QD_LINUXDO_REDIRECT_URI, safe="")}'
							'&response_type=code&scope=read'
							f'&state={state}'
						)
						print(f'⚠️ {self.account_name}: click 后未跳转且未捕获 URL，使用默认 OAuth URL 兜底导航: {fallback}')
						try:
							await page.goto(fallback, wait_until='domcontentloaded')
							await page.wait_for_timeout(800)
						except Exception as e:
							await self._take_screenshot(page, 'oauth_authorize_goto_failed')
							await self._save_page_html(page, 'oauth_authorize_goto_failed')
							raise RuntimeError(f'OAuth authorize 跳转失败: {e}')
					else:
						await self._take_screenshot(page, 'oauth_login_no_navigation')
						await self._save_page_html(page, 'oauth_login_no_navigation')
						raise RuntimeError('点击登录后未能跳转到 linux.do 授权页（可能被遮挡/风控/页面未响应）')
				except Exception:
					# 保持原有错误语义
					raise

		# 若出现 provider 选择页/弹窗，点 linux.do
		# 注意：x666.me/new-api 的登录已由「使用 LinuxDO 继续」触发，这里不应再进入 provider 选择逻辑
		if origin.rstrip('/') == self.X666_ORIGIN.rstrip('/'):
			provider_clicked = False
		else:
			provider_clicked = await self._click_first(
				page,
				[
					'button:has-text("linux.do")',
					'a:has-text("linux.do")',
					'button:has-text("Linux.do")',
					'a:has-text("Linux.do")',
					'button:has-text("Linux")',
					'a:has-text("Linux")',
					'button:has-text("LinuxDO")',
					'a:has-text("LinuxDO")',
				],
				timeout_ms=2500,
			)
		if provider_clicked:
			print(f'ℹ️ {self.account_name}: {origin} provider option clicked: linux.do')
			# provider click 后也可能不导航：同样用捕获到的 OAuth URL 兜底
			try:
				if observed_oauth_urls and not ('connect.linux.do' in (page.url or '')):
					await page.goto(observed_oauth_urls[0], wait_until='domcontentloaded')
					await page.wait_for_timeout(800)
			except Exception:
				pass
		await page.wait_for_timeout(500)

		# 进入 linux.do / connect.linux.do 登录/授权流程
		await self._linuxdo_login_if_needed(page, username, password)

		# 监听回调 URL 捕获 code 参数（参考 fovt 实现）
		captured_callback_urls: list[str] = []

		def _capture_callback(u: str) -> None:
			try:
				if u and 'up.x666.me' in u and 'code=' in u:
					if u not in captured_callback_urls:
						captured_callback_urls.append(u)
			except Exception:
				pass

		try:
			page.on('request', lambda req: _capture_callback(req.url))
			page.on('framenavigated', lambda frame: _capture_callback(frame.url))
		except Exception:
			pass

		# 授权按钮
		try:
			print(f'ℹ️ {self.account_name}: OAuth before approve, url={page.url}')
		except Exception:
			pass
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
		print(f'ℹ️ {self.account_name}: OAuth approve clicked: {"yes" if approved else "no"}')
		if not approved:
			# 这里常见两种情况：1) 已登录且已自动授权并跳回站点；2) 被 CF/风控卡在中间页
			try:
				cur = page.url or ''
				if ('linux.do' in cur) or ('connect.linux.do' in cur):
					await self._take_screenshot(page, 'oauth_approve_not_found')
					await self._save_page_html(page, 'oauth_approve_not_found')
			except Exception:
				pass
		else:
			# qd.x666.me 的 redirect_uri 实际会落到 up.x666.me；这里不能只等 origin 本身
			try:
				if origin.rstrip('/') == self.QD_ORIGIN.rstrip('/'):
					# 先等跳出 linux.do/connect.linux.do，且落在 *.x666.me 域（通常是 up.x666.me）
					await page.wait_for_function(
						"""() => {
							try {
								const u = location.href || '';
								const h = location.hostname || '';
								if (!h.endsWith('x666.me')) return false;
								return !u.includes('linux.do') && !u.includes('connect.linux.do');
							} catch (e) { return false; }
						}""",
						timeout=60000,
					)

					# 处理"OAuth 打开新标签页"的情况：优先切到 up.x666.me 那个页
					try:
						alt = await self._switch_to_context_page_by_host(page, ('up.x666.me',), timeout_ms=8000)
						if alt is not None:
							page = alt
							# 立即从 URL 提取 token（SPA 会很快清掉 URL 参数）
							from urllib.parse import urlparse, parse_qs
							cur_url = page.url or ''
							print(f'ℹ️ {self.account_name}: Switched to up.x666.me, url={cur_url[:80]}')
							parsed = urlparse(cur_url)
							qs = parse_qs(parsed.query)
							url_token = (qs.get('token') or [''])[0]
							if url_token:
								await page.evaluate("""(t) => { try { localStorage.setItem('userToken', t); } catch(e){} }""", url_token)
								print(f'ℹ️ {self.account_name}: Token from URL saved to localStorage')
					except Exception:
						pass

					# 检查 localStorage 是否已有 token
					existing_token = await page.evaluate("() => { try { return localStorage.getItem('userToken'); } catch(e){ return null; } }")
					if existing_token:
						print(f'ℹ️ {self.account_name}: Token in localStorage (len={len(str(existing_token))})')
					else:
						# 尝试从捕获的回调 URL 提取 code 并调用回调 API
						from urllib.parse import urlparse, parse_qs
						callback_url = captured_callback_urls[0] if captured_callback_urls else (page.url or '')
						print(f'ℹ️ {self.account_name}: No token, trying callback: {callback_url[:80]}...')
						parsed = urlparse(callback_url)
						qs = parse_qs(parsed.query)
						code = (qs.get('code') or [''])[0]

						if code:
							print(f'ℹ️ {self.account_name}: Calling callback API with code')
							try:
								result = await page.evaluate(
									"""async (code) => {
										try {
											const url = 'https://up.x666.me/api/auth/callback?code=' + encodeURIComponent(code);
											const resp = await fetch(url, { credentials: 'include' });
											const text = await resp.text();
											return { status: resp.status, text: text.slice(0, 500) };
										} catch (e) { return { status: 0, error: e.message }; }
									}""",
									code,
								)
								print(f'ℹ️ {self.account_name}: Callback response: status={result.get("status")}')
								if result.get('status') == 200:
									try:
										import json as _json
										data = _json.loads(result.get('text', '{}'))
										token = None
										if isinstance(data, dict):
											token = data.get('token') or data.get('access_token') or (data.get('data', {}) or {}).get('token')
										if token:
											await page.evaluate("""(t) => { try { localStorage.setItem('userToken', t); } catch(e){} }""", token)
											print(f'ℹ️ {self.account_name}: Token from callback saved')
									except Exception:
										pass
							except Exception as e:
								print(f'⚠️ {self.account_name}: Callback API error: {e}')

					# 再等 up.x666.me 写入 token（SPA/回调可能需要时间）
					try:
						await page.wait_for_function(
							"""() => {
								try {
									return !!localStorage.getItem('userToken');
								} catch (e) { return false; }
							}""",
							timeout=15000,
						)
					except Exception:
						# 如果不在 up 域，导航到 up 再等（如果 token 已写入，会直接存在）
						try:
							if not (page.url or '').startswith('https://up.x666.me'):
								await page.goto('https://up.x666.me/', wait_until='domcontentloaded')
								await page.wait_for_timeout(1200)
							await page.wait_for_function(
								"""() => {
									try { return !!localStorage.getItem('userToken'); } catch (e) { return false; }
								}""",
								timeout=15000,
							)
						except Exception:
							await self._take_screenshot(page, 'qd_oauth_callback_token_missing')
							await self._save_page_html(page, 'qd_oauth_callback_token_missing')
				else:
					await page.wait_for_url(f'**{origin}/**', timeout=30000)
			except Exception:
				# 不直接失败，后续由"登录态校验"兜底判定
				pass

		# 如果仍停留在 linux.do/connect.linux.do，兜底回站点域名（部分站点授权后会自动跳回其它同系域名，如 up.x666.me）
		try:
			cur = page.url or ''
			if ('linux.do' in cur) or ('connect.linux.do' in cur):
				await page.goto(origin, wait_until='domcontentloaded')
				await page.wait_for_timeout(800)
		except Exception:
			pass
		return page

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
				token = await page.evaluate("() => { try { return localStorage.getItem('userToken'); } catch(e){ return null; } }")
				if not token:
					await page.goto(f'{self.UP_ORIGIN}/', wait_until='domcontentloaded')
					await page.wait_for_timeout(1200)
		except Exception:
			pass

		# 必须拿到 token（存放在 up.x666.me localStorage），否则后续接口调用无法鉴权。
		try:
			token = await page.evaluate("() => { try { return localStorage.getItem('userToken'); } catch(e){ return null; } }")
		except Exception:
			token = None

		if not token:
			# 允许给回调一点时间：切到 up.x666.me 再等一次（SPA 写 localStorage 可能延后）
			try:
				await page.goto(f'{self.UP_ORIGIN}/', wait_until='domcontentloaded')
				await page.wait_for_timeout(1200)
				await page.wait_for_function(
					"""() => {
						try { return !!localStorage.getItem('userToken'); } catch (e) { return false; }
					}""",
					timeout=45000,
				)
				token = await page.evaluate("() => { try { return localStorage.getItem('userToken'); } catch(e){ return null; } }")
			except Exception:
				token = None

		if not token:
			await self._take_screenshot(page, 'qd_no_token')
			await self._save_page_html(page, 'qd_no_token')
			return False, '未获取到 token（OAuth 回调可能未完成/被风控拦截）'

		print(f'ℹ️ {self.account_name}: qd token present (len={len(str(token))}) at {page.url}')

		async def _auth_fetch_json(path: str, method: str = 'GET') -> dict:
			print(f'ℹ️ {self.account_name}: _auth_fetch_json {method} {path} from {page.url}')
			resp = await page.evaluate(
				"""async ({ path, method }) => {
					try {
						const token = localStorage.getItem('userToken');
						if (!token) return { ok: false, status: 0, error: 'no_token' };
						const t = String(token || '').trim();
						const auth = t.toLowerCase().startsWith('bearer ') ? t : `Bearer ${t}`;
						const headers = {
							'accept': 'application/json, text/plain, */*',
							'cache-control': 'no-store',
							'pragma': 'no-cache',
							'authorization': auth,
						};
						let opts = { method, headers, credentials: 'include' };
						// qd/up 的接口一般是空 POST，不要强塞 JSON body，避免后端严格校验 content-length
						const r = await fetch(path, opts);
						const text = await r.text();
						let json = null;
						try { json = JSON.parse(text); } catch (e) {}
						return { ok: r.ok, status: r.status, text: text.slice(0, 200), json };\n\
					} catch (e) {\n\
						return { ok: false, status: 0, error: String(e) };\n\
					}\n\
				}""",
				{'path': path, 'method': method},
			)
			return resp if isinstance(resp, dict) else {'ok': False, 'status': 0, 'error': 'invalid_resp'}

		# 1) 先用 /api/user/info 验证 token 有效性（前端也是这么做的）
		info_resp = await _auth_fetch_json('/api/user/info', 'GET')
		if info_resp.get('status') == 401:
			raise _TokenExpiredError('token已过期')
		info_json = info_resp.get('json') if isinstance(info_resp, dict) else None
		if isinstance(info_json, dict) and info_json.get('success'):
			print(f'ℹ️ {self.account_name}: 用户验证通过: {info_json.get(“username”, “?”)}')
		else:
			print(f'⚠️ {self.account_name}: /api/user/info 响应: {info_resp}')

		# 2) 直接调用签到接口（跟前端 spin() 一样，不先检查 can_spin）
		spin_resp = await _auth_fetch_json('/api/checkin/spin', 'POST')
		spin_json = spin_resp.get('json') if isinstance(spin_resp, dict) else None
		if spin_resp.get('status') == 401:
			raise _TokenExpiredError('token已过期')

		if isinstance(spin_json, dict):
			if spin_json.get('success'):
				label = spin_json.get('label', '')
				quota = spin_json.get('quota', 0)
				print(f'ℹ️ {self.account_name}: spin 成功: {label}, quota={quota}')
				return True, f'签到成功（{label}）'
			msg = spin_json.get('message', spin_json.get('msg', '')) or ''
			if isinstance(msg, str) and ('already' in msg.lower() or '已签到' in msg or '已经' in msg):
				return True, '今日已签到'
			# API 返回了其他错误 → 不直接失败，回退到 UI 点按钮
			print(f'⚠️ {self.account_name}: /api/checkin/spin 返回: {spin_json}，回退到 UI')
		else:
			print(f'⚠️ {self.account_name}: /api/checkin/spin 无有效响应(HTTP {spin_resp.get(“status”)})，回退到 UI')

		# 3) API 未能完成签到，回退到页面 UI 点击按钮
		try:
			cur = page.url or ''
			if not cur.startswith(self.QD_ORIGIN):
				await page.goto(f'{self.QD_ORIGIN}/', wait_until='domcontentloaded')
				await page.wait_for_timeout(1500)
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
			await self._save_page_html(page, 'qd_checkin_button_not_found')
			return False, '未找到签到按钮'

		# 等待抽奖接口返回（比 UI 文案更可靠）。
		try:
			resp = await page.wait_for_response(
				lambda r: '/api/checkin/spin' in (r.url or ''),
				timeout=30000,
			)
			try:
				if resp and resp.status in (200, 400):
					j = await resp.json()
					if isinstance(j, dict):
						if j.get('success'):
							label = j.get('label', '')
							return True, f'签到成功（{label}）'
						msg = j.get('message', j.get('msg', '')) or ''
						if isinstance(msg, str) and ('already' in msg.lower() or '已签到' in msg or '已经' in msg):
							return True, '今日已签到'
			except Exception:
				pass

			# 兜底：再查一次状态（can_spin 在顶层，不在 data 下）
			status2 = await _auth_fetch_json('/api/checkin/status', 'GET')
			j2 = status2.get('json') if isinstance(status2, dict) else None
			if isinstance(j2, dict) and j2.get('success'):
				if j2.get('can_spin') is False:
					return True, '签到成功'
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
			await self._save_page_html(page, 'qd_checkin_timeout')
			return False, '签到状态未确认（可能被风控/接口无响应）'

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

	async def _x666_login_and_get_balance(self, page, context, username: str, password: str) -> dict:
		"""登录 x666.me 并获取余额（参考 fovt 的 OAuth 流程）"""
		from urllib.parse import quote, urlparse, parse_qs

		# 1) 先检查是否已登录
		await page.goto(f'{self.X666_ORIGIN}/console', wait_until='domcontentloaded')
		await page.wait_for_timeout(1500)

		cur_url = page.url or ''
		if '/login' not in cur_url:
			balance = await self._x666_get_balance(page)
			if balance.get('success'):
				return balance

		# 2) 未登录，获取 OAuth state 并构造 URL
		await page.goto(f'{self.X666_ORIGIN}/login', wait_until='domcontentloaded')
		await page.wait_for_timeout(1000)

		try:
			state_result = await page.evaluate(
				"""async () => {
					try {
						const resp = await fetch('/api/oauth/state?provider=linuxdo');
						return await resp.json();
					} catch (e) { return { success: false, error: e.message }; }
				}"""
			)
			auth_state = (state_result or {}).get('data', '')
			if not auth_state:
				return {'success': False, 'error': '获取 OAuth state 失败'}
			print(f'ℹ️ {self.account_name}: x666 OAuth state: {auth_state}')
		except Exception as e:
			return {'success': False, 'error': f'OAuth state 错误: {e}'}

		# 3) 监听回调 URL 捕获 code
		captured_urls: list[str] = []
		def _capture(u: str) -> None:
			if u and 'x666.me' in u and 'code=' in u:
				if u not in captured_urls:
					captured_urls.append(u)
		try:
			page.on('request', lambda req: _capture(req.url))
			page.on('framenavigated', lambda frame: _capture(frame.url))
		except Exception:
			pass

		# 4) 用 x666.me 自己的 OAuth 参数（从站点获取）
		redirect_uri = f'{self.X666_ORIGIN}/api/oauth/linuxdo'
		# 尝试从站点获取 client_id
		try:
			config = await page.evaluate(
				"""async () => {
					try {
						const resp = await fetch('/api/status');
						const data = await resp.json();
						return data.data || data;
					} catch (e) { return {}; }
				}"""
			)
			client_id = (config or {}).get('linuxdo_client_id', '')
		except Exception:
			client_id = ''

		if not client_id:
			# 兜底：尝试从页面 JS 获取
			try:
				client_id = await page.evaluate(
					"""() => {
						try {
							// 尝试从全局变量或 window 获取
							return window.LINUXDO_CLIENT_ID || window.__LINUXDO_CLIENT_ID__ || '';
						} catch (e) { return ''; }
					}"""
				)
			except Exception:
				client_id = ''

		if not client_id:
			print(f'⚠️ {self.account_name}: 未找到 x666 client_id，尝试用页面按钮触发 OAuth')
			# 用页面按钮触发
			clicked = await self._click_newapi_linuxdo_continue(page)
			if not clicked:
				return {'success': False, 'error': '未找到 LinuxDO 登录按钮'}
		else:
			print(f'ℹ️ {self.account_name}: x666 client_id: {client_id[:8]}...')
			oauth_url = (
				'https://connect.linux.do/oauth2/authorize?'
				f'response_type=code&client_id={client_id}&state={auth_state}'
				f'&redirect_uri={quote(redirect_uri, safe="")}'
			)
			await page.goto(oauth_url, wait_until='domcontentloaded')
			await page.wait_for_timeout(1000)

		# 5) 如果需要登录 linux.do
		await self._linuxdo_login_if_needed(page, username, password)

		# 6) 点击授权按钮
		approved = await self._click_first(
			page,
			['a[href^="/oauth2/approve"]', 'button:has-text("允许")', 'button:has-text("授权")'],
			timeout_ms=10000,
		)
		print(f'ℹ️ {self.account_name}: x666 OAuth approve clicked: {"yes" if approved else "no"}')

		# 7) 等待回调并捕获 code
		await page.wait_for_timeout(3000)
		callback_url = captured_urls[0] if captured_urls else (page.url or '')
		print(f'ℹ️ {self.account_name}: x666 回调 URL: {callback_url[:80]}...')

		parsed = urlparse(callback_url)
		qs = parse_qs(parsed.query)
		code = (qs.get('code') or [''])[0]

		if code:
			# 手动调用回调 API
			print(f'ℹ️ {self.account_name}: 调用 x666 回调 API')
			try:
				result = await page.evaluate(
					"""async ({ code, state }) => {
						try {
							const url = '/api/oauth/linuxdo?code=' + encodeURIComponent(code) + '&state=' + encodeURIComponent(state);
							const resp = await fetch(url, { credentials: 'include' });
							const text = await resp.text();
							return { status: resp.status, text: text.slice(0, 500) };
						} catch (e) { return { status: 0, error: e.message }; }
					}""",
					{'code': code, 'state': auth_state},
				)
				print(f'ℹ️ {self.account_name}: x666 回调响应: status={result.get("status")}')
			except Exception as e:
				print(f'⚠️ {self.account_name}: x666 回调失败: {e}')

		# 8) 等待 localStorage user
		await page.wait_for_timeout(2000)
		try:
			await page.wait_for_function(
				"""() => { try { return !!localStorage.getItem('user'); } catch (e) { return false; } }""",
				timeout=10000,
			)
			print(f'ℹ️ {self.account_name}: x666 localStorage user 已就绪')
		except Exception:
			print(f'⚠️ {self.account_name}: x666 localStorage user 未出现，尝试导航到 console')
			await page.goto(f'{self.X666_ORIGIN}/console', wait_until='domcontentloaded')
			await page.wait_for_timeout(2000)

		# 9) 获取余额
		print(f'ℹ️ {self.account_name}: 开始获取 x666 余额')
		return await self._x666_get_balance(page)

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

			async def _run_flow(use_cache: bool) -> tuple[bool, dict]:
				"""执行完整的 OAuth 登录 + 签到 + 余额查询流程"""
				storage_state = cache_file if use_cache and os.path.exists(cache_file) else None
				context = await browser.new_context(storage_state=storage_state)
				page = await context.new_page()

				try:
					page = await self._x666_oauth_login_via_ui(page, self.QD_ORIGIN, username=username, password=password)
					ok, msg = await self._qd_checkin(page)
					print(f'{"✅" if ok else "❌"} {self.account_name}: qd 签到结果: {msg}')

					# 保存/更新 linux.do 会话缓存
					try:
						if '/login' not in (page.url or ''):
							await context.storage_state(path=cache_file)
					except Exception:
						pass

					if not ok:
						return False, {'checkin': False, 'error': msg}

					print(f'ℹ️ {self.account_name}: 开始登录 x666.me 查询余额')
					balance = await self._x666_login_and_get_balance(page, context, username, password)
					if not balance.get('success'):
						await self._take_screenshot(page, 'x666_balance_failed')
						await self._save_page_html(page, 'x666_balance_failed')
						return False, {'checkin': True, 'error': balance.get('error', '获取余额失败')}

					print(f'✅ {self.account_name}: 余额查询成功: {balance.get("display", "")}')
					return True, {
						'checkin': True,
						'checkin_msg': msg,
						'quota': balance.get('quota', 0.0),
						'used_quota': balance.get('used_quota', 0.0),
						'bonus_quota': balance.get('bonus_quota', 0.0),
						'display': balance.get('display', ''),
					}
				finally:
					try:
						await context.close()
					except Exception:
						pass

			# 第一次尝试（使用缓存）
			try:
				return await _run_flow(use_cache=True)
			except _TokenExpiredError:
				print(f'⚠️ {self.account_name}: token 已过期，清除缓存并重新登录')
				try:
					if os.path.exists(cache_file):
						os.remove(cache_file)
						print(f'ℹ️ {self.account_name}: 已删除缓存 {cache_file}')
				except Exception as e:
					print(f'⚠️ {self.account_name}: 删除缓存失败: {e}')

			# 第二次尝试（无缓存，走完整登录流程）
			try:
				return await _run_flow(use_cache=False)
			except Exception as e:
				print(f'❌ {self.account_name}: x666 重新登录后仍失败: {e}')
				return False, {'checkin': False, 'error': f'x666 重新登录后仍失败: {e}'}
