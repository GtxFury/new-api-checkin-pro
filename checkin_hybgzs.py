#!/usr/bin/env python3
"""
黑与白公益站 (cdk.hybgzs.com) 自动签到

签到流程：
1. 使用 linux.do OAuth 登录 cdk.hybgzs.com
2. 每日签到（需要 Turnstile 验证，通过浏览器完成）
3. 大转盘抽奖（最多 5 次/天）
4. 自动转出额度到公益站主站（当钱包余额 > 阈值时）
"""

import hashlib
import os
from datetime import datetime
from pathlib import Path

try:
	from sign_in_with_linuxdo import solve_captcha, _should_try_turnstile_solver

	CAPTCHA_SOLVER_AVAILABLE = True
except Exception:
	solve_captcha = None
	_should_try_turnstile_solver = lambda: False
	CAPTCHA_SOLVER_AVAILABLE = False


class HybgzsCheckIn:
	"""黑与白公益站签到管理类"""

	ORIGIN = 'https://cdk.hybgzs.com'
	# 内部单位：500000 = $1
	UNIT_PER_DOLLAR = 500000

	def __init__(self, account_name: str, *, proxy_config: dict | None = None, transfer_threshold: float = 0):
		self.account_name = account_name
		self.safe_account_name = ''.join(c if c.isalnum() else '_' for c in account_name)
		self.proxy_config = proxy_config
		# 当钱包余额(美元) > transfer_threshold 时自动转出，0 表示不自动转出
		self.transfer_threshold = transfer_threshold

	# ── 工具方法 ──────────────────────────────────────────────

	@staticmethod
	def _env_bool(name: str, default: bool = False) -> bool:
		raw = str(os.getenv(name, '') or '').strip().lower()
		if raw in {'1', 'true', 'yes', 'on'}:
			return True
		if raw in {'0', 'false', 'no', 'off'}:
			return False
		return default

	def _logs_dir(self) -> str:
		d = 'logs'
		os.makedirs(d, exist_ok=True)
		return d

	async def _take_screenshot(self, page, name: str) -> None:
		try:
			ts = datetime.now().strftime('%Y%m%d_%H%M%S')
			path = os.path.join(self._logs_dir(), f'{self.safe_account_name}_{ts}_{name}.png')
			await page.screenshot(path=path, full_page=True)
		except Exception:
			pass

	async def _save_page_html(self, page, name: str) -> None:
		try:
			ts = datetime.now().strftime('%Y%m%d_%H%M%S')
			path = os.path.join(self._logs_dir(), f'{self.safe_account_name}_{ts}_{name}.html')
			html = await page.content()
			with open(path, 'w', encoding='utf-8') as f:
				f.write(html)
		except Exception:
			pass

	async def _browser_fetch_json(self, page, path: str, method: str = 'GET', body: dict | None = None) -> dict:
		"""在浏览器上下文中发起 API 请求（自动携带 cookie）"""
		script = """async ({ path, method, body }) => {
			try {
				const opts = { method, credentials: 'include', headers: { 'accept': 'application/json' } };
				if (body !== null) {
					opts.headers['content-type'] = 'application/json';
					opts.body = JSON.stringify(body);
				}
				const r = await fetch(path, opts);
				const text = await r.text();
				let json = null;
				try { json = JSON.parse(text); } catch (e) {}
				return { ok: r.ok, status: r.status, json, text: text.slice(0, 500) };
			} catch (e) {
				return { ok: false, status: 0, error: String(e) };
			}
		}"""
		try:
			resp = await page.evaluate(script, {'path': path, 'method': method, 'body': body})
			return resp if isinstance(resp, dict) else {'ok': False, 'status': 0, 'error': 'invalid_resp'}
		except Exception as e:
			return {'ok': False, 'status': 0, 'error': str(e)}

	# ── Linux.do OAuth 登录 ──────────────────────────────────

	async def _linuxdo_login_if_needed(self, page, username: str, password: str) -> None:
		"""如果当前在 linux.do 登录页，填写账号密码并提交"""
		cur = getattr(page, 'url', '') or ''
		if 'linux.do/login' not in cur:
			return

		await page.wait_for_timeout(800)

		# 尝试处理 CF Interstitial
		if CAPTCHA_SOLVER_AVAILABLE and solve_captcha:
			try:
				await solve_captcha(page, captcha_type='cloudflare', challenge_type='interstitial')
			except Exception:
				pass

		# 等待登录输入框
		try:
			await page.wait_for_function(
				"""() => {
					const u = document.querySelector('#login-account-name, input[name="login"], input[type="email"], input[type="text"]');
					const p = document.querySelector('#login-account-password, input[name="password"], input[type="password"]');
					return !!(u && p);
				}""",
				timeout=90000,
			)
		except Exception:
			await self._take_screenshot(page, 'linuxdo_login_timeout')

		# 填写账号密码
		async def _set_value(selectors: list[str], value: str) -> bool:
			for sel in selectors:
				try:
					ok = await page.evaluate(
						"""({ sel, value }) => {
							const el = document.querySelector(sel);
							if (!el) return false;
							el.focus(); el.value = value;
							el.dispatchEvent(new Event('input', { bubbles: true }));
							el.dispatchEvent(new Event('change', { bubbles: true }));
							return true;
						}""",
						{'sel': sel, 'value': value},
					)
					if ok:
						return True
				except Exception:
					continue
			return False

		user_ok = await _set_value(
			['#login-account-name', 'input[name="login"]', 'input[name="username"]', 'input[type="email"]', 'input[type="text"]'],
			username,
		)
		pwd_ok = await _set_value(
			['#login-account-password', 'input[name="password"]', 'input[type="password"]'],
			password,
		)
		if not user_ok or not pwd_ok:
			await self._take_screenshot(page, 'linuxdo_login_inputs_not_found')
			raise RuntimeError('linux.do 登录页未找到账号/密码输入框')

		# 点击登录按钮
		for sel in ['#signin-button', '#login-button', 'button:has-text("登录")', 'button[type="submit"]']:
			try:
				btn = await page.query_selector(sel)
				if btn:
					await btn.click()
					break
			except Exception:
				continue

		# 等待跳转
		try:
			await page.wait_for_function(
				"""() => {
					const u = location.href || '';
					return u.includes('/oauth2/authorize') || !u.includes('/login');
				}""",
				timeout=30000,
			)
		except Exception:
			await self._take_screenshot(page, 'linuxdo_login_submit_timeout')
			raise RuntimeError('linux.do 登录提交超时')

	async def _do_oauth_login(self, page, username: str, password: str) -> bool:
		"""完成 cdk.hybgzs.com 的 Linux.do OAuth 登录"""
		# 导航到站点
		try:
			await page.goto(f'{self.ORIGIN}/dashboard', wait_until='domcontentloaded')
		except Exception as e:
			print(f'⚠️ {self.account_name}: 导航到 dashboard 失败: {e}')
			try:
				await page.goto(self.ORIGIN, wait_until='domcontentloaded')
			except Exception as e2:
				print(f'❌ {self.account_name}: 导航到站点失败: {e2}')
				await self._take_screenshot(page, 'navigate_failed')
				return False
		await page.wait_for_timeout(2000)
		print(f'ℹ️ {self.account_name}: 当前 URL: {page.url}')

		# 检查是否已登录（session API）
		session = await self._browser_fetch_json(page, '/api/auth/session')
		session_json = session.get('json') or {}
		if isinstance(session_json, dict) and session_json.get('user'):
			user = session_json['user']
			print(f'✅ {self.account_name}: 已登录 - {user.get("name", "Unknown")}')
			return True

		print(f'ℹ️ {self.account_name}: 未登录 (session: {str(session_json)[:200]})，开始 OAuth 流程')

		# 导航到登录页
		try:
			await page.goto(f'{self.ORIGIN}/login', wait_until='domcontentloaded')
		except Exception as e:
			print(f'❌ {self.account_name}: 导航到登录页失败: {e}')
			await self._take_screenshot(page, 'login_page_failed')
			return False
		await page.wait_for_timeout(2000)
		print(f'ℹ️ {self.account_name}: 登录页 URL: {page.url}')

		# 检查页面上有哪些按钮
		try:
			page_meta = await page.evaluate(
				"""() => {
					const btns = Array.from(document.querySelectorAll('button'));
					return {
						title: document.title,
						url: location.href,
						buttons: btns.map(b => ({ text: (b.textContent || '').trim().slice(0, 50), disabled: b.disabled })),
						bodySnippet: (document.body?.innerText || '').slice(0, 300),
					};
				}"""
			)
			print(f'ℹ️ {self.account_name}: 登录页信息: buttons={page_meta.get("buttons")}, title={page_meta.get("title")}')
		except Exception as e:
			print(f'⚠️ {self.account_name}: 获取页面信息失败: {e}')

		# 关闭可能存在的公告弹窗（会遮挡登录按钮）
		try:
			dismiss_selectors = [
				'button:has-text("我知道了")',
				'button:has-text("关闭")',
				'button:has-text("确定")',
				'button:has-text("OK")',
				'button:has-text("知道了")',
				'button:has-text("好的")',
				# X / 关闭图标按钮
				'.fixed button[aria-label="Close"]',
				'.fixed button[aria-label="关闭"]',
				'.fixed button svg',
			]
			for sel in dismiss_selectors:
				try:
					dismiss_btn = await page.query_selector(sel)
					if dismiss_btn and await dismiss_btn.is_visible():
						await dismiss_btn.click()
						print(f'ℹ️ {self.account_name}: 关闭了弹窗 [{sel}]')
						await page.wait_for_timeout(500)
						break
				except Exception:
					continue

			# 如果弹窗仍然存在，用 JS 强制移除所有 fixed z-50 遮罩
			removed = await page.evaluate(
				"""() => {
					const overlays = document.querySelectorAll('div.fixed.z-50, div[class*="fixed"][class*="inset-0"]');
					let count = 0;
					overlays.forEach(el => { el.remove(); count++; });
					return count;
				}"""
			)
			if removed:
				print(f'ℹ️ {self.account_name}: JS 移除了 {removed} 个遮罩层')
				await page.wait_for_timeout(500)
		except Exception:
			pass

		# 等待 "LinuxDo 登录" 按钮变为可用（初始为 disabled）
		print(f'ℹ️ {self.account_name}: 等待 LinuxDo 登录按钮启用...')
		try:
			await page.wait_for_function(
				"""() => {
					const btns = Array.from(document.querySelectorAll('button'));
					const btn = btns.find(b => (b.textContent || '').includes('LinuxDo') || (b.textContent || '').includes('Linux Do'));
					return btn && !btn.disabled;
				}""",
				timeout=15000,
			)
			print(f'ℹ️ {self.account_name}: LinuxDo 按钮已启用')
		except Exception as e:
			print(f'⚠️ {self.account_name}: 等待 LinuxDo 按钮超时: {e}')
			await self._take_screenshot(page, 'linuxdo_button_not_ready')
			await self._save_page_html(page, 'linuxdo_button_not_ready')

		# 点击 "LinuxDo 登录" 按钮
		clicked = False
		for sel in ['button:has-text("LinuxDo 登录")', 'button:has-text("LinuxDo")', 'button:has-text("Linux Do")']:
			try:
				btn = await page.query_selector(sel)
				if btn:
					is_enabled = await btn.is_enabled()
					print(f'ℹ️ {self.account_name}: 找到按钮 [{sel}], enabled={is_enabled}')
					if is_enabled:
						try:
							await btn.click(timeout=5000)
						except Exception:
							# 常规点击被遮挡，尝试 force 点击
							print(f'⚠️ {self.account_name}: 常规点击被遮挡，尝试 force 点击')
							try:
								await btn.click(force=True, timeout=5000)
							except Exception:
								# force 也失败，用 JS 直接点击
								print(f'⚠️ {self.account_name}: force 点击也失败，尝试 JS 点击')
								await btn.evaluate('el => el.click()')
						clicked = True
						print(f'ℹ️ {self.account_name}: 点击了 LinuxDo 登录按钮')
						break
			except Exception as e:
				print(f'⚠️ {self.account_name}: 点击按钮 [{sel}] 失败: {e}')
				continue

		if not clicked:
			print(f'❌ {self.account_name}: 未找到可点击的 LinuxDo 登录按钮')
			await self._take_screenshot(page, 'linuxdo_button_not_found')
			await self._save_page_html(page, 'linuxdo_button_not_found')
			return False

		# 等待跳转到 connect.linux.do 授权页
		print(f'ℹ️ {self.account_name}: 等待跳转到 linux.do 授权页...')
		try:
			await page.wait_for_function(
				"""() => {
					const u = location.href || '';
					return u.includes('connect.linux.do') || u.includes('linux.do/login');
				}""",
				timeout=15000,
			)
			print(f'ℹ️ {self.account_name}: 已跳转到: {page.url}')
		except Exception as e:
			print(f'⚠️ {self.account_name}: 等待 OAuth 跳转超时 (当前 URL: {page.url}): {e}')
			await self._take_screenshot(page, 'oauth_redirect_timeout')
			await self._save_page_html(page, 'oauth_redirect_timeout')

		await page.wait_for_timeout(1500)

		# 可能需要在 linux.do 登录
		cur_url = page.url or ''
		print(f'ℹ️ {self.account_name}: OAuth 页面 URL: {cur_url}')
		if 'linux.do/login' in cur_url:
			print(f'ℹ️ {self.account_name}: 检测到 linux.do 登录页，开始填写凭据...')
		await self._linuxdo_login_if_needed(page, username, password)

		await page.wait_for_timeout(1000)
		print(f'ℹ️ {self.account_name}: 登录/授权后 URL: {page.url}')

		# 点击授权按钮（如果出现）
		approve_clicked = False
		for sel in ['a[href*="/oauth2/approve"]', 'button:has-text("允许")', 'button:has-text("授权")', 'button:has-text("Authorize")']:
			try:
				btn = await page.query_selector(sel)
				if btn:
					await btn.click()
					approve_clicked = True
					print(f'ℹ️ {self.account_name}: 点击了授权按钮 [{sel}]')
					break
			except Exception:
				continue

		if not approve_clicked:
			cur = page.url or ''
			if 'connect.linux.do' in cur or 'linux.do' in cur:
				print(f'⚠️ {self.account_name}: 未找到授权按钮，仍在 linux.do (URL: {cur})')
				await self._take_screenshot(page, 'oauth_approve_not_found')
				await self._save_page_html(page, 'oauth_approve_not_found')
			else:
				print(f'ℹ️ {self.account_name}: 无需点击授权（可能已自动授权），当前 URL: {cur}')

		# 等待回调完成，回到站点
		print(f'ℹ️ {self.account_name}: 等待回调完成...')
		try:
			await page.wait_for_function(
				f"""() => {{
					const u = location.href || '';
					return u.startsWith('{self.ORIGIN}') && !u.includes('/login');
				}}""",
				timeout=30000,
			)
			print(f'ℹ️ {self.account_name}: 回调完成，URL: {page.url}')
		except Exception as e:
			print(f'⚠️ {self.account_name}: 等待回调超时 (当前 URL: {page.url}): {e}')
			await self._take_screenshot(page, 'oauth_callback_timeout')
			await self._save_page_html(page, 'oauth_callback_timeout')

		await page.wait_for_timeout(2000)

		# 验证登录状态
		session = await self._browser_fetch_json(page, '/api/auth/session')
		session_json = session.get('json') or {}
		if isinstance(session_json, dict) and session_json.get('user'):
			user = session_json['user']
			print(f'✅ {self.account_name}: OAuth 登录成功 - {user.get("name", "Unknown")}')
			return True

		print(f'❌ {self.account_name}: OAuth 登录失败 (session: {str(session_json)[:200]}, URL: {page.url})')
		await self._take_screenshot(page, 'oauth_login_failed')
		await self._save_page_html(page, 'oauth_login_failed')
		return False

	# ── 每日签到 ──────────────────────────────────────────────

	async def _do_checkin(self, page) -> tuple[bool, str]:
		"""执行每日签到（需要 Turnstile 验证）"""
		# 检查签到状态
		status = await self._browser_fetch_json(page, '/api/checkin/status')
		status_json = status.get('json') or {}
		if not (isinstance(status_json, dict) and status_json.get('success')):
			return False, f'获取签到状态失败 (HTTP {status.get("status")})'

		# 导航到签到页面
		await page.goto(f'{self.ORIGIN}/gas-station/checkin', wait_until='domcontentloaded')
		await page.wait_for_timeout(3000)

		# 查找并点击签到按钮
		checkin_btn = None
		for sel in ['button:has-text("立即签到")', 'button:has-text("签到")']:
			try:
				checkin_btn = await page.query_selector(sel)
				if checkin_btn:
					break
			except Exception:
				continue

		if not checkin_btn:
			# 可能已签到
			try:
				already = await page.query_selector('button:has-text("已签到")')
				if already:
					return True, '今日已签到'
			except Exception:
				pass
			await self._take_screenshot(page, 'checkin_button_not_found')
			return False, '未找到签到按钮'

		# 点击签到按钮并等待 Turnstile + API 响应
		try:
			# 监听签到 API 响应
			async with page.expect_response(
				lambda r: '/api/checkin' in (r.url or '') and r.request.method == 'POST',
				timeout=60000,
			) as resp_info:
				await checkin_btn.click()

				# 等待 Turnstile 模态弹窗中的 iframe 加载完成
				try:
					await page.wait_for_selector(
						'iframe[src*="challenges.cloudflare.com"]',
						state='attached',
						timeout=10000,
					)
					print(f'ℹ️ {self.account_name}: Turnstile iframe detected in modal')
					# 给 iframe 一点时间完成渲染
					await page.wait_for_timeout(1500)
				except Exception:
					print(f'⚠️ {self.account_name}: Turnstile iframe not found in modal, proceeding anyway')

				# Turnstile 验证
				if CAPTCHA_SOLVER_AVAILABLE and solve_captcha and _should_try_turnstile_solver():
					try:
						await solve_captcha(page, captcha_type='cloudflare', challenge_type='turnstile')
					except Exception:
						pass

			resp = await resp_info.value
			if resp.status == 200:
				try:
					j = await resp.json()
					if isinstance(j, dict) and j.get('success'):
						reward = j.get('data', {}).get('reward', 0)
						reward_dollars = reward / self.UNIT_PER_DOLLAR if reward else 0
						return True, f'签到成功，获得 ${reward_dollars:.2f}'
				except Exception:
					pass
				return True, '签到成功'
			else:
				try:
					j = await resp.json()
					msg = j.get('error', '') if isinstance(j, dict) else ''
				except Exception:
					msg = f'HTTP {resp.status}'
				if '已签到' in str(msg) or 'already' in str(msg).lower():
					return True, '今日已签到'
				return False, f'签到失败: {msg}'
		except Exception as e:
			# 超时兜底：检查页面是否显示签到成功
			await page.wait_for_timeout(3000)
			try:
				success_text = await page.evaluate(
					"""() => {
						const body = document.body?.innerText || '';
						if (body.includes('签到成功') || body.includes('已签到')) return 'success';
						return '';
					}"""
				)
				if success_text:
					return True, '签到成功（从页面确认）'
			except Exception:
				pass
			await self._take_screenshot(page, 'checkin_timeout')
			return False, f'签到超时: {e}'

	# ── 大转盘 ────────────────────────────────────────────────

	async def _do_wheel(self, page) -> tuple[int, float]:
		"""执行大转盘抽奖，返回 (成功次数, 总奖励美元)"""
		# 获取转盘信息
		wheel_info = await self._browser_fetch_json(page, '/api/wheel')
		wheel_json = (wheel_info.get('json') or {}).get('data', {})
		remaining = wheel_json.get('remainingSpins', 0)
		total_spins = wheel_json.get('totalSpins', 5)

		if remaining <= 0:
			print(f'ℹ️ {self.account_name}: 今日转盘次数已用完 (0/{total_spins})')
			return 0, 0.0

		print(f'🎡 {self.account_name}: 剩余转盘次数 {remaining}/{total_spins}')

		success_count = 0
		total_reward = 0.0

		for i in range(remaining):
			print(f'🎡 {self.account_name}: 第 {i + 1}/{remaining} 次旋转...')
			resp = await self._browser_fetch_json(page, '/api/wheel', method='POST')
			resp_json = resp.get('json')

			if isinstance(resp_json, dict) and resp_json.get('success'):
				data = resp_json.get('data', {}) or {}
				prize_name = data.get('prize', {}).get('name', '未知') if isinstance(data.get('prize'), dict) else '未知'
				amount = data.get('prize', {}).get('amount', 0) if isinstance(data.get('prize'), dict) else 0
				amount_dollars = amount / self.UNIT_PER_DOLLAR if amount else 0
				total_reward += amount_dollars
				success_count += 1
				print(f'  🎉 中奖: {prize_name} (+${amount_dollars:.2f})')
			else:
				error = ''
				if isinstance(resp_json, dict):
					error = resp_json.get('error', resp_json.get('message', ''))
				status_code = resp.get('status')
				print(f'  ❌ 旋转失败: {error or f"HTTP {status_code}"}')
				if '次数' in str(error) or 'limit' in str(error).lower():
					break

			# 间隔避免频率限制
			if i < remaining - 1:
				await page.wait_for_timeout(2000)

		print(f'🎡 {self.account_name}: 转盘完成 {success_count}/{remaining} 次，总奖励 ${total_reward:.2f}')
		return success_count, total_reward

	# ── 自动转出 ──────────────────────────────────────────────

	async def _do_auto_transfer(self, page) -> tuple[bool, str]:
		"""当钱包余额超过阈值时，自动转出到公益站主站"""
		if self.transfer_threshold <= 0:
			return True, '未启用自动转出'

		# 获取余额
		balance_resp = await self._browser_fetch_json(page, '/api/wallet/balance')
		balance_json = (balance_resp.get('json') or {}).get('data', {})
		wallet_balance = (balance_json.get('wallet', {}) or {}).get('balance', 0)
		wallet_dollars = wallet_balance / self.UNIT_PER_DOLLAR
		main_balance = (balance_json.get('mainSite', {}) or {}).get('balance', 0)

		print(f'💰 {self.account_name}: 钱包余额 ${wallet_dollars:.2f}，主站余额 ${main_balance:.2f}')

		if wallet_dollars <= self.transfer_threshold:
			return True, f'钱包余额 ${wallet_dollars:.2f} 未超过阈值 ${self.transfer_threshold:.2f}，跳过转出'

		# 检查转出限制
		limits_resp = await self._browser_fetch_json(page, '/api/wallet/transfer/limits')
		limits_json = (limits_resp.get('json') or {}).get('data', {})
		withdraw_remaining = (limits_json.get('withdraw', {}) or {}).get('remaining', 0)
		main_site_limit = limits_json.get('withdrawMainSiteBalanceLimit', 1000)

		if withdraw_remaining <= 0:
			return True, '今日转出次数已用完'

		if main_balance >= main_site_limit:
			return True, f'主站余额 ${main_balance:.2f} >= ${main_site_limit}，不允许转出'

		# 计算转出金额（保留 $1 在钱包中）
		transfer_dollars = wallet_dollars - 1
		if transfer_dollars < 1:
			return True, f'可转出金额不足 $1'

		# 考虑手续费：fee_config
		fee_config = limits_json.get('withdrawFeeConfig', {}) or {}
		if fee_config.get('enabled'):
			pct = fee_config.get('percentageFee', 0)
			min_fee = fee_config.get('minFee', 0)
			fee = max(transfer_dollars * pct, min_fee)
			# 确保转出后钱包余额不为负
			if transfer_dollars + fee > wallet_dollars - 1:
				transfer_dollars = wallet_dollars - 1 - fee
			if transfer_dollars < 1:
				return True, f'扣除手续费后可转出金额不足 $1'

		transfer_amount = int(transfer_dollars * self.UNIT_PER_DOLLAR)
		print(f'💸 {self.account_name}: 准备转出 ${transfer_dollars:.2f} (内部单位: {transfer_amount})')

		resp = await self._browser_fetch_json(page, '/api/wallet/transfer/withdraw', method='POST', body={'amount': transfer_amount})
		resp_json = resp.get('json')

		if isinstance(resp_json, dict) and resp_json.get('success'):
			data = resp_json.get('data', {}) or {}
			actual_dollars = data.get('amountInDollars', transfer_dollars)
			new_balance = data.get('newWalletBalance', 0) / self.UNIT_PER_DOLLAR
			msg = f'成功转出 ${actual_dollars:.2f}，钱包余额 ${new_balance:.2f}'
			print(f'✅ {self.account_name}: {msg}')
			return True, msg

		error = ''
		if isinstance(resp_json, dict):
			error = resp_json.get('error', resp_json.get('message', ''))
		status_code = resp.get('status')
		return False, f'转出失败: {error or f"HTTP {status_code}"}'

	# ── 获取钱包余额 ─────────────────────────────────────────

	async def _get_wallet_balance(self, page) -> dict:
		"""获取钱包余额信息"""
		resp = await self._browser_fetch_json(page, '/api/wallet/balance')
		resp_json = (resp.get('json') or {}).get('data', {})
		wallet = (resp_json.get('wallet', {}) or {}).get('balance', 0)
		main_site = (resp_json.get('mainSite', {}) or {}).get('balance', 0)
		return {
			'wallet_balance': wallet / self.UNIT_PER_DOLLAR,
			'main_site_balance': main_site,
			'total': wallet / self.UNIT_PER_DOLLAR + main_site,
		}

	# ── 主执行入口 ───────────────────────────────────────────

	async def execute(self, username: str, password: str) -> tuple[bool, dict]:
		"""执行完整签到流程"""
		print(f'\n\n⏳ 开始处理 {self.account_name} (黑与白公益站)')

		try:
			from camoufox.async_api import AsyncCamoufox
		except Exception as e:
			return False, {'error': f'缺少浏览器依赖 camoufox: {e}'}

		headless = self._env_bool('HEADLESS', False)
		storage_dir = Path('storage-states') / 'hybgzs'
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

			results = {
				'checkin': False,
				'checkin_msg': '',
				'wheel_spins': 0,
				'wheel_reward': 0.0,
				'transfer': '',
				'wallet_balance': 0.0,
				'main_site_balance': 0.0,
			}

			try:
				# 1) 登录
				login_ok = await self._do_oauth_login(page, username, password)
				if not login_ok:
					return False, {**results, 'error': 'OAuth 登录失败'}

				# 保存登录状态
				try:
					await context.storage_state(path=cache_file)
				except Exception:
					pass

				# 2) 每日签到
				checkin_ok, checkin_msg = await self._do_checkin(page)
				results['checkin'] = checkin_ok
				results['checkin_msg'] = checkin_msg
				print(f'{"✅" if checkin_ok else "❌"} {self.account_name}: 签到: {checkin_msg}')

				# 3) 大转盘
				wheel_spins, wheel_reward = await self._do_wheel(page)
				results['wheel_spins'] = wheel_spins
				results['wheel_reward'] = wheel_reward

				# 4) 自动转出
				transfer_ok, transfer_msg = await self._do_auto_transfer(page)
				results['transfer'] = transfer_msg
				if not transfer_ok:
					print(f'⚠️ {self.account_name}: 转出: {transfer_msg}')
				else:
					print(f'ℹ️ {self.account_name}: 转出: {transfer_msg}')

				# 5) 获取最终余额
				balance = await self._get_wallet_balance(page)
				results['wallet_balance'] = balance['wallet_balance']
				results['main_site_balance'] = balance['main_site_balance']

				overall = checkin_ok
				return overall, results

			except Exception as e:
				await self._take_screenshot(page, 'flow_exception')
				await self._save_page_html(page, 'flow_exception')
				return False, {**results, 'error': f'执行异常: {e}'}
			finally:
				try:
					await context.close()
				except Exception:
					pass




