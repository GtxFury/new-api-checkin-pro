#!/usr/bin/env python3
"""
使用 Camoufox 通过 Linux.do 执行 OAuth 登录，并在浏览器中完成带 Cloudflare Turnstile 验证的每日签到。

主要用于 runanytime.hxi.me 这类需要在前端页面完成签到的站点。
"""

import asyncio
import json
import os
import sys
import time
import random
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlparse, quote, urlencode

from camoufox.async_api import AsyncCamoufox

from utils.browser_utils import filter_cookies
from utils.config import ProviderConfig
from utils.redact import redact_url_for_log, redact_value_for_log

# 首选依赖：playwright-captcha，用于更智能地处理 Cloudflare Turnstile / Interstitial
try:
	from playwright_captcha import ClickSolver, CaptchaType, FrameworkType  # type: ignore[assignment]
	PLAYWRIGHT_CAPTCHA_AVAILABLE = True
	print("ℹ️ LinuxDoSignIn: playwright-captcha imported successfully")
except Exception as e1:  # pragma: no cover - 可选依赖
	ClickSolver = None  # type: ignore[assignment]
	CaptchaType = None  # type: ignore[assignment]
	FrameworkType = None  # type: ignore[assignment]
	PLAYWRIGHT_CAPTCHA_AVAILABLE = False
	print(f"⚠️ LinuxDoSignIn: playwright-captcha not available: {e1!r}")


def _should_try_turnstile_solver() -> bool:
	# 默认开启：若需要关闭请设 LINUXDO_TRY_TURNSTILE_SOLVER=0/false/no/off
	raw = str(os.getenv("LINUXDO_TRY_TURNSTILE_SOLVER", "") or "").strip().lower()
	if raw in {"0", "false", "no", "off"}:
		return False
	# 兼容旧语义：显式 truthy 也视为开启
	if raw in {"1", "true", "yes", "on"}:
		return True
	# 未设置/未知值：默认开启
	return True


async def solve_captcha(page, captcha_type: str = "cloudflare", challenge_type: str = "turnstile") -> bool:
	"""统一的验证码解决入口，优先使用 playwright-captcha。

	为了兼容现有调用方，保留 captcha_type / challenge_type 参数，但目前主要依赖
	playwright-captcha 的自动检测能力。
	"""
	if not PLAYWRIGHT_CAPTCHA_AVAILABLE or ClickSolver is None or FrameworkType is None or CaptchaType is None:
		print(
			f"⚠️ LinuxDoSignIn: playwright-captcha is not available, "
			f"solve_captcha fallback will always return False"
		)
		return False

	# 默认不尝试 Turnstile click solver（除非显式开启）。
	if captcha_type == "cloudflare" and challenge_type == "turnstile" and not _should_try_turnstile_solver():
		return False

	# 预检测：很多情况下页面并没有 Cloudflare iframe（例如已经通过校验、或被其他 WAF/401 页面拦截），
	# 直接调用 ClickSolver 会反复抛出 “Cloudflare iframes not found” 并产生大量堆栈输出，造成“卡死/刷屏”。
	# 这里先做轻量判断：只有检测到 Cloudflare 相关元素/标记时才进入 solver。
	try:
		# 1) 快速 DOM 证据（Turnstile/Challenge iframe 或表单）
		has_cf_evidence = await page.evaluate(
			"""() => {
				try {
					const hasIframe = !!document.querySelector('iframe[src*=\"challenges.cloudflare.com\"]');
					const hasTurnstileInput = !!document.querySelector('input[name=\"cf-turnstile-response\"], textarea[name=\"cf-turnstile-response\"]');
					const hasChlForm = !!document.querySelector('form[action*=\"__cf_chl\"], input[name=\"cf_chl_seq_\"], input[name=\"cf_challenge_response\"]');
					const title = (document.title || '').toLowerCase();
					const titleLooks = title.includes('just a moment') || title.includes('attention required');
					return { hasIframe, hasTurnstileInput, hasChlForm, titleLooks };
				} catch (e) {
					return { hasIframe: false, hasTurnstileInput: false, hasChlForm: false, titleLooks: false };
				}
			}"""
		)
		if not isinstance(has_cf_evidence, dict):
			has_cf_evidence = {}

		# 2) 若标题疑似 CF，但 iframe 尚未渲染，给一个短等待窗口
		if bool(has_cf_evidence.get("titleLooks")) and not bool(has_cf_evidence.get("hasIframe")):
			try:
				await page.wait_for_selector('iframe[src*="challenges.cloudflare.com"]', timeout=6000)
				has_cf_evidence["hasIframe"] = True
			except Exception:
				pass

		# 仅在“与目标挑战类型匹配”的证据存在时才进入 solver，避免把 interstitial 页面当 turnstile 点，
		# 从而出现 “Cloudflare checkbox not found or not ready” 的误判/刷屏。
		is_turnstile_evidence = bool(has_cf_evidence.get("hasIframe") or has_cf_evidence.get("hasTurnstileInput"))
		is_interstitial_evidence = bool(has_cf_evidence.get("hasChlForm"))

		should_try = False
		if captcha_type == "cloudflare" and challenge_type == "turnstile":
			should_try = is_turnstile_evidence
		elif captcha_type == "cloudflare" and challenge_type == "interstitial":
			# interstitial 常见为 __cf_chl 表单；部分情况下只有标题信号但还未渲染，允许 titleLooks 作为弱触发
			should_try = is_interstitial_evidence or bool(has_cf_evidence.get("titleLooks"))

		if not should_try:
			return False
	except Exception:
		# 预检测失败时不影响原流程：继续尝试 solver（保持行为兼容）
		pass

	try:
		framework = FrameworkType.CAMOUFOX  # 当前项目在 Camoufox 上运行

		# 将调用方传入的 captcha_type / challenge_type 映射到 playwright-captcha 的 CaptchaType
		if captcha_type == "cloudflare" and challenge_type == "turnstile":
			target_type = CaptchaType.CLOUDFLARE_TURNSTILE
		elif captcha_type == "cloudflare" and challenge_type == "interstitial":
			target_type = CaptchaType.CLOUDFLARE_INTERSTITIAL
		else:
			print(
				f"⚠️ LinuxDoSignIn: Unsupported captcha_type/challenge_type combination for playwright-captcha: "
				f"{captcha_type}/{challenge_type}"
			)
			return False

		async def _run_solver() -> bool:
			async with ClickSolver(framework=framework, page=page) as solver:
				# 对于 ClickSolver，solve_captcha 在成功时不会返回 token，能正常返回即视为成功
				await solver.solve_captcha(captcha_container=page, captcha_type=target_type)
				return True

		# 设置 30 秒超时（Turnstile 通常需要一些时间完成验证）
		try:
			return await asyncio.wait_for(_run_solver(), timeout=30.0)
		except asyncio.TimeoutError:
			print(f"⚠️ LinuxDoSignIn: playwright-captcha solver timed out after 30s")
			return False
	except Exception as e:
		print(f"⚠️ LinuxDoSignIn: playwright-captcha solve_captcha error: {e}")
		return False


class LinuxDoSignIn:
	"""使用 Linux.do 账号完成 OAuth 授权，并在浏览器中执行签到。"""

	# 站点前端路由可能有差异（Veloera/New-API），这里放一些常见候选路径做兼容
	PROFILE_PATH_CANDIDATES = (
		"/app/me",
		"/app/profile",
		"/app/user",
		"/app/account",
		"/app",
	)

	APP_FALLBACK_PATH_CANDIDATES = (
		"/console/personal",
		"/console",
		"/console/token",
		"/console/topup",
		"/app/tokens",
		"/app/token",
		"/app/api-keys",
		"/app/keys",
		"/app",
	)

	def __init__(
		self,
		account_name: str,
		provider_config: ProviderConfig,
		username: str,
		password: str,
	):
		self.account_name = account_name
		self.safe_account_name = "".join(c if c.isalnum() else "_" for c in account_name)
		self.provider_config = provider_config
		self.username = username
		self.password = password

	@staticmethod
	def _looks_like_cloudflare_interstitial_html(body: str) -> bool:
		if not body:
			return False
		low = body.lower()
		return (
			("just a moment" in low)
			or ("challenges.cloudflare.com" in low)
			or ("cf-browser-verification" in low)
			or ("__cf_chl" in low)
			or ("cf-chl" in low)
		)

	def _prefer_callback_navigation(self) -> bool:
		# Veloera 系站点（如 elysiver）在回调接口上更容易触发 WAF/CF，优先用浏览器导航跑通挑战。
		try:
			return str(getattr(self.provider_config, "api_user_key", "") or "").lower() == "veloera-user"
		except Exception:
			return False

	def _linuxdo_callback_mode(self) -> str:
		"""获取 Linux.do OAuth 回调策略（来自 provider 配置）。"""
		try:
			mode = str(getattr(self.provider_config, "linuxdo_callback_mode", "auto") or "auto").strip().lower()
		except Exception:
			mode = "auto"
		if mode in {"auto", "fast_fetch", "navigation", "spa"}:
			return mode
		return "auto"

	def _is_wzw_provider(self) -> bool:
		"""判断是否是 wzw 站点"""
		return self.provider_config.name == "wzw"

	async def _complete_oauth_via_spa(
		self,
		page,
		code: str,
		auth_state: str | None,
	) -> tuple[bool, dict]:
		"""依赖站点同源前端 /oauth/linuxdo 完成 OAuth 回调，并从 localStorage 读取 api_user。"""
		origin = self.provider_config.origin
		state_q = auth_state or ""
		try:
			cur = page.url or ""
		except Exception:
			cur = ""

		# 确保进入前端回调路由
		if "/oauth/linuxdo" not in cur:
			try:
				await page.goto(
					f"{origin}/oauth/linuxdo?code={quote(code, safe='')}&state={quote(str(state_q), safe='')}",
					wait_until="domcontentloaded",
				)
			except Exception:
				pass

		# 等待 SPA 写入 localStorage；若失败，导航 /console 触发初始化
		try:
			await page.wait_for_function(
				"""() => {
					try {
						return (
							localStorage.getItem('user') !== null ||
							localStorage.getItem('user_info') !== null ||
							localStorage.getItem('userInfo') !== null
						);
					} catch (e) { return false; }
				}""",
				timeout=20000,
			)
		except Exception:
			try:
				await page.goto(f"{origin}/console", wait_until="domcontentloaded")
				await page.wait_for_timeout(2000)
			except Exception:
				pass

		api_user = await self._extract_api_user_from_localstorage(page)
		if api_user:
			restore_cookies = await page.context.cookies()
			user_cookies = filter_cookies(restore_cookies, origin)
			return True, {"cookies": user_cookies, "api_user": api_user}

		# 若落回登录页，提示重试（可能是回调未完成/会话失效/站点回调失败）
		try:
			if "/login" in (page.url or ""):
				return False, {"error": "OAuth session not established (redirected to login)", "retry": True}
		except Exception:
			pass
		return False, {"error": "OAuth flow failed - no user in localStorage", "retry": True}

	async def _call_provider_linuxdo_callback_fast(
		self,
		page,
		code: str,
		auth_state: str | None,
	) -> str | None:
		"""优先用浏览器内 fetch 调用 provider 的 LinuxDO 回调接口，快速拿到 api_user。

		相比等待 SPA 跳转 + 写入 localStorage，这条路径更快且不降低成功率：失败时仍会走旧兜底。
		"""
		try:
			# SPA 前端路由（不以 /api 开头）返回 HTML 不是 JSON，跳过 fast callback
			auth_path = self.provider_config.linuxdo_auth_path or ""
			if not auth_path.startswith("/api"):
				print(f"ℹ️ {self.account_name}: Skipping fast callback (SPA route: {auth_path})")
				return None

			base_callback_url = self.provider_config.get_linuxdo_auth_url()
			parsed_cb = urlparse(base_callback_url)
			cb_query = parse_qs(parsed_cb.query)
			cb_query["code"] = [code]
			if auth_state:
				cb_query["state"] = [auth_state]
			final_query = urlencode(cb_query, doseq=True)
			final_callback_url = parsed_cb._replace(query=final_query).geturl()

			print(
				f"ℹ️ {self.account_name}: Fast-calling Linux.do callback via browser fetch: "
				f"{redact_url_for_log(final_callback_url)}"
			)

			# 某些站点会校验 api_user header，这里统一以 -1 作为“未登录”占位
			headers = {
				"Accept": "application/json, text/plain, */*",
				"Origin": self.provider_config.origin,
				"Referer": f"{self.provider_config.origin}/console",
				"new-api-user": "-1",
				"New-Api-User": "-1",
				"Veloera-User": "-1",
			}

			resp = await page.evaluate(
				"""async ({ url, headers }) => {
					try {
						const r = await fetch(url, { credentials: 'include', headers });
						const t = await r.text();
						return { ok: r.ok, status: r.status, text: t };
					} catch (e) {
						return { ok: false, status: 0, text: String(e) };
					}
				}""",
				{"url": final_callback_url, "headers": headers},
			)

			status = (resp or {}).get("status", 0)
			text = (resp or {}).get("text", "") or ""
			# Cloudflare interstitial：优先切到“导航回调”跑 challenge，再回来 fetch
			if status in (403, 429, 503) and self._looks_like_cloudflare_interstitial_html(text[:4000]):
				return None
			if status != 200 or not text:
				print(
					f"⚠️ {self.account_name}: Fast callback fetch failed: HTTP {status}, body: {text[:200]}"
				)
				return None

			try:
				data = json.loads(text)
			except Exception as parse_err:
				print(
					f"⚠️ {self.account_name}: Fast callback JSON parse failed: {parse_err}, body: {text[:200]}"
				)
				return None

			if not isinstance(data, dict) or not data.get("success"):
				msg = data.get("message") if isinstance(data, dict) else "Invalid response"
				print(f"⚠️ {self.account_name}: Fast callback returned success=false: {msg}")
				return None

			user_data = data.get("data", {})
			if isinstance(user_data, dict):
				api_user = user_data.get("id") or user_data.get("user_id") or user_data.get("userId")
				if api_user:
					return str(api_user)
			return None
		except Exception as e:
			print(f"⚠️ {self.account_name}: Fast callback fetch error: {e}")
			return None

	async def _call_provider_linuxdo_callback_via_navigation(
		self,
		page,
		code: str,
		auth_state: str | None,
	) -> str | None:
		"""通过页面导航调用 provider 的 LinuxDO 回调接口，尽量确保服务端会话(cookie)被正确写入。"""
		try:
			base_callback_url = self.provider_config.get_linuxdo_auth_url()
			parsed_cb = urlparse(base_callback_url)
			cb_query = parse_qs(parsed_cb.query)
			cb_query["code"] = [code]
			if auth_state:
				cb_query["state"] = [auth_state]
			final_query = urlencode(cb_query, doseq=True)
			final_callback_url = parsed_cb._replace(query=final_query).geturl()

			print(
				f"ℹ️ {self.account_name}: Calling Linux.do callback via browser navigation (helper): "
				f"{redact_url_for_log(final_callback_url)}"
			)

			# 允许重试（应对 CF interstitial / WAF 429）
			for attempt in range(4):
				if attempt > 0:
					await page.wait_for_timeout(1000)
				response = await page.goto(final_callback_url, wait_until="domcontentloaded")
				status = response.status if response else 0
				try:
					text = await response.text() if response else ""
				except Exception:
					text = ""

				if status == 429:
					# 避免立刻重试触发更严格的限流
					backoff = min(30, 6 * (2**attempt)) + random.uniform(0, 2)
					print(
						f"⚠️ {self.account_name}: Callback got HTTP 429, backing off {backoff:.1f}s before retry"
					)
					await page.wait_for_timeout(int(backoff * 1000))
					continue

				if status == 200 and text:
					try:
						data = json.loads(text)
					except Exception:
						data = None
					if isinstance(data, dict) and data.get("success"):
						user_data = data.get("data", {}) or {}
						api_user = user_data.get("id") or user_data.get("user_id") or user_data.get("userId")
						if api_user:
							return str(api_user)

				# 若遇到挑战页，尝试解决后重试
				try:
					html = (await page.content())[:5000]
				except Exception:
					html = ""
				is_cf = (
					"challenges.cloudflare.com" in (page.url or "")
					or "Just a moment" in html
					or "cf-browser-verification" in html
					or self._looks_like_cloudflare_interstitial_html(text[:4000])
				)
				if is_cf:
					print(
						f"⚠️ {self.account_name}: Cloudflare interstitial detected on callback page, attempting to solve"
					)
					try:
						await solve_captcha(page, captcha_type="cloudflare", challenge_type="interstitial")
					except Exception:
						pass
					if _should_try_turnstile_solver():
						try:
							await solve_captcha(page, captcha_type="cloudflare", challenge_type="turnstile")
						except Exception:
							pass
					await page.wait_for_timeout(12000)
					
					# CF 解决后，不能重新 goto 相同 URL（OAuth code 只能使用一次）
					# 检查当前页面是否已经完成登录，或等待自动跳转
					current_url = page.url or ""
					if "/login" not in current_url and "challenges.cloudflare.com" not in current_url:
						# 可能已经跳转到控制台，尝试从 localStorage 获取用户信息
						try:
							api_user_from_ls = await self._extract_api_user_from_localstorage(page)
							if api_user_from_ls:
								print(f"✅ {self.account_name}: Got api user from localStorage after CF solve: {api_user_from_ls}")
								return api_user_from_ls
						except Exception:
							pass
					# 如果仍然没有用户信息，继续重试（但下次 goto 可能会失败因为 code 已被使用）
					continue
				break

			return None
		except Exception as e:
			print(f"⚠️ {self.account_name}: Callback navigation helper error: {e}")
			return None

	async def _handle_cloudflare_challenge(self, page, max_wait_seconds: int = 30) -> bool:
		"""检测并解决 Cloudflare 全屏挑战（Just a moment 页面）

		返回 True 表示页面已通过挑战或无挑战，False 表示挑战解决失败。
		"""
		import time
		start_time = time.time()

		while time.time() - start_time < max_wait_seconds:
			# 检测是否存在 Cloudflare 挑战
			try:
				cf_detected = await page.evaluate("""() => {
					try {
						// 不依赖 document.title（不稳定/可被站点自定义），仅基于 DOM/资源特征判断。
						const hasCfIframe = !!document.querySelector('iframe[src*="challenges.cloudflare.com"]');
						const hasTurnstileInput = !!document.querySelector('input[name="cf-turnstile-response"], textarea[name="cf-turnstile-response"]');
						const hasTurnstileWidget =
							!!document.querySelector('.cf-turnstile, [data-sitekey][data-theme], [data-sitekey][data-action], [data-sitekey][data-callback]');

						const hasChallengePlatform =
							!!document.querySelector('script[src*="/cdn-cgi/challenge-platform/"], link[href*="/cdn-cgi/challenge-platform/"]');
						const hasChlForm =
							!!document.querySelector(
								'form[action*="__cf_chl"], form#challenge-form, #challenge-form, input[name^="cf_chl_"], input[name="cf_challenge_response"]'
							);
						const hasCfSpinner =
							!!document.querySelector('#cf-spinner-please-wait, #cf-please-wait, #challenge-running, .cf-spinner');
						const hasCfRay = !!document.querySelector('#cf-ray, [data-ray]');

						const isTurnstile = hasCfIframe || hasTurnstileInput || hasTurnstileWidget;
						const isInterstitial = hasChallengePlatform || hasChlForm || hasCfSpinner || hasCfRay;

						if (isTurnstile) return { detected: true, type: 'turnstile' };
						if (isInterstitial) return { detected: true, type: 'interstitial' };
						return { detected: false, type: 'none' };
					} catch (e) {
						return { detected: false, error: e.message };
					}
				}""")
			except Exception as e:
				print(f"⚠️ {self.account_name}: CF detection error: {e}")
				cf_detected = {"detected": False}

			if not cf_detected.get("detected"):
				# 无 Cloudflare 挑战，直接返回
				return True

			cf_type = cf_detected.get("type", "unknown")
			print(f"ℹ️ {self.account_name}: Cloudflare challenge detected (type: {cf_type}), attempting to solve...")

			# 尝试使用 playwright-captcha 解决
			solver_attempted = False
			solver_succeeded = False
			try:
				# 先尝试 interstitial
				solver_attempted = True
				solver_succeeded = bool(
					await solve_captcha(page, captcha_type="cloudflare", challenge_type="interstitial")
				) or solver_succeeded
			except Exception as e:
				print(f"⚠️ {self.account_name}: CF interstitial solve error: {e}")

			# 再尝试 turnstile
			if _should_try_turnstile_solver():
				try:
					solver_attempted = True
					solver_succeeded = bool(
						await solve_captcha(page, captcha_type="cloudflare", challenge_type="turnstile")
					) or solver_succeeded
				except Exception as e:
					print(f"⚠️ {self.account_name}: CF turnstile solve error: {e}")

			# 等待页面跳转或挑战消失
			await page.wait_for_timeout(3000)

			# 检查是否成功通过
			try:
				# 再跑一次 DOM 特征检测：不再依赖标题判断是否过挑战
				check2 = await page.evaluate("""() => {
					try {
						const hasCfIframe = !!document.querySelector('iframe[src*="challenges.cloudflare.com"]');
						const hasTurnstileInput = !!document.querySelector('input[name="cf-turnstile-response"], textarea[name="cf-turnstile-response"]');
						const hasTurnstileWidget =
							!!document.querySelector('.cf-turnstile, [data-sitekey][data-theme], [data-sitekey][data-action], [data-sitekey][data-callback]');

						const hasChallengePlatform =
							!!document.querySelector('script[src*="/cdn-cgi/challenge-platform/"], link[href*="/cdn-cgi/challenge-platform/"]');
						const hasChlForm =
							!!document.querySelector(
								'form[action*="__cf_chl"], form#challenge-form, #challenge-form, input[name^="cf_chl_"], input[name="cf_challenge_response"]'
							);
						const hasCfSpinner =
							!!document.querySelector('#cf-spinner-please-wait, #cf-please-wait, #challenge-running, .cf-spinner');
						const hasCfRay = !!document.querySelector('#cf-ray, [data-ray]');

						const isTurnstile = hasCfIframe || hasTurnstileInput || hasTurnstileWidget;
						const isInterstitial = hasChallengePlatform || hasChlForm || hasCfSpinner || hasCfRay;
						return { detected: !!(isTurnstile || isInterstitial) };
					} catch (e) {
						return { detected: false };
					}
				}""")
				if not bool((check2 or {}).get("detected")):
					# 注意：solver 可能抛错/返回 False，但页面也可能因自动跳转/刷新而“自己过了挑战”。
					if solver_succeeded:
						print(f"✅ {self.account_name}: Cloudflare challenge cleared (solver)")
					elif solver_attempted:
						print(
							f"✅ {self.account_name}: Cloudflare challenge cleared (page changed without solver success)"
						)
					else:
						print(f"✅ {self.account_name}: Cloudflare challenge cleared")
					return True
			except Exception:
				pass

		print(f"⚠️ {self.account_name}: Cloudflare challenge not solved within {max_wait_seconds}s")
		await self._take_screenshot(page, f"{self.provider_config.name}_cf_challenge_timeout")
		return False

	async def _runanytime_verify_session(self, page, api_user: str) -> bool:
		"""runanytime/new-api：用 /api/user/self 校验 session 是否有效（比看 UI 是否 NaN 更准）。"""
		try:
			resp = await page.evaluate(
				"""async (apiUser) => {
					try {
						const r = await fetch('/api/user/self', {
							credentials: 'include',
							headers: { 'new-api-user': String(apiUser), 'Accept': 'application/json, text/plain, */*' },
						});
						return { status: r.status, text: await r.text() };
					} catch (e) {
						return { status: 0, text: String(e) };
					}
				}""",
				api_user,
			)
			status = int((resp or {}).get("status", 0) or 0)
			if status == 200:
				return True
			if status:
				print(f"⚠️ {self.account_name}: runanytime session verify failed: HTTP {status}")
			return False
		except Exception:
			return False

	async def _take_screenshot(self, page, reason: str) -> None:
		"""截取当前页面截图"""
		try:
			screenshots_dir = "screenshots"
			os.makedirs(screenshots_dir, exist_ok=True)

			timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
			safe_reason = "".join(c if c.isalnum() else "_" for c in reason)
			filename = f"{self.safe_account_name}_{timestamp}_{safe_reason}.png"
			filepath = os.path.join(screenshots_dir, filename)

			await page.screenshot(path=filepath, full_page=True)
			print(f"📸 {self.account_name}: Screenshot saved to {filepath}")
		except Exception as e:
			print(f"⚠️ {self.account_name}: Failed to take screenshot: {e}")

	async def _save_page_content_to_file(self, page, reason: str) -> None:
		"""保存页面 HTML 到日志文件"""
		try:
			logs_dir = "logs"
			os.makedirs(logs_dir, exist_ok=True)

			timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
			safe_reason = "".join(c if c.isalnum() else "_" for c in reason)
			filename = f"{self.safe_account_name}_{timestamp}_linuxdo_{safe_reason}.html"
			filepath = os.path.join(logs_dir, filename)

			html_content = await page.content()
			with open(filepath, "w", encoding="utf-8") as f:
				f.write(html_content)

			print(f"📄 {self.account_name}: Page HTML saved to {filepath}")
		except Exception as e:
			print(f"⚠️ {self.account_name}: Failed to save HTML: {e}")

	def _clear_provider_site_caches(
		self,
		cache_file_path: str = "",
		include_linuxdo_state: bool = True,
	) -> None:
		"""清理当前 provider 的站点缓存（跨账号）。"""
		try:
			provider_name = str(getattr(self.provider_config, "name", "") or "").strip()
			if not provider_name:
				return

			cache_dir = Path(cache_file_path).parent if cache_file_path else Path("storage-states")
			if not str(cache_dir):
				cache_dir = Path("storage-states")

			target_files: set[Path] = set()
			if include_linuxdo_state and cache_file_path:
				target_files.add(Path(cache_file_path))

			name_variants = {provider_name, provider_name.lower(), provider_name.upper()}
			for n in name_variants:
				target_files.update(cache_dir.glob(f"cf_{n}_*_cookies.json"))
				target_files.update(cache_dir.glob(f"{n}_*_session_cache.json"))
				legacy_dir = cache_dir / n
				if legacy_dir.exists() and legacy_dir.is_dir():
					target_files.update(legacy_dir.rglob("*.json"))

			deleted = 0
			for p in target_files:
				try:
					if p.exists() and p.is_file():
						p.unlink()
						deleted += 1
						print(f"ℹ️ {self.account_name}: Cleared provider cache file: {p}")
				except Exception as del_err:
					print(f"⚠️ {self.account_name}: Failed to clear cache file {p}: {del_err}")

			print(
				f"ℹ️ {self.account_name}: Provider cache cleanup done "
				f"(provider={provider_name}, deleted={deleted}, include_linuxdo_state={include_linuxdo_state})"
			)
		except Exception as e:
			print(f"⚠️ {self.account_name}: Provider cache cleanup error: {e}")

	async def _solve_turnstile(self, page) -> bool:
		"""尝试解决 Cloudflare Turnstile 验证

		优先使用 playwright-captcha，如果不可用则回退到简单的坐标点击方案。
		"""

		# 1. 如果 playwright-captcha 可用，优先使用
		if solve_captcha is not None:
			try:
				print(f"ℹ️ {self.account_name}: Solving Cloudflare Turnstile via playwright-captcha ClickSolver")
				solved = await solve_captcha(
					page,
					captcha_type="cloudflare",
					challenge_type="turnstile",
				)
				print(f"ℹ️ {self.account_name}: Turnstile solve result from playwright-captcha: {solved}")
				if solved:
					return True
			except Exception as sc_err:
				print(f"⚠️ {self.account_name}: playwright-captcha solve_captcha error: {sc_err}")

		# 2. 手动回退方案：查找 Turnstile iframe，然后点击其中心区域
		try:
			# 有些环境下 iframe 的 id 可能不固定，这里只按 src 匹配
			iframe_selector = 'iframe[src*="challenges.cloudflare.com"]'
			iframe = await page.query_selector(iframe_selector)
			if not iframe:
				try:
					# 只要求元素存在即可，不强制可见，避免样式原因导致超时
					iframe = await page.wait_for_selector(
						iframe_selector,
						timeout=20000,
						state="attached",
					)
				except Exception as e:
					print(f"⚠️ {self.account_name}: Turnstile iframe not found on page: {e}")
					await self._take_screenshot(page, f"{self.provider_config.name}_turnstile_iframe_not_found")
					return False

			box = await iframe.bounding_box()
			if not box:
				print(f"⚠️ {self.account_name}: Failed to get Turnstile iframe bounding box")
				return False

			click_x = box["x"] + box["width"] / 2
			click_y = box["y"] + box["height"] / 2
			print(
				f"ℹ️ {self.account_name}: Clicking Turnstile checkbox at "
				f"({click_x:.1f}, {click_y:.1f}) using manual fallback"
			)

			await page.mouse.move(click_x, click_y)
			await page.wait_for_timeout(1000)
			await page.mouse.click(click_x, click_y)
			await page.wait_for_timeout(5000)

			return True
		except Exception as e:
			print(f"⚠️ {self.account_name}: Manual Turnstile solving failed: {e}")
			return False

	async def _browser_check_in_with_turnstile(self, page) -> bool:
		"""在 provider 的页面中执行每日签到（部分站点可能包含 Turnstile）。

		返回：True 表示已确认“今日已签到/签到成功”，False 表示未能确认。
		"""
		try:
			# 如果配置了签到页面路径，只使用该路径
			if getattr(self.provider_config, "checkin_page_path", None):
				checkin_paths = [self.provider_config.checkin_page_path]
			else:
				# 回退到原有的候选路径
				checkin_paths = list(self.PROFILE_PATH_CANDIDATES)

			for path in checkin_paths:
				target_url = f"{self.provider_config.origin}{path}"
				print(f"ℹ️ {self.account_name}: Navigating to check-in page: {target_url}")
				await page.goto(target_url, wait_until="networkidle")

				try:
					await page.wait_for_function('document.readyState === "complete"', timeout=5000)
				except Exception:
					await page.wait_for_timeout(3000)

				# elysiver: 检测并解决 Cloudflare 全屏挑战（Just a moment 页面）
				if self.provider_config.name == "elysiver":
					await self._handle_cloudflare_challenge(page)

				# 检测是否被重定向到登录页（session 可能已过期）
				current_url = page.url or ""
				if "/login" in current_url:
					expired_reason = "expired=true" if "expired=true" in current_url else "session invalid"
					print(f"⚠️ {self.account_name}: Redirected to login page ({expired_reason}), session may have expired")
					await self._take_screenshot(page, f"{self.provider_config.name}_session_expired")
					# 如果是 elysiver 且只有一个签到路径，直接返回避免无效尝试
					if self.provider_config.name == "elysiver" and len(checkin_paths) == 1:
						print(f"❌ {self.account_name}: Cannot proceed with check-in due to session expiry")
						return False
					continue

				# 快速检测页面是否存在 Turnstile iframe，存在才调用 solver
				try:
					turnstile_iframe = await page.query_selector('iframe[src*="challenges.cloudflare.com"]')
				except Exception:
					turnstile_iframe = None
				if turnstile_iframe:
					solved = await self._solve_turnstile(page)
					if not solved:
						print(f"⚠️ {self.account_name}: Turnstile solving may have failed, continue to try check-in")

				# 等待页面内容加载
				await page.wait_for_timeout(2000)

				# 检查是否已经签到
				try:
					already_btn = await page.query_selector('button:has-text("今日已签到")')
				except Exception:
					already_btn = None

				if already_btn:
					print(f"ℹ️ {self.account_name}: Already checked in today on provider site")
					return True

				# 查找"立即签到"按钮并点击
				checkin_btn = None
				try:
					# 先等待按钮出现
					await page.wait_for_selector('button:has-text("立即签到")', timeout=10000)
					checkin_btn = await page.query_selector('button:has-text("立即签到")')
				except Exception:
					checkin_btn = None

				if not checkin_btn:
					continue

				print(f"ℹ️ {self.account_name}: Clicking daily check-in button in browser")
				await checkin_btn.click()

				# 签到后可能弹出 CF Turnstile Security Check 弹窗
				await page.wait_for_timeout(1500)
				try:
					cf_iframe = await page.query_selector('iframe[src*="challenges.cloudflare.com"]')
					if cf_iframe:
						print(f"ℹ️ {self.account_name}: CF Turnstile popup after check-in, solving...")
						await solve_captcha(page, captcha_type="cloudflare", challenge_type="turnstile")
						await page.wait_for_timeout(3000)
						print(f"✅ {self.account_name}: CF Turnstile solved")
				except Exception as cf_err:
					print(f"⚠️ {self.account_name}: CF Turnstile after check-in: {cf_err}")

				# 等待状态变为“今日已签到”
				try:
					await page.wait_for_selector('button:has-text("今日已签到")', timeout=60000)
					print(f"✅ {self.account_name}: Daily check-in completed in browser")
					return True
				except Exception as wait_err:
					print(
						f"⚠️ {self.account_name}: Daily check-in may have failed or timed out: {wait_err}"
					)
					await self._take_screenshot(page, f"{self.provider_config.name}_checkin_timeout")
					return False
				return False

			print(f"⚠️ {self.account_name}: Daily check-in button not found on any known profile page")
			await self._take_screenshot(page, f"{self.provider_config.name}_checkin_button_not_found")
			return False
		except Exception as e:
			print(f"❌ {self.account_name}: Error during browser check-in: {e}")
			await self._take_screenshot(page, f"{self.provider_config.name}_checkin_error")
			return False

	async def _extract_api_user_from_localstorage(self, page) -> str | None:
		"""尽量从 localStorage 中读取 user id（兼容不同前端存储 key/字段）。"""
		for storage_key in ("user", "user_info", "userInfo"):
			try:
				user_data = await page.evaluate(f"() => localStorage.getItem('{storage_key}')")
			except Exception:
				user_data = None

			if not user_data:
				continue

			try:
				user_obj = json.loads(user_data)
			except Exception:
				continue

			if not isinstance(user_obj, dict):
				continue

			for id_key in ("id", "user_id", "userId"):
				api_user = user_obj.get(id_key)
				if api_user:
					return str(api_user)
		return None

	async def _extract_api_user_from_body_json(self, page) -> str | None:
		"""当页面是 /api/oauth/* 这类 JSON 输出时，从 body 里尝试解析 user id。"""
		try:
			body_text = await page.evaluate(
				"() => document.body ? (document.body.innerText || document.body.textContent || '') : ''"
			)
		except Exception:
			body_text = ""

		body_text = (body_text or "").strip()
		if not body_text or len(body_text) > 200000:
			return None

		try:
			data = json.loads(body_text)
		except Exception:
			return None

		if not isinstance(data, dict):
			return None

		payload = data.get("data")
		if isinstance(payload, dict):
			for id_key in ("id", "user_id", "userId"):
				api_user = payload.get(id_key)
				if api_user:
					return str(api_user)

		for id_key in ("id", "user_id", "userId"):
			api_user = data.get(id_key)
			if api_user:
				return str(api_user)
		return None

	async def _extract_balance_from_profile(self, page) -> dict | None:
		"""从 provider 的个人中心页面中提取当前余额和历史消耗。

		当前针对 runanytime / elysiver 等 Veloera 系站点，这些站点在
		个人中心页面的表格中以「当前余额 / 历史消耗」形式展示美元金额。
		"""
		# newapi_console_personal 站点使用 /console/personal 页面，余额在卡片组件中而非表格
		if getattr(self.provider_config, "checkin_mode", None) == "newapi_console_personal":
			return await self._extract_balance_from_newapi_card(page)

		try:
			async def _eval_summary() -> dict | None:
				return await page.evaluate(
					"""() => {
						try {
							const rows = Array.from(document.querySelectorAll('table tr'));
							const result = {};
							for (const row of rows) {
								const header = row.querySelector('th, [role="rowheader"]');
								const cell = row.querySelector('td, [role="cell"]');
								if (!header || !cell) continue;
								const label = header.innerText.trim();
								const value = cell.innerText.trim();
								result[label] = value;
							}
							return result;
						} catch (e) {
							return null;
						}
					}"""
				)

			summary = await _eval_summary()

			# 若当前页没有表格，尝试跳转到常见个人中心页面再解析
			if not summary:
				for path in self.PROFILE_PATH_CANDIDATES:
					try:
						await page.goto(f"{self.provider_config.origin}{path}", wait_until="networkidle")
						try:
							await page.wait_for_function('document.readyState === "complete"', timeout=5000)
						except Exception:
							await page.wait_for_timeout(1500)
						summary = await _eval_summary()
						if summary:
							break
					except Exception:
						continue

			if not summary:
				print(f"⚠️ {self.account_name}: Failed to extract balance table from profile pages")
				return None

			quota_keys = ("当前余额", "当前额度", "剩余额度", "余额", "可用额度")
			used_keys = ("历史消耗", "历史消费", "已用额度", "消耗")

			balance_str = None
			used_str = None
			for k in quota_keys:
				if summary.get(k):
					balance_str = summary.get(k)
					break
			for k in used_keys:
				if summary.get(k):
					used_str = summary.get(k)
					break

			if balance_str is None:
				try:
					snippet = json.dumps(summary, ensure_ascii=False)[:200]
				except Exception:
					snippet = str(summary)[:200]
				print(
					f"⚠️ {self.account_name}: Balance row not found in profile page summary: {snippet}"
				)
				return None

			def _parse_amount(s: str) -> float:
				s = s.replace("￥", "").replace("$", "").replace(",", "").strip()
				try:
					return float(s)
				except Exception:
					return 0.0

			quota = _parse_amount(str(balance_str))
			used_quota = _parse_amount(str(used_str)) if used_str is not None else 0.0

			print(
				f"✅ {self.account_name}: Parsed balance from /app/me - "
				f"Current balance: ${quota}, Used: ${used_quota}"
			)
			return {
				"success": True,
				"quota": quota,
				"used_quota": used_quota,
				"display": f"Current balance: ${quota}, Used: ${used_quota}",
			}
		except Exception as e:
			print(f"⚠️ {self.account_name}: Error extracting balance from /app/me: {e}")
			return None

	async def _extract_balance_from_newapi_card(self, page) -> dict | None:
		"""从 New-API /console/personal 页面的卡片组件中提取余额信息。

		适用于 elysiver / anthorpic 等使用 New-API 新版 UI 的站点。
		优先从页面 DOM 获取（更准确），回退到 localStorage。
		"""
		try:
			# 先确保在 /console/personal 页面
			current_url = page.url or ""
			if "/console/personal" not in current_url:
				try:
					await page.goto(f"{self.provider_config.origin}/console/personal", wait_until="networkidle")
					await page.wait_for_timeout(2000)
				except Exception as nav_err:
					print(f"⚠️ {self.account_name}: Failed to navigate to /console/personal: {nav_err}")

			# 方法1：从页面 DOM 提取余额信息（优先，因为 OAuth 回调后 localStorage 可能还没更新）
			balance_info = await page.evaluate(
				"""() => {
					try {
						const bodyText = document.body?.innerText || '';
						const result = {};

						// 匹配 "当前余额" 前面的数值，兼容 "E 146.60" / "$ 5.00" / 纯数字
						const balanceMatch = bodyText.match(/([E$￥])\s*([\d.,]+)\s*当前余额/);
						if (balanceMatch) {
							result.symbol = balanceMatch[1];
							result.quota = balanceMatch[2];
						} else {
							const altMatch = bodyText.match(/([\d.,]+)\s*当前余额/);
							if (altMatch) {
								result.symbol = '$';
								result.quota = altMatch[1];
							}
						}

						// 匹配 "历史消耗" 后面的数值
						const usedMatch = bodyText.match(/历史消耗\s*(?:[E$￥]\s*)?([\d.,]+)/);
						if (usedMatch) {
							result.used_quota = usedMatch[1];
						}

						return Object.keys(result).length > 0 ? result : null;
					} catch (e) {
						return null;
					}
				}"""
			)

			if balance_info and balance_info.get("quota"):
				def _parse_amount(s: str) -> float:
					s = str(s).replace("E", "").replace("￥", "").replace("$", "").replace(",", "").strip()
					try:
						return float(s)
					except Exception:
						return 0.0

				symbol = balance_info.get("symbol", "$")
				quota = _parse_amount(balance_info.get("quota", "0"))
				used_quota = _parse_amount(balance_info.get("used_quota", "0"))
				print(
					f"✅ {self.account_name}: Parsed balance from DOM - "
					f"Current balance: {symbol} {quota:.2f}, Used: {symbol} {used_quota:.2f}"
				)
				return {
					"success": True,
					"quota": round(quota, 2),
					"used_quota": round(used_quota, 2),
					"display": f"Current balance: {symbol} {quota:.2f}, Used: {symbol} {used_quota:.2f}",
				}

			# 方法2：从 localStorage 获取用户信息（回退方案）
			user_data = await page.evaluate("() => localStorage.getItem('user')")
			if user_data:
				try:
					user_obj = json.loads(user_data)
					if isinstance(user_obj, dict):
						# quota 和 used_quota 在 localStorage 中是原始值，需要除以 quota_per_unit
						# 从 /api/status 获取 quota_per_unit，默认 500000
						quota_per_unit = 500000
						try:
							status_data = await page.evaluate(
								"""() => fetch('/api/status').then(r => r.json()).catch(() => null)"""
							)
							if status_data and status_data.get("data", {}).get("quota_per_unit"):
								quota_per_unit = status_data["data"]["quota_per_unit"]
						except Exception:
							pass
						raw_quota = user_obj.get("quota", 0)
						raw_used = user_obj.get("used_quota", 0)
						if raw_quota and raw_quota > 0:
							quota = raw_quota / quota_per_unit
							used_quota = raw_used / quota_per_unit if raw_used else 0.0
							print(
								f"✅ {self.account_name}: Parsed balance from localStorage - "
								f"Current balance: ${quota:.2f}, Used: ${used_quota:.2f}"
							)
							return {
								"success": True,
								"quota": round(quota, 2),
								"used_quota": round(used_quota, 2),
								"display": f"Current balance: ${quota:.2f}, Used: ${used_quota:.2f}",
							}
				except Exception as parse_err:
					print(f"⚠️ {self.account_name}: Failed to parse localStorage user data: {parse_err}")

			print(f"⚠️ {self.account_name}: Failed to extract balance from /console/personal")
			return None
		except Exception as e:
			print(f"⚠️ {self.account_name}: Error extracting balance from /console/personal: {e}")
			return None

	async def signin(
		self,
		client_id: str,
		auth_state: str,
		auth_cookies: list,
		cache_file_path: str = "",
	) -> tuple[bool, dict]:
		"""使用 Linux.do 账号执行登录授权并返回 provider cookies / api_user"""

		print(f"ℹ️ {self.account_name}: Executing sign-in with Linux.do")
		print(
			f"ℹ️ {self.account_name}: Using client_id: {client_id}, auth_state: {auth_state}, cache_file: {cache_file_path}"
		)

		# 使用 Camoufox 启动浏览器
		async with AsyncCamoufox(
			headless=False,
			humanize=True,
			# 使用中文环境，更接近本地浏览器配置
			locale="zh-CN",
			# 为了可以点击 cross-origin 的 Turnstile iframe
			disable_coop=True,
			# 允许访问 scope / shadow-root，用于 playwright-captcha 检测 iframe
			config={"forceScopeAccess": True},
			i_know_what_im_doing=True,
			# 固定一个常见桌面分辨率，方便我们基于坐标点击
			window=(1280, 720),
		) as browser:
			# 只有在缓存文件存在时才加载 storage_state
			storage_state = cache_file_path if os.path.exists(cache_file_path) else None
			if storage_state:
				print(f"ℹ️ {self.account_name}: Found cache file, restore storage state")
			else:
				print(f"ℹ️ {self.account_name}: No cache file found, starting fresh")

			context = await browser.new_context(storage_state=storage_state)

			# 设置从参数获取的 auth cookies 到页面上下文
			if auth_cookies:
				await context.add_cookies(auth_cookies)
				print(f"ℹ️ {self.account_name}: Set {len(auth_cookies)} auth cookies from provider")
			else:
				print(f"ℹ️ {self.account_name}: No auth cookies to set")

			page = await context.new_page()

			try:
				is_logged_in = False
				# 使用与后端回调一致的 redirect_uri，避免默认跳转到 linux.do 论坛等其它站点
				redirect_uri = self.provider_config.get_linuxdo_auth_url()
				oauth_url = (
					"https://connect.linux.do/oauth2/authorize?"
					f"response_type=code&client_id={client_id}&state={auth_state}"
					f"&redirect_uri={quote(redirect_uri, safe='')}"
				)

				# 如果存在缓存，先尝试直接访问授权页面
				if os.path.exists(cache_file_path):
					try:
						print(
							f"ℹ️ {self.account_name}: Checking login status at {redact_url_for_log(oauth_url)}"
						)
						response = await page.goto(oauth_url, wait_until="domcontentloaded")
						print(
							f"ℹ️ {self.account_name}: redirected to app page "
							f"{redact_url_for_log(response.url) if response else 'N/A'}"
						)
						await self._save_page_content_to_file(page, "sign_in_check")
						# 调试：如果落在 Discourse SSO 中转页，截一张图便于确认页面实际内容
						try:
							redir = (response.url if response else "") or (page.url or "")
							if "linux.do/session/sso_provider" in redir:
								await page.wait_for_timeout(1200)
								await self._take_screenshot(page, "linuxdo_sso_provider_redirect")
								# /session/sso_provider 既可能是正常 SSO 中转，也可能是 CF challenge。
								# 先给它一点时间自然跳回 connect.linux.do；如果仍停留且检测到 CF 特征，再尝试解挑战。
								try:
									await page.wait_for_url("**connect.linux.do/**", timeout=8000)
								except Exception:
									pass
								try:
									cur2 = page.url or ""
									if "linux.do/session/sso_provider" in cur2:
										cf_probe = await page.evaluate(
											"""() => {
												try {
													const hasCfIframe = !!document.querySelector('iframe[src*="challenges.cloudflare.com"]');
													const hasTurnstileInput = !!document.querySelector('input[name="cf-turnstile-response"], textarea[name="cf-turnstile-response"]');
													const hasTurnstileWidget =
														!!document.querySelector('.cf-turnstile, [data-sitekey][data-theme], [data-sitekey][data-action], [data-sitekey][data-callback]');
													const hasChallengePlatform =
														!!document.querySelector('script[src*="/cdn-cgi/challenge-platform/"], link[href*="/cdn-cgi/challenge-platform/"]');
													const hasChlForm =
														!!document.querySelector(
															'form[action*="__cf_chl"], form#challenge-form, #challenge-form, input[name^="cf_chl_"], input[name="cf_challenge_response"]'
														);
													const hasCfSpinner =
														!!document.querySelector('#cf-spinner-please-wait, #cf-please-wait, #challenge-running, .cf-spinner');
													const hasCfRay = !!document.querySelector('#cf-ray, [data-ray]');
													const isTurnstile = hasCfIframe || hasTurnstileInput || hasTurnstileWidget;
													const isInterstitial = hasChallengePlatform || hasChlForm || hasCfSpinner || hasCfRay;
													return { detected: !!(isTurnstile || isInterstitial) };
												} catch (e) {
													return { detected: false };
												}
											}""",
										)
										if bool((cf_probe or {}).get("detected")):
											await self._handle_cloudflare_challenge(page, max_wait_seconds=45)
								except Exception:
									pass
						except Exception:
							pass

						# 某些情况下（如 Discourse SSO 中转页 /session/sso_provider），页面会先落在 linux.do，
						# 然后再自动跳回 connect.linux.do 展示授权按钮；这里不能立刻判定“缓存过期”。
						async def _wait_cache_oauth_ready() -> bool:
							try:
								start = time.time()
								tried_cf = False
								# 最多等待 15s，让 SSO 中转/重定向完成
								while time.time() - start < 15:
									cur = page.url or ""
									# 已直接回到 provider（可能已自动授权）
									if cur.startswith(self.provider_config.origin):
										return True
									# 进入登录页，说明确实失效
									if "/login" in cur:
										return False
									# 授权按钮出现，说明已登录
									try:
										if await page.query_selector('a[href^="/oauth2/approve"]'):
											return True
									except Exception:
										pass
									# 智能检测 Cloudflare challenge：不要仅凭 URL 粗暴判断（SSO 中转页也可能正常），
									# 仅当页面特征显示为 CF challenge 时才尝试解。
									try:
										if not tried_cf:
											cf_probe = await page.evaluate("""() => {
												try {
													const hasCfIframe = !!document.querySelector('iframe[src*="challenges.cloudflare.com"]');
													const hasTurnstileInput = !!document.querySelector('input[name="cf-turnstile-response"], textarea[name="cf-turnstile-response"]');
													const hasTurnstileWidget =
														!!document.querySelector('.cf-turnstile, [data-sitekey][data-theme], [data-sitekey][data-action], [data-sitekey][data-callback]');
													const hasChallengePlatform =
														!!document.querySelector('script[src*="/cdn-cgi/challenge-platform/"], link[href*="/cdn-cgi/challenge-platform/"]');
													const hasChlForm =
														!!document.querySelector(
															'form[action*="__cf_chl"], form#challenge-form, #challenge-form, input[name^="cf_chl_"], input[name="cf_challenge_response"]'
														);
													const hasCfSpinner =
														!!document.querySelector('#cf-spinner-please-wait, #cf-please-wait, #challenge-running, .cf-spinner');
													const hasCfRay = !!document.querySelector('#cf-ray, [data-ray]');
													const isTurnstile = hasCfIframe || hasTurnstileInput || hasTurnstileWidget;
													const isInterstitial = hasChallengePlatform || hasChlForm || hasCfSpinner || hasCfRay;
													return { detected: !!(isTurnstile || isInterstitial) };
												} catch (e) {
													return { detected: false };
												}
											}""")
											if bool((cf_probe or {}).get("detected")):
												tried_cf = True
												try:
													await self._handle_cloudflare_challenge(page, max_wait_seconds=45)
												except Exception:
													pass
										if not tried_cf:
											body = await page.content()
											if self._looks_like_cloudflare_interstitial_html(body[:4000]):
												tried_cf = True
												try:
													await self._handle_cloudflare_challenge(page, max_wait_seconds=45)
												except Exception:
													pass
									except Exception:
										pass
									await page.wait_for_timeout(600)
							except Exception:
								return False
							return False

						if response and response.url.startswith(self.provider_config.origin):
							is_logged_in = True
						else:
							is_logged_in = await _wait_cache_oauth_ready()

						if is_logged_in:
							print(
								f"✅ {self.account_name}: Already logged in via cache, proceeding to authorization"
							)
						else:
							print(f"ℹ️ {self.account_name}: Cache session expired, need to login again")
							# 优先尝试用 LINUXDOT 重建当前账号的 linuxdo storage-state，避免直接进入重登录。
							try:
								from utils.restore_linuxdot import restore_linuxdot_entry

								target_basename = os.path.basename(cache_file_path) if cache_file_path else ""
								restored, restore_reason = restore_linuxdot_entry(
									target_basename,
									force_overwrite=True,
								)
								if restored and cache_file_path and os.path.exists(cache_file_path):
									print(
										f"ℹ️ {self.account_name}: Rebuilt linuxdo state from LINUXDOT "
										f"({target_basename}, reason={restore_reason}), rechecking login..."
									)
									try:
										await page.close()
									except Exception:
										pass
									try:
										await context.close()
									except Exception:
										pass

									context = await browser.new_context(storage_state=cache_file_path)
									if auth_cookies:
										await context.add_cookies(auth_cookies)
									page = await context.new_page()

									response2 = await page.goto(oauth_url, wait_until="domcontentloaded")
									print(
										f"ℹ️ {self.account_name}: recheck redirected to "
										f"{redact_url_for_log(response2.url) if response2 else 'N/A'}"
									)
									await self._save_page_content_to_file(page, "sign_in_check_after_linuxdot_restore")

									if response2 and response2.url.startswith(self.provider_config.origin):
										is_logged_in = True
									else:
										is_logged_in = await _wait_cache_oauth_ready()

									if is_logged_in:
										print(
											f"✅ {self.account_name}: LINUXDOT state restore worked, skip relogin"
										)
									else:
										print(
											f"⚠️ {self.account_name}: LINUXDOT restored but still not logged in, "
											"will continue relogin flow"
										)
								else:
									print(
										f"ℹ️ {self.account_name}: LINUXDOT rebuild skipped "
										f"(target={target_basename or 'N/A'}, reason={restore_reason})"
									)
							except Exception as restore_err:
								print(f"⚠️ {self.account_name}: LINUXDOT rebuild attempt error: {restore_err}")
					except Exception as e:
						print(f"⚠️ {self.account_name}: Failed to check login status: {e}")

				# 如果未登录，则执行登录流程
				if not is_logged_in:
					try:
						print(f"ℹ️ {self.account_name}: Starting to sign in linux.do")

						try:
							login_resp = await page.goto("https://linux.do/login", wait_until="domcontentloaded")
						except Exception as nav_err:
							# 导航超时通常是 CF 拦截页阻塞了 domcontentloaded
							print(f"⚠️ {self.account_name}: linux.do/login navigation timeout, checking page state: {nav_err}")
							login_resp = None
							# 检查页面是否部分加载（CF challenge / 空白页）
							try:
								cur_url = page.url or ""
								if "linux.do" not in cur_url:
									raise RuntimeError(f"linux.do navigation failed completely (url={cur_url})")
							except RuntimeError:
								raise
							except Exception:
								pass
						try:
							if login_resp and getattr(login_resp, "status", None) == 429:
								raise RuntimeError("linux.do 返回 429（IP 被临时限流/封禁），请稍后重试或更换出口 IP")
						except Exception:
							raise
						# linux.do 登录页会出现 Cloudflare Turnstile/Interstitial，先尝试处理（失败不阻塞，后续仍可能人工通过）
						try:
							await solve_captcha(page, captcha_type="cloudflare", challenge_type="interstitial")
						except Exception:
							pass
						# Turnstile click solver 默认关闭；如需启用请设 LINUXDO_TRY_TURNSTILE_SOLVER=1
						if _should_try_turnstile_solver():
							try:
								await solve_captcha(page, captcha_type="cloudflare", challenge_type="turnstile")
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
										{"sel": sel, "value": value},
									)
									if ok:
										return True
								except Exception:
									continue
							return False

						user_ok = await _set_value(
							[
								"#login-account-name",
								"#signin_username",
								'input[name="login"]',
								'input[name="username"]',
								'input[type="email"]',
								'input[autocomplete="username"]',
							],
							self.username,
						)
						pwd_ok = await _set_value(
							[
								"#login-account-password",
								"#signin_password",
								'input[name="password"]',
								'input[type="password"]',
								'input[autocomplete="current-password"]',
							],
							self.password,
						)
						if not user_ok or not pwd_ok:
							await self._take_screenshot(page, "linuxdo_login_inputs_not_found")
							raise RuntimeError("linux.do login inputs not found or not editable")

						# 点击登录按钮（linux.do 近期使用 #signin-button；保留旧 id 兼容）
						clicked = False
						for sel in [
							"#signin-button",
							"#login-button",
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
							# 兜底：回车提交
							try:
								await page.press("#login-account-password", "Enter")
								clicked = True
							except Exception:
								pass

						# 等待跳出 /login（或出现授权按钮）
						try:
							await page.wait_for_function(
								"""() => {
									const u = location.href || '';
									if (u.includes('/oauth2/authorize')) return true;
									if (!u.includes('/login')) return true;
									const t = document.body ? (document.body.innerText || '') : '';
									return t.includes('授权') || t.includes('Authorize') || t.includes('/oauth2/approve');
								}""",
								timeout=90000,
							)
						except Exception:
							await self._take_screenshot(page, "linuxdo_login_timeout")
							raise RuntimeError("linux.do login submit timeout")

						await self._save_page_content_to_file(page, "sign_in_result")

						# 简单处理 Cloudflare challenge（如果存在）
						try:
							current_url = page.url
							print(f"ℹ️ {self.account_name}: Current page url is {current_url}")
							if "linux.do/challenge" in current_url:
								print(
									f"⚠️ {self.account_name}: Cloudflare challenge detected, "
									"Camoufox should bypass it automatically. Waiting..."
								)
								await page.wait_for_selector('a[href^="/oauth2/approve"]', timeout=60000)
								print(f"✅ {self.account_name}: Cloudflare challenge bypassed successfully")
						except Exception as e:
							print(f"⚠️ {self.account_name}: Possible Cloudflare challenge: {e}")

						# 保存新的会话状态（仅在确实离开登录页后保存，避免把错误页状态写进缓存）
						try:
							if "/login" not in page.url:
								await context.storage_state(path=cache_file_path)
								print(f"✅ {self.account_name}: Storage state saved to cache file")
						except Exception:
							pass
					except Exception as e:
						print(f"❌ {self.account_name}: Error occurred while signing in linux.do: {e}")
						# 登录流程异常时删除本地 linuxdo cache，避免后续运行反复命中过期状态
						if cache_file_path and os.path.exists(cache_file_path):
							try:
								os.remove(cache_file_path)
								print(f"ℹ️ {self.account_name}: Deleted invalid cache file after sign-in error: {cache_file_path}")
							except Exception as del_err:
								print(f"⚠️ {self.account_name}: Failed to delete invalid cache file: {del_err}")
						await self._take_screenshot(page, "signin_bypass_error")
						return False, {"error": "Linux.do sign-in error", "retry": True}

					# 登录后访问授权页面
					try:
						print(
							f"ℹ️ {self.account_name}: Navigating to authorization page: "
							f"{redact_url_for_log(oauth_url)}"
						)
						await page.goto(oauth_url, wait_until="domcontentloaded")
					except Exception as e:
						print(f"❌ {self.account_name}: Failed to navigate to authorization page: {e}")
						await self._take_screenshot(page, "auth_page_navigation_failed_bypass")
						# 导航授权页失败通常意味着当前缓存上下文异常，删除缓存后允许上层重试一次
						if cache_file_path and os.path.exists(cache_file_path):
							try:
								os.remove(cache_file_path)
								print(f"ℹ️ {self.account_name}: Deleted invalid cache file after auth navigation failure: {cache_file_path}")
							except Exception as del_err:
								print(f"⚠️ {self.account_name}: Failed to delete invalid cache file: {del_err}")
						return False, {"error": "Linux.do authorization page navigation failed", "retry": True}

					# 统一处理授权逻辑（无论是否通过缓存登录）
				try:
					oauth_redirect_url: str | None = None
					observed_oauth_urls: list[str] = []
					callback_attempted = False

					def _record_provider_url(u: str) -> None:
						try:
							if not u:
								return
							if not u.startswith(self.provider_config.origin):
								return
							# 只记录包含 code 的跳转（防止最终落在 /console/token 丢失 code）
							if "code=" in u and "linuxdo" in u:
								if u not in observed_oauth_urls:
									observed_oauth_urls.append(u)
						except Exception:
							return

					try:
						def on_frame_navigated(frame) -> None:
							try:
								_record_provider_url(frame.url)
							except Exception:
								return

						def on_request(req) -> None:
							try:
								_record_provider_url(req.url)
							except Exception:
								return

						page.on("framenavigated", on_frame_navigated)
						page.on("request", on_request)
					except Exception:
						pass

					# 快路径：如果已经落在 provider 回调 URL（已带 code），无需再等待/点击授权按钮
					try:
						cur0 = page.url or ""
						if cur0.startswith(self.provider_config.origin) and "code=" in cur0 and "linuxdo" in cur0:
							oauth_redirect_url = cur0
							print(
								f"ℹ️ {self.account_name}: OAuth already redirected (code detected): "
								f"{redact_url_for_log(oauth_redirect_url)}"
							)
					except Exception:
						pass

					# 如果还在 linux.do 的 SSO 中转页，给它一点时间跳回 connect.linux.do
					if not oauth_redirect_url:
						try:
							cur = page.url or ""
							if "/session/sso_provider" in cur:
								await page.wait_for_url("**connect.linux.do/**", timeout=15000)
						except Exception:
							pass

					allow_btn_ele = None
					if not oauth_redirect_url:
						print(f"ℹ️ {self.account_name}: Waiting for authorization button...")
						await page.wait_for_selector('a[href^="/oauth2/approve"]', timeout=30000)
						allow_btn_ele = await page.query_selector('a[href^="/oauth2/approve"]')

					if not oauth_redirect_url and not allow_btn_ele:
						print(f"❌ {self.account_name}: Approve button not found")
						await self._take_screenshot(page, "approve_button_not_found_bypass")
						return False, {"error": "Linux.do allow button not found"}

					if not oauth_redirect_url:
						print(f"ℹ️ {self.account_name}: Clicking authorization button...")
						try:
							# 避免 click 自带的“等待导航/网络空闲”导致超时（linux.do 有时会被挑战页/风控卡住）
							await allow_btn_ele.click(no_wait_after=True, timeout=30000)
						except Exception:
							# 兜底：走 JS click，不等待任何后续事件
							try:
								await page.evaluate("(el) => el && el.click && el.click()", allow_btn_ele)
							except Exception:
								raise
						# 等待跳转到 provider 的 OAuth 回调页面，并保存第一次匹配到的 OAuth URL，
						# 便于后续在站点发生二次重定向（例如跳转到 /app 或 /login）后依然能够解析到
						# 原始的 code/state 参数。
						try:
							await page.wait_for_url(
								f"**{self.provider_config.origin}/**",
								timeout=30000,
							)
							# 优先使用“带 code 的最早一次跳转”，否则回退到当前 URL
							oauth_redirect_url = observed_oauth_urls[0] if observed_oauth_urls else page.url
							print(
								f"ℹ️ {self.account_name}: Captured OAuth redirect URL: "
								f"{redact_url_for_log(oauth_redirect_url)}"
							)
						except Exception as nav_err:
							print(
								f"⚠️ {self.account_name}: Wait for OAuth redirect URL failed or timed out: {nav_err}"
							)
							# 尝试等待页面加载完成，避免直接视为失败
							try:
								await page.wait_for_load_state("load", timeout=5000)
							except Exception:
								await page.wait_for_timeout(5000)

					# 从 localStorage 获取 user 对象并提取 id
					api_user = None
					try:
						# 快路径：如果回调 URL 已包含 code/state，优先直接调用后端 /api/oauth/linuxdo 拿 api_user，
						# 这样可以跳过 SPA 写 localStorage 的慢等待；失败再走原有兜底逻辑。
						try:
							source_for_code = oauth_redirect_url or page.url
							parsed_fast = urlparse(source_for_code)
							q_fast = parse_qs(parsed_fast.query)
							code_fast_vals = q_fast.get("code")
							code_fast = code_fast_vals[0] if code_fast_vals else None

							# elysiver：必须走前端 /oauth/linuxdo（SPA）完成 OAuth 回调，才能真正建立 session/localStorage。
							# 若强行访问 /api/oauth/linuxdo，往往会停在 JSON 页，导致随后访问 /console/personal 被重定向到 /login?expired=true。
							if self.provider_config.name == "elysiver" and "oauth-redirect.html" in (page.url or ""):
								print(
									f"ℹ️ {self.account_name}: elysiver detected oauth-redirect.html, waiting for SPA /oauth/linuxdo to complete login..."
								)
								try:
									await page.wait_for_function(
										"""() => {
											const u = location.href || '';
											return u.includes('/oauth/linuxdo') || u.includes('/console') || u.includes('/login');
										}""",
										timeout=8000,
									)
								except Exception:
									# 兜底：如果 oauth-redirect 的自动跳转没触发，主动进入前端回调路由
									try:
										state_fast_vals = q_fast.get("state")
										state_fast = state_fast_vals[0] if state_fast_vals else auth_state
										if code_fast and state_fast:
											await page.goto(
												f"{self.provider_config.origin}/oauth/linuxdo?code={quote(code_fast, safe='')}&state={quote(str(state_fast), safe='')}",
												wait_until="domcontentloaded",
											)
									except Exception:
										pass

							# 可配置的 SPA 回调：依赖同源 /oauth/linuxdo 完成回调并写入 localStorage。
							# 为避免改变 wzw/elysiver 的既有特殊处理逻辑，这里仅对其它站点启用通用 SPA 回调。
							if (
								code_fast
								and self._linuxdo_callback_mode() == "spa"
								and self.provider_config.name not in {"wzw", "elysiver"}
							):
								print(
									f"ℹ️ {self.account_name}: {self.provider_config.name} OAuth: waiting for SPA /oauth/linuxdo to complete login..."
								)
								state_fast_vals = q_fast.get("state")
								state_fast = state_fast_vals[0] if state_fast_vals else auth_state

								ok_spa, result_spa = await self._complete_oauth_via_spa(page, code_fast, state_fast)
								if ok_spa and result_spa.get("api_user") and getattr(self.provider_config, "turnstile_check", False):
									# turnstile 站点需要在同一浏览器中完成签到（避免新浏览器指纹不匹配导致 session 失效）
									checkin_done_spa = await self._browser_check_in_with_turnstile(page)
									user_info_spa = await self._extract_balance_from_profile(page)
									if checkin_done_spa and not user_info_spa:
										user_info_spa = {
											"success": True,
											"quota": 0.0,
											"used_quota": 0.0,
											"display": "今日已签到（余额解析失败）",
										}
									if user_info_spa:
										result_spa["user_info"] = user_info_spa
								return ok_spa, result_spa

							mode = self._linuxdo_callback_mode()
							if code_fast and mode != "spa" and self.provider_config.name != "elysiver":
								callback_attempted = True
								# Veloera 系站点（如 elysiver）更容易在回调接口触发 CF/WAF，避免先用 fetch 反复打回调导致 429
								if mode == "navigation" or (mode == "auto" and self._prefer_callback_navigation()):
									api_user_fast = await self._call_provider_linuxdo_callback_via_navigation(
										page, code_fast, auth_state
									)
								else:
									api_user_fast = await self._call_provider_linuxdo_callback_fast(
										page, code_fast, auth_state
									)
								if api_user_fast:
									print(
										f"✅ {self.account_name}: Got api user from fast callback fetch: {api_user_fast}"
									)
									# elysiver: 需要在浏览器中执行签到
									user_info_fast = None
									if self.provider_config.name == "elysiver":
										# elysiver: 先等待当前页面完成登录流程，确保 session 建立
										print(f"ℹ️ {self.account_name}: Waiting for elysiver to establish session after OAuth callback")
										
										# 等待 localStorage 中出现 user 数据，表示前端已完成登录
										try:
											await page.wait_for_function(
												"""() => {
													try {
														const user = localStorage.getItem('user');
														return user !== null && user !== '';
													} catch (e) {
														return false;
													}
												}""",
												timeout=10000,
											)
											print(f"✅ {self.account_name}: elysiver localStorage user detected, session established")
										except Exception:
											print(f"⚠️ {self.account_name}: elysiver localStorage user not found, trying page reload")
											await page.reload(wait_until="networkidle")
											await page.wait_for_timeout(3000)
										
										# 导航到控制台页面
										print(f"ℹ️ {self.account_name}: Navigating to console to establish session")
										await page.goto(f"{self.provider_config.origin}/console", wait_until="networkidle")
										await page.wait_for_timeout(2000)
										
										# 检测 session 是否有效（如果被重定向到登录页则 session 已过期）
										console_url = page.url or ""
										if "/login" in console_url:
											expired_msg = "expired=true" if "expired=true" in console_url else "invalid"
											print(f"⚠️ {self.account_name}: elysiver session {expired_msg} after OAuth callback, clearing cache for retry...")

											# 删除缓存文件，强制下次重新登录
											if cache_file_path and os.path.exists(cache_file_path):
												try:
													os.remove(cache_file_path)
													print(f"ℹ️ {self.account_name}: Deleted cache file: {cache_file_path}")
												except Exception as del_err:
													print(f"⚠️ {self.account_name}: Failed to delete cache file: {del_err}")

											await self._take_screenshot(page, f"{self.provider_config.name}_session_expired_need_retry")
											return False, {"error": "session_verify_failed_need_retry", "retry": True}
										else:
											checkin_done_fast = await self._browser_check_in_with_turnstile(page)
											user_info_fast = await self._extract_balance_from_profile(page)
											if checkin_done_fast and not user_info_fast and self.provider_config.name == "elysiver":
												user_info_fast = {
													"success": True,
													"quota": 0.0,
													"used_quota": 0.0,
													"display": "今日已签到（余额解析失败）",
												}

									restore_cookies = await page.context.cookies()
									user_cookies = filter_cookies(
										restore_cookies, self.provider_config.origin
									)
									# 将 provider 侧 cookies 持久化到 cache_file（包含 runanytime session）
									try:
										await page.context.storage_state(path=cache_file_path)
									except Exception:
										pass
									result_fast: dict = {"cookies": user_cookies, "api_user": api_user_fast}
									if user_info_fast:
										result_fast["user_info"] = user_info_fast
									return True, result_fast
								# fetch 失败时，尝试用"页面导航回调"确保 session cookie 写入（Veloera 分支已优先走过）
								if not self._prefer_callback_navigation():
									api_user_nav = await self._call_provider_linuxdo_callback_via_navigation(
										page, code_fast, auth_state
									)
									if api_user_nav:
										print(
											f"✅ {self.account_name}: Got api user from callback navigation: {api_user_nav}"
										)
										# elysiver: 需要在浏览器中执行签到
										user_info_nav = None
										if self.provider_config.name == "elysiver":
											# elysiver: 先等待当前页面完成登录流程，确保 session 建立
											print(f"ℹ️ {self.account_name}: Waiting for elysiver to establish session after OAuth callback")
											
											# 等待 localStorage 中出现 user 数据
											try:
												await page.wait_for_function(
													"""() => {
														try {
															const user = localStorage.getItem('user');
															return user !== null && user !== '';
														} catch (e) {
															return false;
														}
													}""",
													timeout=10000,
												)
												print(f"✅ {self.account_name}: elysiver localStorage user detected, session established")
											except Exception:
												print(f"⚠️ {self.account_name}: elysiver localStorage user not found, trying page reload")
												await page.reload(wait_until="networkidle")
												await page.wait_for_timeout(3000)
											
											# 导航到控制台页面
											print(f"ℹ️ {self.account_name}: Navigating to console to establish session")
											await page.goto(f"{self.provider_config.origin}/console", wait_until="networkidle")
											await page.wait_for_timeout(2000)
											
											# 检测 session 是否有效
											console_url = page.url or ""
											if "/login" in console_url:
												expired_msg = "expired=true" if "expired=true" in console_url else "invalid"
												print(f"⚠️ {self.account_name}: elysiver session {expired_msg} after OAuth callback, clearing cache for retry...")

												# 删除缓存文件，强制下次重新登录
												if cache_file_path and os.path.exists(cache_file_path):
													try:
														os.remove(cache_file_path)
														print(f"ℹ️ {self.account_name}: Deleted cache file: {cache_file_path}")
													except Exception as del_err:
														print(f"⚠️ {self.account_name}: Failed to delete cache file: {del_err}")

												await self._take_screenshot(page, f"{self.provider_config.name}_session_expired_need_retry")
												return False, {"error": "session_verify_failed_need_retry", "retry": True}
											else:
												checkin_done_nav = await self._browser_check_in_with_turnstile(page)
												user_info_nav = await self._extract_balance_from_profile(page)
												if checkin_done_nav and not user_info_nav and self.provider_config.name == "elysiver":
													user_info_nav = {
														"success": True,
														"quota": 0.0,
														"used_quota": 0.0,
														"display": "今日已签到（余额解析失败）",
													}

										restore_cookies = await page.context.cookies()
										user_cookies = filter_cookies(
											restore_cookies, self.provider_config.origin
										)
										try:
											await page.context.storage_state(path=cache_file_path)
										except Exception:
											pass
										result_nav: dict = {"cookies": user_cookies, "api_user": api_user_nav}
										if user_info_nav:
											result_nav["user_info"] = user_info_nav
										return True, result_nav
						except Exception:
							pass

						# OAuth 回调页通常会再跳转到 /console/* 才写入 localStorage，这里做更稳健的等待：
						# 1) 优先等待 localStorage 出现 user 相关 key
						try:
							await page.wait_for_function(
								"""() => {
									return (
										localStorage.getItem('user') !== null ||
										localStorage.getItem('user_info') !== null ||
										localStorage.getItem('userInfo') !== null
									);
								}""",
								timeout=20000,
							)
						except Exception:
							# 2) 如果未等到，尝试等待跳转到控制台（很多 new-api 站点会走 /console）
							try:
								await page.wait_for_url(
									f"**{self.provider_config.origin}/console**",
									timeout=15000,
								)
							except Exception:
								# 3) 再给一点时间让 SPA 初始化
								try:
									await page.wait_for_timeout(4000)
								except Exception:
									pass

						api_user = await self._extract_api_user_from_localstorage(page)
						if api_user:
							print(f"✅ {self.account_name}: Got api user from localStorage: {api_user}")
						else:
							# 如果当前落在 /api/oauth/* 这类 JSON 输出页，尝试从 body 解析
							api_user = await self._extract_api_user_from_body_json(page)
							if api_user:
								print(
									f"✅ {self.account_name}: Got api user from OAuth JSON response: {api_user}"
								)

						# 某些站点需要进入 /app 才会写入 localStorage，再做一次页面候选跳转
						if not api_user:
							for path in self.APP_FALLBACK_PATH_CANDIDATES:
								try:
									await page.goto(
										f"{self.provider_config.origin}{path}",
										wait_until="domcontentloaded",
									)
									try:
										await page.wait_for_function(
											'localStorage.length > 0',
											timeout=8000,
										)
									except Exception:
										await page.wait_for_timeout(2000)

									api_user = await self._extract_api_user_from_localstorage(page)
									if api_user:
										print(
											f"✅ {self.account_name}: Got api user from app fallback ({path}): "
											f"{api_user}"
										)
										break
								except Exception:
									continue
					except Exception as e:
						print(f"⚠️ {self.account_name}: Error reading user from localStorage: {e}")

					if api_user:
						print(f"✅ {self.account_name}: OAuth authorization successful")

						# wzw 站点：localStorage 有 user 不代表服务端 session 已建立。
						# 需要等待 SPA 完成 OAuth 流程，确保 session cookie 被正确设置。
						if self.provider_config.name == "wzw":
							print(f"ℹ️ {self.account_name}: wzw: waiting for session to be established...")
							try:
								# 等待一小段时间让 SPA 完成 OAuth 回调处理
								await page.wait_for_timeout(2000)

								# 导航到 /console 触发 session 验证
								try:
									await page.goto(f"{self.provider_config.origin}/console", wait_until="networkidle")
									await page.wait_for_timeout(1000)
								except Exception:
									pass

								# 验证 session 是否有效：尝试调用 /api/user/self
								try:
									api_response = await page.evaluate("""
										async () => {
											try {
												const resp = await fetch('/api/user/self', {
													method: 'GET',
													headers: {
														'Accept': 'application/json',
														'Content-Type': 'application/json'
													},
													credentials: 'include'
												});
												return { status: resp.status, ok: resp.ok };
											} catch (e) {
												return { status: 0, ok: false, error: e.message };
											}
										}
									""")
									if api_response and api_response.get("ok"):
										print(f"✅ {self.account_name}: wzw session verified successfully")
									else:
										print(f"⚠️ {self.account_name}: wzw session verification returned status {api_response.get('status')}")
										# 如果 session 无效，尝试重新导航到 OAuth 回调 URL
										if oauth_redirect_url:
											print(f"ℹ️ {self.account_name}: wzw: retrying OAuth callback navigation...")
											try:
												await page.goto(oauth_redirect_url, wait_until="networkidle")
												await page.wait_for_timeout(3000)
											except Exception:
												pass
								except Exception as verify_err:
									print(f"⚠️ {self.account_name}: wzw session verification error: {verify_err}")
							except Exception as wzw_err:
								print(f"⚠️ {self.account_name}: wzw session wait error: {wzw_err}")

						# runanytime/new-api：localStorage 里有 user 不代表服务端 session 已建立。
						# 这里用 /api/user/self（带 new-api-user）强校验；若失败则删除缓存并返回 retry 标记。
							if self.provider_config.name == "runanytime":
								ok = await self._runanytime_verify_session(page, str(api_user))
								if not ok:
									print(
										f"⚠️ {self.account_name}: runanytime session verify failed (401), "
										"clearing provider cache for retry..."
									)
									# 401 分支仅清理 provider 侧缓存，不清理 linux.do 缓存。
									self._clear_provider_site_caches(
										cache_file_path,
										include_linuxdo_state=False,
									)

									await self._take_screenshot(page, "runanytime_session_401_need_retry")
									return False, {"error": "session_verify_failed_need_retry", "retry": True}

						# 对于启用了 Turnstile 的站点（如 runanytime），在浏览器中直接完成每日签到
						user_info = None
						# newapi 通用签到入口在控制台 `/console/personal`（右侧“立即签到”）。
						# 此处仅负责完成登录与 cookies 提取，不在登录流程里强依赖旧的 /app/me DOM 解析。
						if getattr(self.provider_config, "turnstile_check", False) and self.provider_config.name != "runanytime":
							checkin_done = await self._browser_check_in_with_turnstile(page)
							# 在同一页面上直接解析余额信息，避免额外的 HTTP 请求
							user_info = await self._extract_balance_from_profile(page)
							if checkin_done and not user_info:
								user_info = {
									"success": True,
									"quota": 0.0,
									"used_quota": 0.0,
									"display": "今日已签到（余额解析失败）",
								}

						# 提取 session cookie，只保留与 provider domain 匹配的
						restore_cookies = await page.context.cookies()
						user_cookies = filter_cookies(restore_cookies, self.provider_config.origin)

						result: dict = {"cookies": user_cookies, "api_user": api_user}
						if user_info:
							result["user_info"] = user_info

						# 将 provider 侧 cookies 持久化到 cache_file（包含 runanytime session）
						try:
							await page.context.storage_state(path=cache_file_path)
						except Exception:
							pass

						return True, result

						# 未能从 localStorage 获取 user，尝试从回调 URL 中解析 code
						print(f"⚠️ {self.account_name}: OAuth callback received but no user ID found")
						await self._take_screenshot(page, "oauth_failed_no_user_id_bypass")
						# 按 provider 维度清理站点缓存（例如 runanytime），避免残留坏状态反复失败。
						# 这里不清理 linux.do 缓存，只清理 provider 侧缓存。
						self._clear_provider_site_caches(cache_file_path, include_linuxdo_state=False)
					# 回调没有 user_id 时，先尝试用 LINUXDOT 重建 linuxdo state 并重试一次 OAuth，
					# 避免直接落到 no-code 失败。
					try:
						from utils.restore_linuxdot import restore_linuxdot_entry

						target_basename = os.path.basename(cache_file_path) if cache_file_path else ""
						restored, restore_reason = restore_linuxdot_entry(
							target_basename,
							force_overwrite=True,
						)
						if restored and cache_file_path and os.path.exists(cache_file_path):
							print(
								f"ℹ️ {self.account_name}: Rebuilt linuxdo state from LINUXDOT "
								f"({target_basename}, reason={restore_reason}), rechecking login..."
							)
							try:
								await page.close()
							except Exception:
								pass
							try:
								await context.close()
							except Exception:
								pass

							context = await browser.new_context(storage_state=cache_file_path)
							if auth_cookies:
								await context.add_cookies(auth_cookies)
							page = await context.new_page()

							resp_retry = None
							try:
								resp_retry = await page.goto(oauth_url, wait_until="domcontentloaded")
							except Exception as retry_err:
								print(
									f"⚠️ {self.account_name}: OAuth recheck navigation after LINUXDOT restore failed: {retry_err}"
								)
							print(
								f"ℹ️ {self.account_name}: recheck redirected to "
								f"{redact_url_for_log(resp_retry.url) if resp_retry else redact_url_for_log(page.url)}"
							)
							await self._save_page_content_to_file(page, "oauth_no_user_recheck_after_linuxdot_restore")

							# 先再尝试一次直接取 user_id，成功则直接返回。
							try:
								await page.wait_for_function(
									"""() => {
										return (
											localStorage.getItem('user') !== null ||
											localStorage.getItem('user_info') !== null ||
											localStorage.getItem('userInfo') !== null
										);
									}""",
									timeout=10000,
								)
							except Exception:
								pass

							api_user_retry = await self._extract_api_user_from_localstorage(page)
							if not api_user_retry:
								api_user_retry = await self._extract_api_user_from_body_json(page)

							if api_user_retry:
								print(f"✅ {self.account_name}: Got api user after LINUXDOT recheck: {api_user_retry}")
								restore_cookies = await page.context.cookies()
								user_cookies = filter_cookies(restore_cookies, self.provider_config.origin)
								try:
									await page.context.storage_state(path=cache_file_path)
								except Exception:
									pass
								return True, {"cookies": user_cookies, "api_user": api_user_retry}

							# 更新候选回调 URL，供下方 code 解析继续使用
							if resp_retry and getattr(resp_retry, "url", ""):
								oauth_redirect_url = resp_retry.url
						else:
							print(
								f"ℹ️ {self.account_name}: LINUXDOT rebuild skipped "
								f"(target={target_basename or 'N/A'}, reason={restore_reason})"
							)
					except Exception as rebuild_err:
						print(f"⚠️ {self.account_name}: LINUXDOT rebuild on missing user_id error: {rebuild_err}")
					# 优先使用首次捕获到的 OAuth 回调 URL（如果存在），避免站点后续重定向到
					# /app/me 或 /login?expired 等页面导致 code/state 丢失。
					source_url = oauth_redirect_url or page.url
					if oauth_redirect_url:
						print(
							f"ℹ️ {self.account_name}: Using captured OAuth redirect URL for code parsing: "
							f"{redact_url_for_log(oauth_redirect_url)}"
						)
					else:
						print(
							f"ℹ️ {self.account_name}: No captured OAuth redirect URL, fallback to current page URL: "
							f"{redact_url_for_log(page.url)}"
						)

					parsed_url = urlparse(source_url)
					query_params = parse_qs(parsed_url.query)

					code_values = query_params.get("code")
					code = code_values[0] if code_values else None
					if code:
						print(
							f"✅ {self.account_name}: OAuth code received: "
							f"{redact_value_for_log(code) or '***'}"
						)
					else:
						print(f"❌ {self.account_name}: OAuth failed, no code in callback")
						self._clear_provider_site_caches(cache_file_path)
						return False, {
							"error": "Linux.do OAuth failed - no code in callback",
							"retry": True,
						}

					# elysiver：必须走前端 /oauth/linuxdo（SPA）完成 OAuth 回调，才能建立 session/localStorage。
					# 这里如果继续调用 /api/oauth/linuxdo，往往会落在 JSON 页，导致后续 /console/personal 被重定向到 /login?expired=true。
					if self.provider_config.name == "elysiver":
						print(f"ℹ️ {self.account_name}: elysiver OAuth: waiting for SPA to complete OAuth flow...")
						try:
							state_vals = query_params.get("state")
							state_q = state_vals[0] if state_vals else auth_state
							cur = page.url or ""
							if "/oauth/linuxdo" not in cur:
								try:
									await page.goto(
										f"{self.provider_config.origin}/oauth/linuxdo?code={quote(code, safe='')}&state={quote(str(state_q), safe='')}",
										wait_until="domcontentloaded",
									)
								except Exception:
									pass

							try:
								await page.wait_for_function(
									"""() => {
										try {
											const user = localStorage.getItem('user');
											return user !== null && user !== '';
										} catch (e) {
											return false;
										}
									}""",
									timeout=15000,
								)
							except Exception:
								await page.wait_for_timeout(3000)

							api_user_ely = await self._extract_api_user_from_localstorage(page)
							if api_user_ely:
								print(f"✅ {self.account_name}: Got api user from elysiver localStorage: {api_user_ely}")
								restore_cookies_ely = await page.context.cookies()
								user_cookies_ely = filter_cookies(restore_cookies_ely, self.provider_config.origin)
								return True, {"cookies": user_cookies_ely, "api_user": api_user_ely}

							if "/login" in (page.url or ""):
								return False, {"error": "elysiver OAuth session not established (redirected to login)", "retry": True}
							return False, {"error": "elysiver OAuth flow failed - no user in localStorage", "retry": True}
						except Exception as ely_err:
							return False, {"error": f"elysiver OAuth flow error: {ely_err}", "retry": True}

					# 快路径：先直接调用后端回调接口拿到 api_user（通常比等 localStorage/跳转更快）
					# wzw 站点例外：需要让 SPA 自行处理 OAuth 回调建立 session
					if self.provider_config.name == "wzw":
						# wzw: 等待 SPA 自然完成 OAuth 流程，不要手动导航到 API 端点
						# 这样可以让前端正确建立 session，避免后续签到 401
						print(f"ℹ️ {self.account_name}: wzw OAuth: waiting for SPA to complete OAuth flow...")
						try:
							# 等待 localStorage 中出现 user 数据，表示 SPA 已完成 OAuth 处理
							try:
								await page.wait_for_function(
									"""() => {
										try {
											const user = localStorage.getItem('user');
											return user !== null && user !== '';
										} catch (e) {
											return false;
										}
									}""",
									timeout=15000,
								)
								print(f"✅ {self.account_name}: wzw localStorage user detected")
							except Exception:
								# 如果等待超时，尝试导航到 /console 触发 SPA 初始化
								print(f"⚠️ {self.account_name}: wzw localStorage timeout, trying /console navigation...")
								try:
									await page.goto(f"{self.provider_config.origin}/console", wait_until="networkidle")
									await page.wait_for_timeout(3000)
								except Exception:
									pass

							# 从 localStorage 获取 api_user
							api_user_wzw = await self._extract_api_user_from_localstorage(page)
							if api_user_wzw:
								print(f"✅ {self.account_name}: Got api user from wzw localStorage: {api_user_wzw}")
								restore_cookies_wzw = await page.context.cookies()
								user_cookies_wzw = filter_cookies(
									restore_cookies_wzw, self.provider_config.origin
								)
								print(f"ℹ️ {self.account_name}: wzw cookies extracted: {len(user_cookies_wzw)} cookies")
								return True, {"cookies": user_cookies_wzw, "api_user": api_user_wzw}
							else:
								# 如果仍然无法获取 api_user，返回 OAuth code 让上层通过 HTTP 调用回调
								print(f"⚠️ {self.account_name}: wzw: no api_user in localStorage, returning OAuth code")
								return True, {"code": [code], "state": [auth_state] if auth_state else []}
						except Exception as wzw_err:
							print(f"⚠️ {self.account_name}: wzw OAuth flow error: {wzw_err}")
							# 返回 OAuth code 让上层处理
							return True, {"code": [code], "state": [auth_state] if auth_state else []}

					# 可配置的通用 SPA 回调（非 wzw/elysiver）：依赖同源 /oauth/linuxdo 完成回调并写入 localStorage。
					if self._linuxdo_callback_mode() == "spa" and self.provider_config.name not in {"wzw", "elysiver"}:
						print(
							f"ℹ️ {self.account_name}: {self.provider_config.name} OAuth: waiting for SPA /oauth/linuxdo to complete OAuth flow..."
						)
						ok_spa, data_spa = await self._complete_oauth_via_spa(page, code, auth_state)
						return ok_spa, data_spa

					if callback_attempted and self._prefer_callback_navigation():
						return False, {"error": "Linux.do 回调被 Cloudflare/WAF 拦截或限流(429)，请稍后重试"}

					try:
						callback_attempted = True
						mode2 = self._linuxdo_callback_mode()
						if mode2 == "navigation" or (mode2 == "auto" and self._prefer_callback_navigation()):
							api_user_fast2 = await self._call_provider_linuxdo_callback_via_navigation(
								page, code, auth_state
							)
						else:
							api_user_fast2 = await self._call_provider_linuxdo_callback_fast(
								page, code, auth_state
							)
						if api_user_fast2:
							print(
								f"✅ {self.account_name}: Got api_user from fast callback fetch: {api_user_fast2}"
							)
							restore_cookies_fast2 = await page.context.cookies()
							user_cookies_fast2 = filter_cookies(
								restore_cookies_fast2, self.provider_config.origin
							)
							return True, {"cookies": user_cookies_fast2, "api_user": api_user_fast2}
					except Exception:
						pass

						# 对于启用了 Turnstile 校验的站点（如 runanytime / elysiver），
						# 不再手动调用 Linux.do 回调接口，而是依赖前端完成 OAuth，
						# 然后在 /app 页面中解析 user 信息。如果这里依然拿不到 user，
						# 则直接视为本次认证失败，避免重复使用 code 触发后端错误。
						if getattr(self.provider_config, "turnstile_check", False):
							try:
								api_user_fb = None
								for path in self.APP_FALLBACK_PATH_CANDIDATES:
									target_url = f"{self.provider_config.origin}{path}"
									print(
										f"ℹ️ {self.account_name}: Navigating to app page for OAuth fallback: "
										f"{target_url}"
									)
									await page.goto(target_url, wait_until="networkidle")

									try:
										await page.wait_for_function(
											'localStorage.length > 0',
											timeout=15000,
										)
									except Exception:
										await page.wait_for_timeout(3000)

									api_user_fb = await self._extract_api_user_from_localstorage(page)
									if api_user_fb:
										print(
											f"✅ {self.account_name}: Got api user from app fallback ({path}): "
											f"{api_user_fb}"
										)
										break

								if api_user_fb:
									user_info_fb = None
									try:
										if self.provider_config.name != "runanytime":
											checkin_done_fb = await self._browser_check_in_with_turnstile(page)
											user_info_fb = await self._extract_balance_from_profile(page)
											if checkin_done_fb and not user_info_fb and self.provider_config.name == "elysiver":
												user_info_fb = {
													"success": True,
													"quota": 0.0,
													"used_quota": 0.0,
													"display": "今日已签到（余额解析失败）",
												}
									except Exception as fb_chk_err:
										print(
											f"⚠️ {self.account_name}: Error during browser check-in fallback: "
											f"{fb_chk_err}"
										)

									restore_cookies_fb = await page.context.cookies()
									user_cookies_fb = filter_cookies(
										restore_cookies_fb, self.provider_config.origin
									)

									result_fb: dict = {
										"cookies": user_cookies_fb,
										"api_user": api_user_fb,
									}
									if user_info_fb:
										result_fb["user_info"] = user_info_fb

									return True, result_fb

								print(
									f"⚠️ {self.account_name}: No user found in localStorage after /app fallback "
									f"for Turnstile provider"
								)
							except Exception as fb_err:
								print(
									f"⚠️ {self.account_name}: Error during Turnstile provider OAuth fallback: "
									f"{fb_err}"
								)
							# localStorage 兜底失败并不代表 OAuth 失败：
							# 对于 new-api 站点，真正建立会话的是后端回调 `/api/oauth/linuxdo`。
							# 继续向下走“浏览器内调用回调接口”的通用逻辑，尝试从回调 JSON 拿到 api_user。

						# 优先在浏览器内通过页面导航方式调用 Linux.do 回调接口，避免 httpx 再次触发 Cloudflare
						try:
							base_callback_url = self.provider_config.get_linuxdo_auth_url()

							# 构建带 code/state 参数的完整回调 URL
							parsed_cb = urlparse(base_callback_url)
							cb_query = parse_qs(parsed_cb.query)
							cb_query["code"] = [code]
							if auth_state:
								cb_query["state"] = [auth_state]
							final_query = urlencode(cb_query, doseq=True)
							final_callback_url = parsed_cb._replace(query=final_query).geturl()

							print(
								f"ℹ️ {self.account_name}: Calling Linux.do callback via browser navigation: "
								f"{redact_url_for_log(final_callback_url)}"
							)

							status = 0
							text = ""

							for attempt in range(2):
								response = await page.goto(final_callback_url, wait_until="domcontentloaded")

								current_url = page.url
								print(
									f"ℹ️ {self.account_name}: Callback page current url is "
									f"{redact_url_for_log(current_url)}"
								)

								# 读取本次响应的状态码和正文文本
								status = 0
								text = ""
								if response is not None:
									try:
										status = response.status
										text = await response.text()
									except Exception as resp_err:
										print(
											f"⚠️ {self.account_name}: Failed to read callback response body: {resp_err}"
										)

								# 判断是否疑似 Cloudflare 挑战页
								is_cf_challenge = False
								if (
									"challenges.cloudflare.com" in current_url
									or "/challenge" in current_url
									or "__cf_chl_" in current_url
								):
									is_cf_challenge = True

								if not is_cf_challenge and status in (403, 429):
									try:
										html_snippet = (await page.content())[:5000]
										if (
											"Just a moment" in html_snippet
											or "cf-browser-verification" in html_snippet
											or "Cloudflare" in html_snippet
											or "challenges.cloudflare.com" in html_snippet
										):
											is_cf_challenge = True
									except Exception as cf_html_err:
										print(
											f"⚠️ {self.account_name}: Failed to inspect callback page HTML for "
											f"Cloudflare markers: {cf_html_err}"
										)

								if is_cf_challenge:
									print(
										f"⚠️ {self.account_name}: Cloudflare challenge detected on callback page, "
										f"attempting to solve"
									)

									# 如果 playwright-captcha 可用，尝试解决整页拦截
									if solve_captcha is not None:
										try:
											print(
												f"ℹ️ {self.account_name}: Solving Cloudflare interstitial on callback "
												f"page via playwright-captcha ClickSolver"
											)
											solved_cb = await solve_captcha(
												page,
												captcha_type="cloudflare",
												challenge_type="interstitial",
											)
											print(
												f"ℹ️ {self.account_name}: playwright-captcha solve result on callback "
												f"page: {solved_cb}"
											)
										except Exception as sc_err:
											print(
												f"⚠️ {self.account_name}: playwright-captcha error on callback page: "
												f"{sc_err}"
											)
									else:
										# 没有自动解法时，至少等待一段时间让 Cloudflare JS 检查自动完成
										await page.wait_for_timeout(15000)

									# 首次尝试遇到 Cloudflare 时，在解决后重试一次回调
									if attempt == 0:
										print(
											f"ℹ️ {self.account_name}: Retrying Linux.do callback after solving "
											f"Cloudflare challenge"
										)
										continue

								# 没有检测到 Cloudflare 挑战，或已经重试过，尝试解析 JSON
								if status == 200 and text:
									try:
										json_data = json.loads(text)
									except Exception as parse_err:
										print(
											f"⚠️ {self.account_name}: Failed to parse Linux.do callback JSON: {parse_err}"
										)
									else:
										if json_data and json_data.get("success"):
											user_data = json_data.get("data", {})
											api_user_from_cb = user_data.get("id")

											if api_user_from_cb:
												print(
													f"✅ {self.account_name}: Got api_user from Linux.do callback JSON: "
													f"{api_user_from_cb}"
												)

												# 提取 session cookie，只保留与 provider domain 匹配的
												restore_cookies = await page.context.cookies()
												user_cookies = filter_cookies(
													restore_cookies, self.provider_config.origin
												)

												# 对于启用了 Turnstile 的站点（如 runanytime），在浏览器中直接完成每日签到
												user_info_cb = None
												if getattr(self.provider_config, "turnstile_check", False) and self.provider_config.name != "runanytime":
													checkin_done_cb = await self._browser_check_in_with_turnstile(page)
													user_info_cb = await self._extract_balance_from_profile(page)
													if checkin_done_cb and not user_info_cb and self.provider_config.name == "elysiver":
														user_info_cb = {
															"success": True,
															"quota": 0.0,
															"used_quota": 0.0,
															"display": "今日已签到（余额解析失败）",
														}

												result_cb: dict = {
													"cookies": user_cookies,
													"api_user": api_user_from_cb,
												}
												if user_info_cb:
													result_cb["user_info"] = user_info_cb

												return True, result_cb

								# 如果本次尝试没有成功解析 JSON，则不再在循环中处理，统一由下方日志 / 兜底逻辑接管
								break

							print(
								f"⚠️ {self.account_name}: Linux.do callback via browser navigation failed or not "
								f"JSON success (HTTP {status}), body: {text[:200]}"
							)
						except Exception as cb_err:
							print(
								f"⚠️ {self.account_name}: Error during Linux.do callback via browser navigation: "
								f"{cb_err}"
							)

						# 浏览器回调失败：对 Veloera/Turnstile 站点，回退到 httpx 基本也会被 CF/WAF 拦截，直接判定失败，
						# 避免反复打回调触发 429 以及 code 被消耗。
						if self._prefer_callback_navigation():
							return False, {"error": "Linux.do 回调被 Cloudflare/WAF 拦截或限流(429)，请稍后重试"}

						# 非 Turnstile 站点仍保留旧逻辑：返回 code/state 由上层 httpx 调用
						return True, query_params

					print(f"❌ {self.account_name}: OAuth failed, no code in callback")
					self._clear_provider_site_caches(cache_file_path)
					return False, {
						"error": "Linux.do OAuth failed - no code in callback",
						"retry": True,
					}
				except Exception as e:
					print(
						f"❌ {self.account_name}: Error occurred during authorization: {e}\n\n"
						f"Current page is: {page.url}"
					)
					await self._take_screenshot(page, "authorization_failed_bypass")
					return False, {"error": "Linux.do authorization failed"}
			except Exception as e:
				print(f"❌ {self.account_name}: Error occurred while processing linux.do page: {e}")
				await self._take_screenshot(page, "page_navigation_error_bypass")
				return False, {"error": "Linux.do page navigation error"}
			finally:
				await page.close()
				await context.close()
