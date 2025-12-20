#!/usr/bin/env python3
"""
使用 Camoufox 通过 Linux.do 执行 OAuth 登录，并在浏览器中完成带 Cloudflare Turnstile 验证的每日签到。

主要用于 runanytime.hxi.me 这类需要在前端页面完成签到的站点。
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlparse, quote, urlencode

from camoufox.async_api import AsyncCamoufox

from utils.browser_utils import filter_cookies
from utils.config import ProviderConfig

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

		async with ClickSolver(framework=framework, page=page) as solver:
			# 对于 ClickSolver，solve_captcha 在成功时不会返回 token，能正常返回即视为成功
			await solver.solve_captcha(captcha_container=page, captcha_type=target_type)
			return True
	except Exception as e:
		print(f"⚠️ LinuxDoSignIn: playwright-captcha solve_captcha error: {e}")
		return False


class LinuxDoSignIn:
	"""使用 Linux.do 账号完成 OAuth 授权，并在浏览器中执行签到。"""

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
					await self._take_screenshot(page, "runanytime_turnstile_iframe_not_found")
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

	async def _browser_check_in_with_turnstile(self, page) -> None:
		"""在 provider 的页面中执行带 Turnstile 的每日签到"""
		try:
			target_url = f"{self.provider_config.origin}/app/me"
			print(f"ℹ️ {self.account_name}: Navigating to profile page for check-in: {target_url}")
			await page.goto(target_url, wait_until="networkidle")

			try:
				await page.wait_for_function('document.readyState === "complete"', timeout=5000)
			except Exception:
				await page.wait_for_timeout(3000)

			# 先尝试解决 Turnstile（如果存在）
			solved = await self._solve_turnstile(page)
			if not solved:
				print(f"⚠️ {self.account_name}: Turnstile solving may have failed, continue to try check-in")

			# 检查是否已经签到
			try:
				already_btn = await page.query_selector('button:has-text("今日已签到")')
			except Exception:
				already_btn = None

			if already_btn:
				print(f"ℹ️ {self.account_name}: Already checked in today on provider site")
				return

			# 查找“立即签到”按钮并点击
			checkin_btn = None
			try:
				checkin_btn = await page.query_selector('button:has-text("立即签到")')
			except Exception:
				checkin_btn = None

			if not checkin_btn:
				print(
					f"⚠️ {self.account_name}: Daily check-in button not found on profile page"
				)
				await self._take_screenshot(page, "runanytime_checkin_button_not_found")
				return

			print(f"ℹ️ {self.account_name}: Clicking daily check-in button in browser")
			await checkin_btn.click()

			# 等待状态变为“今日已签到”
			try:
				await page.wait_for_selector('button:has-text("今日已签到")', timeout=60000)
				print(f"✅ {self.account_name}: Daily check-in completed in browser")
			except Exception as wait_err:
				print(
					f"⚠️ {self.account_name}: Daily check-in may have failed or timed out: {wait_err}"
				)
				await self._take_screenshot(page, "runanytime_checkin_timeout")
		except Exception as e:
			print(f"❌ {self.account_name}: Error during browser check-in: {e}")
			await self._take_screenshot(page, "runanytime_checkin_error")

	async def _extract_balance_from_profile(self, page) -> dict | None:
		"""从 provider 的 /app/me 页面中提取当前余额和历史消耗。

		当前针对 runanytime / elysiver 等 Veloera 系站点，这些站点在
		个人中心页面的表格中以「当前余额 / 历史消耗」形式展示美元金额。
		"""
		try:
			summary = await page.evaluate(
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

			if not summary:
				print(f"⚠️ {self.account_name}: Failed to extract balance table from /app/me")
				return None

			balance_str = summary.get("当前余额")
			used_str = summary.get("历史消耗")

			if balance_str is None or used_str is None:
				try:
					snippet = json.dumps(summary, ensure_ascii=False)[:200]
				except Exception:
					snippet = str(summary)[:200]
				print(
					f"⚠️ {self.account_name}: Balance rows not found in profile page summary: {snippet}"
				)
				return None

			def _parse_amount(s: str) -> float:
				s = s.replace("￥", "").replace("$", "").replace(",", "").strip()
				try:
					return float(s)
				except Exception:
					return 0.0

			quota = _parse_amount(balance_str)
			used_quota = _parse_amount(used_str)

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
						print(f"ℹ️ {self.account_name}: Checking login status at {oauth_url}")
						response = await page.goto(oauth_url, wait_until="domcontentloaded")
						print(
							f"ℹ️ {self.account_name}: redirected to app page "
							f"{response.url if response else 'N/A'}"
						)
						await self._save_page_content_to_file(page, "sign_in_check")

						if response and response.url.startswith(self.provider_config.origin):
							is_logged_in = True
							print(
								f"✅ {self.account_name}: Already logged in via cache, "
								f"proceeding to authorization"
							)
						else:
							allow_btn = await page.query_selector('a[href^="/oauth2/approve"]')
							if allow_btn:
								is_logged_in = True
								print(
									f"✅ {self.account_name}: Already logged in via cache, "
									f"proceeding to authorization"
								)
							else:
								print(f"ℹ️ {self.account_name}: Cache session expired, need to login again")
					except Exception as e:
						print(f"⚠️ {self.account_name}: Failed to check login status: {e}")

				# 如果未登录，则执行登录流程
				if not is_logged_in:
					try:
						print(f"ℹ️ {self.account_name}: Starting to sign in linux.do")

						await page.goto("https://linux.do/login", wait_until="domcontentloaded")
						await page.fill("#login-account-name", self.username)
						await page.wait_for_timeout(2000)
						await page.fill("#login-account-password", self.password)
						await page.wait_for_timeout(2000)
						await page.click("#login-button")
						await page.wait_for_timeout(10000)

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

						# 保存新的会话状态
						await context.storage_state(path=cache_file_path)
						print(f"✅ {self.account_name}: Storage state saved to cache file")
					except Exception as e:
						print(f"❌ {self.account_name}: Error occurred while signing in linux.do: {e}")
						await self._take_screenshot(page, "signin_bypass_error")
						return False, {"error": "Linux.do sign-in error"}

					# 登录后访问授权页面
					try:
						print(f"ℹ️ {self.account_name}: Navigating to authorization page: {oauth_url}")
						await page.goto(oauth_url, wait_until="domcontentloaded")
					except Exception as e:
						print(f"❌ {self.account_name}: Failed to navigate to authorization page: {e}")
						await self._take_screenshot(page, "auth_page_navigation_failed_bypass")
						return False, {"error": "Linux.do authorization page navigation failed"}

				# 统一处理授权逻辑（无论是否通过缓存登录）
				try:
					print(f"ℹ️ {self.account_name}: Waiting for authorization button...")
					await page.wait_for_selector('a[href^="/oauth2/approve"]', timeout=30000)
					allow_btn_ele = await page.query_selector('a[href^="/oauth2/approve"]')

					if not allow_btn_ele:
						print(f"❌ {self.account_name}: Approve button not found")
						await self._take_screenshot(page, "approve_button_not_found_bypass")
						return False, {"error": "Linux.do allow button not found"}

					print(f"ℹ️ {self.account_name}: Clicking authorization button...")
					await allow_btn_ele.click()
					await page.wait_for_url(f"**{self.provider_config.origin}/oauth/**", timeout=30000)

					# 从 localStorage 获取 user 对象并提取 id
					api_user = None
					try:
						try:
							await page.wait_for_function(
								'localStorage.getItem("user") !== null', timeout=10000
							)
						except Exception:
							await page.wait_for_timeout(5000)

						user_data = await page.evaluate("() => localStorage.getItem('user')")
						if user_data:
							user_obj = json.loads(user_data)
							api_user = user_obj.get("id")
							if api_user:
								print(f"✅ {self.account_name}: Got api user: {api_user}")
							else:
								print(f"⚠️ {self.account_name}: User id not found in localStorage")
						else:
							print(f"⚠️ {self.account_name}: User data not found in localStorage")
					except Exception as e:
						print(f"⚠️ {self.account_name}: Error reading user from localStorage: {e}")

					if api_user:
						print(f"✅ {self.account_name}: OAuth authorization successful")

						# 对于启用了 Turnstile 的站点（如 runanytime），在浏览器中直接完成每日签到
						user_info = None
						if getattr(self.provider_config, "turnstile_check", False):
							await self._browser_check_in_with_turnstile(page)
							# 在同一页面上直接解析余额信息，避免额外的 HTTP 请求
							user_info = await self._extract_balance_from_profile(page)

						# 提取 session cookie，只保留与 provider domain 匹配的
						restore_cookies = await page.context.cookies()
						user_cookies = filter_cookies(restore_cookies, self.provider_config.origin)

						result: dict = {"cookies": user_cookies, "api_user": api_user}
						if user_info:
							result["user_info"] = user_info

						return True, result

					# 未能从 localStorage 获取 user，尝试从回调 URL 中解析 code
					print(f"⚠️ {self.account_name}: OAuth callback received but no user ID found")
					await self._take_screenshot(page, "oauth_failed_no_user_id_bypass")
					parsed_url = urlparse(page.url)
					query_params = parse_qs(parsed_url.query)

					code_values = query_params.get("code")
					if code_values:
						code = code_values[0]
						print(f"✅ {self.account_name}: OAuth code received: {code}")

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
								f"{final_callback_url}"
							)

							status = 0
							text = ""

							for attempt in range(2):
								response = await page.goto(final_callback_url, wait_until="domcontentloaded")

								current_url = page.url
								print(f"ℹ️ {self.account_name}: Callback page current url is {current_url}")

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
												if getattr(self.provider_config, "turnstile_check", False):
													await self._browser_check_in_with_turnstile(page)
													user_info_cb = await self._extract_balance_from_profile(page)

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

						# 浏览器回调失败，回退到返回 code/state，由上层用 httpx 调用
						return True, query_params

					print(f"❌ {self.account_name}: OAuth failed, no code in callback")
					return False, {
						"error": "Linux.do OAuth failed - no code in callback",
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
