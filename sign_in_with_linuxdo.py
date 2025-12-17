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
from urllib.parse import parse_qs, urlparse

from camoufox.async_api import AsyncCamoufox

from utils.browser_utils import filter_cookies
from utils.config import ProviderConfig

# 可选依赖：camoufox-captcha，用于更智能地处理 Cloudflare Turnstile
solve_captcha = None
try:  # 优先尝试作为已安装包导入
	from camoufox_captcha import solve_captcha  # type: ignore[assignment]
	print("ℹ️ LinuxDoSignIn: camoufox_captcha imported as installed package")
except Exception as e1:
	print(f"⚠️ LinuxDoSignIn: import camoufox_captcha failed (installed): {e1!r}")

	# 在 CI / GitHub Actions 中，camoufox-captcha 通常作为当前仓库的“兄弟目录”存在
	candidates: list[Path] = []
	try:
		current = Path(__file__).resolve()
		parents = [current.parent, current.parent.parent, current.parent.parent.parent]
		for base in parents:
			if base:
				candidates.append(base / "camoufox-captcha")
	except Exception:
		pass

	for extra_path in candidates:
		try:
			print(f"ℹ️ LinuxDoSignIn: trying to import camoufox_captcha from {extra_path}")
			if extra_path and extra_path.exists():
				sys.path.insert(0, str(extra_path))
				from camoufox_captcha import solve_captcha  # type: ignore[assignment]
				print(
					"ℹ️ LinuxDoSignIn: camoufox_captcha imported from local directory "
					f"{extra_path}"
				)
				break
		except Exception as e2:  # pragma: no cover - 仅用于调试 CI 环境
			print(f"⚠️ LinuxDoSignIn: import camoufox_captcha failed from {extra_path}: {e2!r}")
	else:
		print("⚠️ LinuxDoSignIn: camoufox_captcha not available, Turnstile will be solved manually")
		solve_captcha = None


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

		优先使用 camoufox-captcha，如果不可用则回退到简单的坐标点击方案。
		"""

		# 1. 如果 camoufox-captcha 可用，优先使用
		if solve_captcha is not None:
			try:
				print(f"ℹ️ {self.account_name}: Solving Cloudflare Turnstile via camoufox-captcha")
				solved = await solve_captcha(
					page,
					captcha_type="cloudflare",
					challenge_type="turnstile",
				)
				print(f"ℹ️ {self.account_name}: Turnstile solve result from camoufox-captcha: {solved}")
				if solved:
					return True
			except Exception as sc_err:
				print(f"⚠️ {self.account_name}: camoufox-captcha solve_captcha error: {sc_err}")

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
			# 允许访问 scope / shadow-root，用于 camoufox-captcha 检测 iframe
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
				oauth_url = (
					"https://connect.linux.do/oauth2/authorize?"
					f"response_type=code&client_id={client_id}&state={auth_state}"
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
						if getattr(self.provider_config, "turnstile_check", False):
							await self._browser_check_in_with_turnstile(page)

						# 提取 session cookie，只保留与 provider domain 匹配的
						restore_cookies = await page.context.cookies()
						user_cookies = filter_cookies(restore_cookies, self.provider_config.origin)

						return True, {"cookies": user_cookies, "api_user": api_user}

					# 未能从 localStorage 获取 user，尝试从回调 URL 中解析 code
					print(f"⚠️ {self.account_name}: OAuth callback received but no user ID found")
					await self._take_screenshot(page, "oauth_failed_no_user_id_bypass")
					parsed_url = urlparse(page.url)
					query_params = parse_qs(parsed_url.query)

					if "code" in query_params:
						print(f"✅ {self.account_name}: OAuth code received: {query_params.get('code')}")
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
