#!/usr/bin/env python3
"""
使用账号密码直接登录 New API 站点，并在浏览器中完成签到。

适用于不支持 OAuth（linux.do/GitHub）的站点，如 api.gemai.cc。
"""

import asyncio
import json
import os
import re
from datetime import datetime
from urllib.parse import urlparse

from camoufox.async_api import AsyncCamoufox
from playwright_captcha import CaptchaType, ClickSolver, FrameworkType

from utils.browser_utils import filter_cookies
from utils.config import ProviderConfig


class CredentialsSignIn:
    """使用账号密码完成登录，并在浏览器中执行签到。"""

    # 签到页面候选路径
    CHECKIN_PATH_CANDIDATES = (
        "/console/personal",
        "/console",
        "/app/me",
        "/app/profile",
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

    async def _detect_turnstile(self, page) -> bool:
        """检测页面是否存在 Turnstile 验证码"""
        try:
            # 检测 Turnstile iframe 或容器
            turnstile_selectors = [
                'iframe[src*="challenges.cloudflare.com"]',
                'iframe[src*="turnstile"]',
                '[class*="cf-turnstile"]',
                '#cf-turnstile',
                'div[data-sitekey]',
            ]
            for selector in turnstile_selectors:
                element = await page.query_selector(selector)
                if element:
                    print(f"ℹ️ {self.account_name}: Detected Turnstile captcha ({selector})")
                    return True
            return False
        except Exception as e:
            print(f"⚠️ {self.account_name}: Error detecting Turnstile: {e}")
            return False

    async def _solve_turnstile(self, page) -> bool:
        """使用 playwright-captcha 解决 Turnstile 验证码"""
        try:
            print(f"ℹ️ {self.account_name}: Attempting to solve Turnstile captcha...")

            # 使用 ClickSolver 配合 Camoufox 框架
            async with ClickSolver(
                framework=FrameworkType.CAMOUFOX,
                page=page,
                max_attempts=5,
                attempt_delay=3,
            ) as solver:
                await solver.solve_captcha(
                    captcha_container=page,
                    captcha_type=CaptchaType.CLOUDFLARE_TURNSTILE,
                )

            print(f"✅ {self.account_name}: Turnstile captcha solved successfully")
            return True
        except Exception as e:
            print(f"❌ {self.account_name}: Failed to solve Turnstile captcha: {e}")
            await self._take_screenshot(page, "turnstile_solve_failed")
            return False

    async def _extract_api_user_from_localstorage(self, page) -> str | None:
        """从 localStorage 中读取 user id"""
        for storage_key in ("user", "user_info", "userInfo"):
            try:
                user_data = await page.evaluate(f"() => localStorage.getItem('{storage_key}')")
                if not user_data:
                    continue
                parsed = json.loads(user_data)
                if isinstance(parsed, dict):
                    user_id = parsed.get("id") or parsed.get("user_id") or parsed.get("userId")
                    if user_id:
                        return str(user_id)
            except Exception:
                continue
        return None

    async def _do_login(self, page) -> bool:
        """执行登录流程"""
        login_url = self.provider_config.get_login_url()
        print(f"ℹ️ {self.account_name}: Navigating to login page: {login_url}")

        try:
            await page.goto(login_url, wait_until="networkidle")
        except Exception as e:
            print(f"⚠️ {self.account_name}: Failed to navigate to login page: {e}")
            return False

        # 等待页面加载完成
        try:
            await page.wait_for_function('document.readyState === "complete"', timeout=10000)
        except Exception:
            await page.wait_for_timeout(3000)

        # 检查是否已经登录（可能有缓存的 session）
        current_url = page.url or ""
        if "/console" in current_url and "/login" not in current_url:
            print(f"ℹ️ {self.account_name}: Already logged in (redirected to console)")
            return True

        # 填写用户名
        try:
            # 尝试多种选择器
            username_selectors = [
                'input[placeholder*="用户名"]',
                'input[placeholder*="邮箱"]',
                'input[type="text"]',
                'input[type="email"]',
            ]
            username_input = None
            for selector in username_selectors:
                try:
                    username_input = await page.wait_for_selector(selector, timeout=5000)
                    if username_input:
                        break
                except Exception:
                    continue

            if not username_input:
                print(f"❌ {self.account_name}: Username input not found")
                await self._take_screenshot(page, "login_username_not_found")
                return False

            await username_input.fill(self.username)
            print(f"ℹ️ {self.account_name}: Filled username")
        except Exception as e:
            print(f"❌ {self.account_name}: Failed to fill username: {e}")
            await self._take_screenshot(page, "login_username_error")
            return False

        # 填写密码
        try:
            password_selectors = [
                'input[placeholder*="密码"]',
                'input[type="password"]',
            ]
            password_input = None
            for selector in password_selectors:
                try:
                    password_input = await page.wait_for_selector(selector, timeout=5000)
                    if password_input:
                        break
                except Exception:
                    continue

            if not password_input:
                print(f"❌ {self.account_name}: Password input not found")
                await self._take_screenshot(page, "login_password_not_found")
                return False

            await password_input.fill(self.password)
            print(f"ℹ️ {self.account_name}: Filled password")
        except Exception as e:
            print(f"❌ {self.account_name}: Failed to fill password: {e}")
            await self._take_screenshot(page, "login_password_error")
            return False

        # 勾选用户协议（如果存在）
        try:
            agreement_selectors = [
                'text=我已阅读并同意',
                'input[type="checkbox"]',
                '.semi-checkbox',
            ]
            for selector in agreement_selectors:
                try:
                    checkbox = await page.query_selector(selector)
                    if checkbox:
                        # 检查是否已经勾选
                        is_checked = await page.evaluate(
                            """(el) => {
                                if (el.type === 'checkbox') return el.checked;
                                const cb = el.querySelector('input[type="checkbox"]');
                                return cb ? cb.checked : false;
                            }""",
                            checkbox,
                        )
                        if not is_checked:
                            await checkbox.click()
                            print(f"ℹ️ {self.account_name}: Checked user agreement")
                        break
                except Exception:
                    continue
        except Exception as e:
            print(f"⚠️ {self.account_name}: Failed to check agreement (may not exist): {e}")

        # 检测并解决 Turnstile 验证码（如果存在）
        if await self._detect_turnstile(page):
            turnstile_solved = await self._solve_turnstile(page)
            if not turnstile_solved:
                print(f"⚠️ {self.account_name}: Turnstile captcha not solved, attempting to continue...")
            # 等待验证码处理完成后页面稳定
            await page.wait_for_timeout(1000)

        # 等待一下让按钮变为可点击状态
        await page.wait_for_timeout(500)

        # 点击登录按钮
        try:
            login_btn_selectors = [
                'button:has-text("继续")',
                'button:has-text("登录")',
                'button:has-text("登 录")',
                'button[type="submit"]',
            ]
            login_btn = None
            for selector in login_btn_selectors:
                try:
                    login_btn = await page.query_selector(selector)
                    if login_btn:
                        # 检查按钮是否可点击
                        is_disabled = await login_btn.is_disabled()
                        if not is_disabled:
                            break
                        login_btn = None
                except Exception:
                    continue

            if not login_btn:
                print(f"❌ {self.account_name}: Login button not found or disabled")
                await self._take_screenshot(page, "login_button_not_found")
                return False

            print(f"ℹ️ {self.account_name}: Clicking login button")
            await login_btn.click()
        except Exception as e:
            print(f"❌ {self.account_name}: Failed to click login button: {e}")
            await self._take_screenshot(page, "login_button_error")
            return False

        # 等待登录完成（跳转到控制台或其他页面）
        try:
            # 等待 URL 变化或出现登录成功的标志
            await page.wait_for_function(
                """() => {
                    const url = window.location.href;
                    // 登录成功后通常会跳转到 /console 或其他页面
                    if (url.includes('/console') && !url.includes('/login')) return true;
                    // 或者 localStorage 中有 user 信息
                    if (localStorage.getItem('user')) return true;
                    return false;
                }""",
                timeout=30000,
            )
            print(f"✅ {self.account_name}: Login successful")
            return True
        except Exception as e:
            # 检查是否有错误提示
            try:
                error_text = await page.evaluate(
                    """() => {
                        const alerts = document.querySelectorAll('[class*="error"], [class*="alert"], [role="alert"]');
                        for (const el of alerts) {
                            const text = el.innerText || el.textContent;
                            if (text && text.trim()) return text.trim();
                        }
                        return null;
                    }"""
                )
                if error_text:
                    print(f"❌ {self.account_name}: Login failed with error: {error_text}")
            except Exception:
                pass

            print(f"❌ {self.account_name}: Login timeout or failed: {e}")
            await self._take_screenshot(page, "login_timeout")
            return False

    async def _do_checkin(self, page) -> bool:
        """执行签到流程"""
        # 确定签到页面路径
        if getattr(self.provider_config, "checkin_page_path", None):
            checkin_paths = [self.provider_config.checkin_page_path]
        else:
            checkin_paths = list(self.CHECKIN_PATH_CANDIDATES)

        for path in checkin_paths:
            target_url = f"{self.provider_config.origin}{path}"
            print(f"ℹ️ {self.account_name}: Navigating to check-in page: {target_url}")

            try:
                await page.goto(target_url, wait_until="networkidle")
            except Exception as e:
                print(f"⚠️ {self.account_name}: Failed to navigate to {path}: {e}")
                continue

            # 等待页面加载
            try:
                await page.wait_for_function('document.readyState === "complete"', timeout=10000)
            except Exception:
                await page.wait_for_timeout(3000)

            # 检查是否被重定向到登录页
            current_url = page.url or ""
            if "/login" in current_url:
                print(f"⚠️ {self.account_name}: Redirected to login page, session may have expired")
                await self._take_screenshot(page, "checkin_session_expired")
                return False

            # 等待页面内容加载
            await page.wait_for_timeout(2000)

            # 检查是否已经签到
            try:
                already_btn = await page.query_selector('button:has-text("今日已签到")')
                if already_btn:
                    print(f"ℹ️ {self.account_name}: Already checked in today")
                    return True
            except Exception:
                pass

            # 查找"立即签到"按钮并点击
            try:
                checkin_btn = await page.wait_for_selector('button:has-text("立即签到")', timeout=10000)
                if checkin_btn:
                    print(f"ℹ️ {self.account_name}: Clicking check-in button")
                    await checkin_btn.click()

                    # 等待签到完成
                    try:
                        await page.wait_for_selector('button:has-text("今日已签到")', timeout=30000)
                        print(f"✅ {self.account_name}: Check-in completed successfully")
                        return True
                    except Exception as wait_err:
                        print(f"⚠️ {self.account_name}: Check-in may have failed: {wait_err}")
                        await self._take_screenshot(page, "checkin_timeout")
                        return False
            except Exception:
                continue

        print(f"⚠️ {self.account_name}: Check-in button not found on any known page")
        await self._take_screenshot(page, "checkin_button_not_found")
        return False

    async def _get_balance(self, page) -> dict | None:
        """从页面获取余额信息"""
        origin = self.provider_config.origin

        def _parse_amount(text: str) -> float | None:
            if not text:
                return None
            t = text.replace("￥", "").replace("$", "").replace("¥", "").replace(",", "").strip()
            t = re.sub(r"[^0-9.\-]", "", t)
            try:
                return float(t)
            except Exception:
                return None

        # 尝试从 /console 或 /console/personal 页面获取余额
        for path in ("/console/personal", "/console"):
            try:
                current_url = page.url or ""
                if path not in current_url:
                    await page.goto(f"{origin}{path}", wait_until="networkidle")
                    await page.wait_for_timeout(2000)
            except Exception:
                continue

            # 等待余额数据加载（避免 NaN）
            try:
                await page.wait_for_function(
                    """() => {
                        const t = document.body ? (document.body.innerText || '') : '';
                        if (t.includes('NaN')) return false;
                        if (t.includes('当前余额') && /¥[\\d.]+/.test(t)) return true;
                        return false;
                    }""",
                    timeout=10000,
                )
            except Exception:
                pass

            # 从页面提取余额信息
            try:
                extracted = await page.evaluate(
                    """() => {
                        const bodyText = document.body ? (document.body.innerText || '') : '';

                        function pickByLabel(label) {
                            const nodes = Array.from(document.querySelectorAll('*'));
                            const exact = nodes.find(n => ((n.innerText || '').trim() === label));
                            if (exact && exact.parentElement) {
                                const t = (exact.parentElement.innerText || '').trim();
                                if (t.includes('¥') || t.includes('$') || t.includes('￥')) return t;
                            }
                          const candidates = nodes
                                .map(n => (n.innerText || '').trim())
                                .filter(t => t && t.includes(label) && (t.includes('¥') || t.includes('$') || t.includes('￥')))
                                .sort((a, b) => a.length - b.length);
                            return candidates[0] || null;
                        }

                        return {
                            balanceBlock: pickByLabel('当前余额'),
                            usedBlock: pickByLabel('历史消耗'),
                        };
                    }"""
                )

                if not extracted:
                    continue

                balance_block = extracted.get("balanceBlock") or ""
                used_block = extracted.get("usedBlock") or ""

                quota = None
                used_quota = None

                # 解析当前余额
                if balance_block:
                    match = re.search(r"[¥￥$]\s*([\d.]+)", balance_block)
                    if match:
                        quota = _parse_amount(match.group(1))

                # 解析历史消耗
                if used_block:
                    match = re.search(r"[¥￥$]\s*([\d.]+)", used_block)
                    if match:
                        used_quota = _parse_amount(match.group(1))

                if quota is not None:
                    return {
                        "quota": round(quota, 2),
                        "used_quota": round(used_quota, 2) if used_quota is not None else 0,
                    }

            except Exception as e:
                print(f"⚠️ {self.account_name}: Failed to extract balance: {e}")
                continue

        return None

    async def sign_in_and_check_in(
        self,
        proxy_config: dict | None = None,
    ) -> tuple[bool, dict]:
        """执行完整的登录和签到流程

        Args:
            proxy_config: 代理配置

        Returns:
            (success, result_dict)
            - success: 是否成功
            - result_dict: 包含 cookies, api_user 等信息，或 error 信息
        """
        print(f"ℹ️ {self.account_name}: Starting credentials sign-in for {self.provider_config.name}")

        try:
            async with AsyncCamoufox(
                headless=True,
                proxy=proxy_config,
                locale="zh-CN",
            ) as browser:
                page = await browser.new_page()

                # 执行登录
                login_success = await self._do_login(page)
                if not login_success:
                    return False, {"error": "Login failed"}

                # 提取 api_user
                api_user = await self._extract_api_user_from_localstorage(page)
                if api_user:
                    print(f"ℹ️ {self.account_name}: Extracted api_user from localStorage: {api_user}")

                # 执行签到
                checkin_success = await self._do_checkin(page)

                # 获取余额
                balance_info = await self._get_balance(page)
                quota = balance_info.get("quota", 0) if balance_info else 0
                used_quota = balance_info.get("used_quota", 0) if balance_info else 0

                if balance_info:
                    print(f"ℹ️ {self.account_name}: Balance: ¥{quota}, Used: ¥{used_quota}")

                # 获取 cookies
                cookies = await page.context.cookies()
                origin = self.provider_config.origin
                user_cookies = filter_cookies(cookies, origin)

                if checkin_success:
                    return True, {
                        "success": True,
                        "cookies": user_cookies,
                        "api_user": api_user,
                        "checkin": True,
                        "quota": quota,
                        "used_quota": used_quota,
                        "display": f"¥{quota:.2f} | Used ¥{used_quota:.2f}",
                    }
                else:
                    # 登录成功但签到失败
                    return True, {
                        "success": True,
                        "cookies": user_cookies,
                        "api_user": api_user,
                        "checkin": False,
                        "quota": quota,
                        "used_quota": used_quota,
                        "display": f"¥{quota:.2f} | Used ¥{used_quota:.2f}",
                        "warning": "Login successful but check-in failed",
                    }

        except Exception as e:
            print(f"❌ {self.account_name}: Credentials sign-in error: {e}")
            return False, {"error": str(e)}
