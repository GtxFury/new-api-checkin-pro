#!/usr/bin/env python3
"""
Fovt (api.voct.top + gift.voct.top) 自动签到

签到流程：
1. 登录 api.voct.top（通过 linux.do OAuth）
2. 访问 gift.voct.top/dashboard/checkin 完成签到
3. 获取兑换码
4. 在 api.voct.top 兑换额度
"""

import asyncio
import os
from datetime import datetime
from urllib.parse import quote

from camoufox.async_api import AsyncCamoufox

from utils.browser_utils import filter_cookies

# 复用 sign_in_with_linuxdo 中的验证码解决方案
try:
    from sign_in_with_linuxdo import solve_captcha, _should_try_turnstile_solver

    CAPTCHA_SOLVER_AVAILABLE = True
    print("ℹ️ FovtCheckIn: solve_captcha imported from sign_in_with_linuxdo")
except Exception as e:
    solve_captcha = None
    _should_try_turnstile_solver = lambda: False
    CAPTCHA_SOLVER_AVAILABLE = False
    print(f"⚠️ FovtCheckIn: solve_captcha not available: {e}")


class FovtCheckIn:
    """Fovt 签到管理类"""

    # 站点配置
    API_ORIGIN = "https://api.voct.top"
    GIFT_ORIGIN = "https://gift.voct.top"
    BACKEND_ORIGIN = "https://backend.voct.top"
    LINUXDO_CLIENT_ID = "gO5j0MafWWtkDgU2OsHfMFKbekJUFsIA"

    def __init__(self, account_name: str, *, proxy_config: dict | None = None):
        self.account_name = account_name
        self.safe_account_name = "".join(c if c.isalnum() else "_" for c in account_name)
        self.proxy_config = proxy_config

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

    async def _save_page_content(self, page, reason: str) -> None:
        """保存页面 HTML 到日志文件"""
        try:
            logs_dir = "logs"
            os.makedirs(logs_dir, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_reason = "".join(c if c.isalnum() else "_" for c in reason)
            filename = f"{self.safe_account_name}_{timestamp}_fovt_{safe_reason}.html"
            filepath = os.path.join(logs_dir, filename)

            html_content = await page.content()
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html_content)

            print(f"📄 {self.account_name}: Page HTML saved to {filepath}")
        except Exception as e:
            print(f"⚠️ {self.account_name}: Failed to save HTML: {e}")

    async def _linuxdo_login_if_needed(self, page, linuxdo_username: str, linuxdo_password: str) -> None:
        """在 linux.do 登录页（若出现）自动填表提交

        复用自 checkin.py 的逻辑，兼容近期 selector 变更。
        """
        u = page.url or ""
        if "linux.do/login" not in u:
            return

        print(f"ℹ️ {self.account_name}: Detected linux.do login page, filling credentials...")

        # linux.do 登录页可能出现 Turnstile/Interstitial
        if CAPTCHA_SOLVER_AVAILABLE and solve_captcha is not None:
            try:
                await solve_captcha(page, captcha_type="cloudflare", challenge_type="interstitial")
            except Exception:
                pass
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
            linuxdo_username,
        )
        pwd_ok = await _set_value(
            [
                "#login-account-password",
                "#signin_password",
                'input[name="password"]',
                'input[type="password"]',
                'input[autocomplete="current-password"]',
            ],
            linuxdo_password,
        )

        if not user_ok or not pwd_ok:
            await self._take_screenshot(page, "linuxdo_login_inputs_not_found")
            raise RuntimeError("linux.do 登录页未找到可输入的账号/密码框")

        # 点击登录按钮
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
            try:
                await page.press("#login-account-password", "Enter")
            except Exception:
                pass

        # 等待跳出 /login
        try:
            await page.wait_for_function(
                """() => {
                    const u = location.href || '';
                    if (u.includes('/oauth2/authorize')) return true;
                    if (!u.includes('/login')) return true;
                    return false;
                }""",
                timeout=30000,
            )
        except Exception:
            await self._take_screenshot(page, "linuxdo_login_timeout")
            raise RuntimeError("linux.do 登录提交超时")

        print(f"✅ {self.account_name}: Linux.do login successful")

    async def _maybe_solve_cloudflare_interstitial(self, page) -> None:
        """尝试解决 Cloudflare Interstitial 挑战"""
        if not CAPTCHA_SOLVER_AVAILABLE or solve_captcha is None:
            return
        try:
            await solve_captcha(page, captcha_type="cloudflare", challenge_type="interstitial")
            await page.wait_for_timeout(3000)
        except Exception:
            pass

    async def _click_linuxdo_login_button(self, page) -> bool:
        """点击登录页的 "使用 LinuxDO 继续" 按钮

        完全复用 checkin.py 的 _ensure_runanytime_logged_in 逻辑
        """
        # 关键：等待页面完全渲染，确保 "使用 LinuxDO 继续" 按钮出现
        try:
            await page.wait_for_selector('button:has-text("使用 LinuxDO 继续")', timeout=10000)
            print(f"ℹ️ {self.account_name}: LinuxDO button appeared")
        except Exception:
            print(f"⚠️ {self.account_name}: Timeout waiting for LinuxDO button")

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
                    print(f"ℹ️ {self.account_name}: Found login button: {sel}")
                    break
            except Exception:
                continue

        if login_btn:
            await login_btn.click()
            print(f"ℹ️ {self.account_name}: Clicked LinuxDO login button")
        else:
            # 兜底：用 JS 精确查找第一个包含 "LinuxDO 继续" 的按钮
            print(f"ℹ️ {self.account_name}: Button not found, trying JS fallback...")
            try:
                clicked = await page.evaluate(
                    """() => {
                        // 精确查找包含 "LinuxDO" 且包含 "继续" 的按钮（排除邮箱按钮）
                        const buttons = Array.from(document.querySelectorAll('button'));
                        const btn = buttons.find(x => {
                            const t = x.innerText || '';
                            return t.includes('LinuxDO') && t.includes('继续');
                        });
                        if (btn) {
                            btn.click();
                            return true;
                        }
                        return false;
                    }"""
                )
                if clicked:
                    print(f"ℹ️ {self.account_name}: Clicked via JS (LinuxDO 继续)")
                else:
                    print(f"⚠️ {self.account_name}: JS fallback also failed")
                    return False
            except Exception as e:
                print(f"⚠️ {self.account_name}: JS click error: {e}")
                return False

        await page.wait_for_timeout(2000)
        return True

    async def _get_gift_checkin_status(self, page) -> dict:
        """获取 gift.voct.top 签到状态"""
        try:
            result = await page.evaluate(
                """async () => {
                    try {
                        const resp = await fetch('https://backend.voct.top/api/checkin/status', {
                            credentials: 'include',
                            headers: { 'Accept': 'application/json' }
                        });
                        return { status: resp.status, data: await resp.json() };
                    } catch (e) {
                        return { status: 0, error: e.message };
                    }
                }"""
            )
            return result or {}
        except Exception as e:
            print(f"⚠️ {self.account_name}: Failed to get checkin status: {e}")
            return {}

    async def _do_gift_checkin(self, page) -> tuple[bool, str]:
        """在 gift.voct.top 执行签到"""
        try:
            result = await page.evaluate(
                """async () => {
                    try {
                        const resp = await fetch('https://backend.voct.top/api/checkin', {
                            method: 'POST',
                            credentials: 'include',
                            headers: {
                                'Accept': 'application/json',
                                'Content-Type': 'application/json'
                            }
                        });
                        const data = await resp.json();
                        return { status: resp.status, data: data };
                    } catch (e) {
                        return { status: 0, error: e.message };
                    }
                }"""
            )

            if not result:
                return False, ""

            status = result.get("status", 0)
            data = result.get("data", {})

            if status == 200 and data.get("success"):
                code = data.get("data", {}).get("code", "")
                quota = data.get("data", {}).get("quota", 0)
                print(f"✅ {self.account_name}: Gift checkin successful! Quota: {quota}, Code: {code}")
                return True, code

            message = data.get("message", data.get("error", "Unknown error"))
            if "already" in str(message).lower() or "已签到" in str(message) or "已经签到" in str(message):
                print(f"ℹ️ {self.account_name}: Already checked in today on gift site")
                existing_code = data.get("data", {}).get("code", "")
                return True, existing_code

            print(f"⚠️ {self.account_name}: Gift checkin failed: {message}")
            return False, ""
        except Exception as e:
            print(f"❌ {self.account_name}: Gift checkin error: {e}")
            return False, ""

    async def _redeem_code_on_api(self, page, code: str) -> bool:
        """在 api.voct.top 兑换码"""
        if not code:
            print(f"ℹ️ {self.account_name}: No code to redeem")
            return True

        try:
            print(f"ℹ️ {self.account_name}: Navigating to topup page to redeem code")
            await page.goto(f"{self.API_ORIGIN}/console/topup", wait_until="networkidle")
            await page.wait_for_timeout(2000)

            result = await page.evaluate(
                """async (code) => {
                    try {
                        const resp = await fetch('/api/user/topup', {
                            method: 'POST',
                            credentials: 'include',
                            headers: {
                                'Accept': 'application/json',
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({ key: code })
                        });
                        return { status: resp.status, data: await resp.json() };
                    } catch (e) {
                        return { status: 0, error: e.message };
                    }
                }""",
                code,
            )

            if not result:
                return False

            status = result.get("status", 0)
            data = result.get("data", {})

            if status == 200 and (data.get("success") or data.get("code") == 0):
                print(f"✅ {self.account_name}: Code redeemed successfully!")
                return True

            message = data.get("message", data.get("msg", "Unknown error"))
            if "already" in str(message).lower() or "已使用" in str(message) or "已被使用" in str(message):
                print(f"ℹ️ {self.account_name}: Code already redeemed")
                return True

            print(f"⚠️ {self.account_name}: Code redemption failed: {message}")
            return False
        except Exception as e:
            print(f"❌ {self.account_name}: Code redemption error: {e}")
            return False

    async def _get_user_balance(self, page) -> dict:
        """获取用户余额信息"""
        try:
            result = await page.evaluate(
                """async () => {
                    try {
                        const resp = await fetch('/api/user/self', {
                            credentials: 'include',
                            headers: { 'Accept': 'application/json' }
                        });
                        return { status: resp.status, data: await resp.json() };
                    } catch (e) {
                        return { status: 0, error: e.message };
                    }
                }"""
            )

            if not result or result.get("status") != 200:
                return {}

            data = result.get("data", {})
            if not data.get("success"):
                return {}

            user_data = data.get("data", {})
            quota = user_data.get("quota", 0)
            used_quota = user_data.get("used_quota", 0)
            username = user_data.get("username", "Unknown")

            quota_per_unit = 500000
            balance = quota / quota_per_unit if quota else 0
            used = used_quota / quota_per_unit if used_quota else 0

            return {
                "username": username,
                "quota": round(balance, 2),
                "used_quota": round(used, 2),
                "raw_quota": quota,
            }
        except Exception as e:
            print(f"⚠️ {self.account_name}: Failed to get user balance: {e}")
            return {}

    async def execute(
        self,
        linuxdo_username: str,
        linuxdo_password: str,
        cache_file_path: str = "",
    ) -> tuple[bool, dict]:
        """执行 Fovt 签到"""
        print(f"\n\n⏳ 开始处理 {self.account_name}")
        print(f"ℹ️ {self.account_name}: 执行 Fovt 签到 (using proxy: {'true' if self.proxy_config else 'false'})")

        results = {
            "linuxdo_login": False,
            "gift_checkin": False,
            "code_redeem": False,
            "balance": 0.0,
        }

        try:
            async with AsyncCamoufox(
                headless=False,
                humanize=True,
                locale="zh-CN",
                disable_coop=True,
                config={"forceScopeAccess": True},
                i_know_what_im_doing=True,
                window=(1280, 720),
                proxy=self.proxy_config,
            ) as browser:
                storage_state = cache_file_path if cache_file_path and os.path.exists(cache_file_path) else None
                if storage_state:
                    print(f"ℹ️ {self.account_name}: Found cache file, restore storage state")
                else:
                    print(f"ℹ️ {self.account_name}: No cache file found, starting fresh")

                context = await browser.new_context(storage_state=storage_state)
                page = await context.new_page()

                try:
                    is_logged_in = False

                    # 步骤1: 检查是否已登录 api.voct.top
                    print(f"ℹ️ {self.account_name}: Checking login status on api.voct.top")
                    await page.goto(f"{self.API_ORIGIN}/console", wait_until="networkidle")
                    await page.wait_for_timeout(2000)

                    current_url = page.url or ""
                    if "/login" not in current_url:
                        balance_info = await self._get_user_balance(page)
                        if balance_info and balance_info.get("username"):
                            print(f"✅ {self.account_name}: Already logged in as {balance_info.get('username')}")
                            is_logged_in = True
                            results["linuxdo_login"] = True

                    # 如果未登录，执行 Linux.do OAuth 登录
                    if not is_logged_in:
                        print(f"ℹ️ {self.account_name}: Need to login via Linux.do OAuth")

                        # 获取 OAuth state
                        await page.goto(f"{self.API_ORIGIN}/login", wait_until="networkidle")
                        try:
                            state_result = await page.evaluate(
                                """async () => {
                                    try {
                                        const resp = await fetch('/api/oauth/state?provider=linuxdo');
                                        return await resp.json();
                                    } catch (e) {
                                        return { success: false, error: e.message };
                                    }
                                }"""
                            )
                            auth_state = (state_result or {}).get("data", "")
                            if not auth_state:
                                print(f"⚠️ {self.account_name}: Failed to get OAuth state")
                                await self._take_screenshot(page, "oauth_state_failed")
                                return False, {"error": "Failed to get OAuth state", **results}
                            print(f"ℹ️ {self.account_name}: Got OAuth state: {auth_state}")
                        except Exception as e:
                            print(f"⚠️ {self.account_name}: OAuth state error: {e}")
                            return False, {"error": f"OAuth state error: {e}", **results}

                        redirect_uri = f"{self.API_ORIGIN}/api/oauth/linuxdo"
                        oauth_url = (
                            "https://connect.linux.do/oauth2/authorize?"
                            f"response_type=code&client_id={self.LINUXDO_CLIENT_ID}&state={auth_state}"
                            f"&redirect_uri={quote(redirect_uri, safe='')}"
                        )

                        # ===== 步骤1: 先到 linux.do 登录页登录 =====
                        print(f"ℹ️ {self.account_name}: Starting to sign in linux.do")
                        login_resp = await page.goto("https://linux.do/login", wait_until="domcontentloaded")

                        try:
                            if login_resp and getattr(login_resp, "status", None) == 429:
                                raise RuntimeError("linux.do 返回 429（IP 被临时限流/封禁）")
                        except Exception:
                            raise

                        # 尝试解决 Cloudflare
                        await self._maybe_solve_cloudflare_interstitial(page)
                        if CAPTCHA_SOLVER_AVAILABLE and _should_try_turnstile_solver():
                            try:
                                await solve_captcha(page, captcha_type="cloudflare", challenge_type="turnstile")
                            except Exception:
                                pass

                        # 填写账号密码
                        await self._linuxdo_login_if_needed(page, linuxdo_username, linuxdo_password)

                        # 等待跳出 /login
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
                            print(f"ℹ️ {self.account_name}: Left login page, current URL: {page.url}")
                        except Exception:
                            await self._take_screenshot(page, "linuxdo_login_timeout")
                            return False, {"error": "linux.do login submit timeout", **results}

                        # 保存 linux.do session
                        try:
                            if cache_file_path and "/login" not in page.url:
                                cache_dir = os.path.dirname(cache_file_path)
                                if cache_dir:
                                    os.makedirs(cache_dir, exist_ok=True)
                                await context.storage_state(path=cache_file_path)
                                print(f"✅ {self.account_name}: Linux.do session saved")
                        except Exception:
                            pass

                        # ===== 步骤2: 登录后重新导航到 OAuth URL =====
                        print(f"ℹ️ {self.account_name}: Navigating to authorization page: {oauth_url}")
                        await page.goto(oauth_url, wait_until="domcontentloaded")

                        # ===== 步骤3: 等待授权按钮出现 =====
                        print(f"ℹ️ {self.account_name}: Waiting for authorization button...")
                        try:
                            await page.wait_for_selector('a[href^="/oauth2/approve"]', timeout=30000)
                        except Exception:
                            await self._take_screenshot(page, "approve_button_not_found")
                            await self._save_page_content(page, "approve_button_not_found")
                            print(f"⚠️ {self.account_name}: Approve button not found, current URL: {page.url}")
                            return False, {"error": "Approve button not found", **results}

                        allow_btn_ele = await page.query_selector('a[href^="/oauth2/approve"]')
                        if not allow_btn_ele:
                            await self._take_screenshot(page, "approve_button_query_failed")
                            return False, {"error": "Approve button query failed", **results}

                        # ===== 步骤4: 点击授权按钮 =====
                        print(f"ℹ️ {self.account_name}: Clicking authorization button...")

                        # 设置 URL 监听捕获 OAuth 回调
                        oauth_redirect_url = None
                        observed_oauth_urls = []

                        def _record_provider_url(u: str) -> None:
                            try:
                                if u and u.startswith(self.API_ORIGIN) and "code=" in u:
                                    if u not in observed_oauth_urls:
                                        observed_oauth_urls.append(u)
                            except Exception:
                                pass

                        try:
                            page.on("framenavigated", lambda frame: _record_provider_url(frame.url))
                            page.on("request", lambda req: _record_provider_url(req.url))
                        except Exception:
                            pass

                        try:
                            await allow_btn_ele.click(no_wait_after=True, timeout=30000)
                        except Exception:
                            try:
                                await page.evaluate("(el) => el && el.click && el.click()", allow_btn_ele)
                            except Exception:
                                pass

                        # ===== 步骤5: 等待重定向到 provider =====
                        try:
                            await page.wait_for_url(f"**{self.API_ORIGIN}/**", timeout=30000)
                            oauth_redirect_url = observed_oauth_urls[0] if observed_oauth_urls else page.url
                            print(f"ℹ️ {self.account_name}: Redirected to: {oauth_redirect_url}")
                        except Exception:
                            await self._take_screenshot(page, "oauth_redirect_timeout")
                            print(f"⚠️ {self.account_name}: OAuth redirect timeout, current URL: {page.url}")

                        # 从 URL 中提取 code 参数
                        from urllib.parse import urlparse, parse_qs
                        source_url = oauth_redirect_url or page.url
                        parsed_url = urlparse(source_url)
                        query_params = parse_qs(parsed_url.query)
                        code_values = query_params.get("code")
                        code = code_values[0] if code_values else None

                        if code:
                            print(f"ℹ️ {self.account_name}: Got OAuth code: {code[:20]}...")

                        # ===== 步骤6: 等待 session 建立 =====
                        # 等待 localStorage 中出现 user 数据
                        await page.wait_for_timeout(3000)
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
                            print(f"✅ {self.account_name}: localStorage user detected")
                        except Exception:
                            print(f"⚠️ {self.account_name}: localStorage timeout, current URL: {page.url}")
                            # 尝试导航到 /console 触发 SPA 初始化
                            try:
                                await page.goto(f"{self.API_ORIGIN}/console", wait_until="networkidle")
                                await page.wait_for_timeout(3000)
                            except Exception:
                                pass

                        # 验证登录成功
                        current_url = page.url or ""
                        print(f"ℹ️ {self.account_name}: Current URL after OAuth: {current_url}")

                        if "/login" in current_url:
                            await self._take_screenshot(page, "oauth_redirect_to_login")
                            await self._save_page_content(page, "oauth_redirect_to_login")
                            print(f"⚠️ {self.account_name}: Redirected to login page")

                        # 确保在 console 页面
                        if "/console" not in current_url and "/login" not in current_url:
                            await page.goto(f"{self.API_ORIGIN}/console", wait_until="networkidle")
                            await page.wait_for_timeout(2000)
                            current_url = page.url or ""

                        if "/login" in current_url:
                            await self._take_screenshot(page, "login_verification_failed")
                            await self._save_page_content(page, "login_verification_failed")
                            return False, {"error": "Login verification failed - redirected to login", **results}

                        balance_info = await self._get_user_balance(page)
                        if balance_info and balance_info.get("username"):
                            print(f"✅ {self.account_name}: Login successful as {balance_info.get('username')}")
                            is_logged_in = True
                            results["linuxdo_login"] = True

                            # 保存 session
                            try:
                                if cache_file_path:
                                    cache_dir = os.path.dirname(cache_file_path)
                                    if cache_dir:
                                        os.makedirs(cache_dir, exist_ok=True)
                                    await context.storage_state(path=cache_file_path)
                                    print(f"✅ {self.account_name}: Session saved to cache")
                            except Exception as e:
                                print(f"⚠️ {self.account_name}: Failed to save session: {e}")
                        else:
                            await self._take_screenshot(page, "login_verification_failed")
                            await self._save_page_content(page, "login_verification_failed")
                            return False, {"error": "Login verification failed", **results}

                    # 步骤2: 访问 gift.voct.top 进行签到
                    print(f"ℹ️ {self.account_name}: Navigating to gift site for checkin")
                    await page.goto(f"{self.GIFT_ORIGIN}/dashboard/checkin", wait_until="networkidle")
                    await page.wait_for_timeout(2000)

                    # 检查签到状态
                    checkin_status = await self._get_gift_checkin_status(page)
                    print(f"ℹ️ {self.account_name}: Checkin status: {checkin_status}")

                    # 执行签到
                    checkin_ok, code = await self._do_gift_checkin(page)
                    results["gift_checkin"] = checkin_ok

                    # 步骤3: 如果获得了兑换码，去 api.voct.top 兑换
                    if code:
                        print(f"ℹ️ {self.account_name}: Got redemption code: {code}")
                        redeem_ok = await self._redeem_code_on_api(page, code)
                        results["code_redeem"] = redeem_ok
                    else:
                        print(f"ℹ️ {self.account_name}: No new code to redeem")
                        results["code_redeem"] = True

                    # 步骤4: 获取最终余额
                    await page.goto(f"{self.API_ORIGIN}/console", wait_until="networkidle")
                    await page.wait_for_timeout(1000)
                    final_balance = await self._get_user_balance(page)
                    if final_balance:
                        results["balance"] = final_balance.get("quota", 0)
                        results["used_quota"] = final_balance.get("used_quota", 0)
                        results["username"] = final_balance.get("username", "Unknown")
                        print(
                            f"✅ {self.account_name}: Final balance: ${results['balance']}, "
                            f"Used: ${results.get('used_quota', 0)}"
                        )

                    overall_success = results["linuxdo_login"] and results["gift_checkin"]
                    return overall_success, results

                except Exception as e:
                    print(f"❌ {self.account_name}: Error during execution: {e}")
                    await self._take_screenshot(page, "execution_error")
                    return False, {"error": str(e), **results}
                finally:
                    await page.close()
                    await context.close()

        except Exception as e:
            print(f"❌ {self.account_name}: Browser error: {e}")
            return False, {"error": str(e), **results}
