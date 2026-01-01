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
import json
import os
import random
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from camoufox.async_api import AsyncCamoufox

from utils.browser_utils import filter_cookies

# 首选依赖：playwright-captcha，用于更智能地处理 Cloudflare Turnstile / Interstitial
try:
    from playwright_captcha import ClickSolver, CaptchaType, FrameworkType  # type: ignore[assignment]

    PLAYWRIGHT_CAPTCHA_AVAILABLE = True
    print("ℹ️ FovtCheckIn: playwright-captcha imported successfully")
except Exception as e1:  # pragma: no cover - 可选依赖
    ClickSolver = None  # type: ignore[assignment]
    CaptchaType = None  # type: ignore[assignment]
    FrameworkType = None  # type: ignore[assignment]
    PLAYWRIGHT_CAPTCHA_AVAILABLE = False
    print(f"⚠️ FovtCheckIn: playwright-captcha not available: {e1!r}")


def _should_try_turnstile_solver() -> bool:
    """判断是否尝试 Turnstile solver"""
    raw = str(os.getenv("LINUXDO_TRY_TURNSTILE_SOLVER", "") or "").strip().lower()
    if raw in {"0", "false", "no", "off"}:
        return False
    if raw in {"1", "true", "yes", "on"}:
        return True
    return True


async def solve_captcha(page, captcha_type: str = "cloudflare", challenge_type: str = "turnstile") -> bool:
    """统一的验证码解决入口"""
    if not PLAYWRIGHT_CAPTCHA_AVAILABLE or ClickSolver is None or FrameworkType is None or CaptchaType is None:
        return False

    if captcha_type == "cloudflare" and challenge_type == "turnstile" and not _should_try_turnstile_solver():
        return False

    try:
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

        if bool(has_cf_evidence.get("titleLooks")) and not bool(has_cf_evidence.get("hasIframe")):
            try:
                await page.wait_for_selector('iframe[src*="challenges.cloudflare.com"]', timeout=6000)
                has_cf_evidence["hasIframe"] = True
            except Exception:
                pass

        is_turnstile_evidence = bool(has_cf_evidence.get("hasIframe") or has_cf_evidence.get("hasTurnstileInput"))
        is_interstitial_evidence = bool(has_cf_evidence.get("hasChlForm"))

        should_try = False
        if captcha_type == "cloudflare" and challenge_type == "turnstile":
            should_try = is_turnstile_evidence
        elif captcha_type == "cloudflare" and challenge_type == "interstitial":
            should_try = is_interstitial_evidence or bool(has_cf_evidence.get("titleLooks"))

        if not should_try:
            return False
    except Exception:
        pass

    try:
        framework = FrameworkType.CAMOUFOX

        if captcha_type == "cloudflare" and challenge_type == "turnstile":
            target_type = CaptchaType.CLOUDFLARE_TURNSTILE
        elif captcha_type == "cloudflare" and challenge_type == "interstitial":
            target_type = CaptchaType.CLOUDFLARE_INTERSTITIAL
        else:
            return False

        async def _run_solver() -> bool:
            async with ClickSolver(framework=framework, page=page) as solver:
                await solver.solve_captcha(captcha_container=page, captcha_type=target_type)
                return True

        try:
            return await asyncio.wait_for(_run_solver(), timeout=30.0)
        except asyncio.TimeoutError:
            print(f"⚠️ FovtCheckIn: playwright-captcha solver timed out after 30s")
            return False
    except Exception as e:
        print(f"⚠️ FovtCheckIn: playwright-captcha solve_captcha error: {e}")
        return False


class FovtCheckIn:
    """Fovt 签到管理类"""

    # 站点配置
    API_ORIGIN = "https://api.voct.top"
    GIFT_ORIGIN = "https://gift.voct.top"
    BACKEND_ORIGIN = "https://backend.voct.top"
    LINUXDO_CLIENT_ID = "8w2uZtoWH9AUXrZr1qeCEEmvXLafea3c"  # 需要从站点获取真实值
    LINUXDO_AUTH_PATH = "/api/oauth/linuxdo"

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

    async def _linuxdo_login(self, page, username: str, password: str) -> bool:
        """执行 Linux.do 登录"""
        try:
            print(f"ℹ️ {self.account_name}: Starting Linux.do login")

            login_resp = await page.goto("https://linux.do/login", wait_until="domcontentloaded")

            if login_resp and getattr(login_resp, "status", None) == 429:
                raise RuntimeError("linux.do 返回 429（IP 被临时限流/封禁），请稍后重试或更换出口 IP")

            # 尝试处理 Cloudflare 挑战
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
                username,
            )
            pwd_ok = await _set_value(
                [
                    "#login-account-password",
                    "#signin_password",
                    'input[name="password"]',
                    'input[type="password"]',
                    'input[autocomplete="current-password"]',
                ],
                password,
            )

            if not user_ok or not pwd_ok:
                await self._take_screenshot(page, "linuxdo_login_inputs_not_found")
                raise RuntimeError("linux.do login inputs not found or not editable")

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

            # 等待登录完成
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
                raise RuntimeError("linux.do login submit timeout")

            print(f"✅ {self.account_name}: Linux.do login successful")
            return True
        except Exception as e:
            print(f"❌ {self.account_name}: Linux.do login failed: {e}")
            return False

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
                # 尝试获取今日的兑换码
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
            # 先导航到 api.voct.top/console/topup
            print(f"ℹ️ {self.account_name}: Navigating to topup page to redeem code")
            await page.goto(f"{self.API_ORIGIN}/console/topup", wait_until="networkidle")
            await page.wait_for_timeout(2000)

            # 调用兑换接口
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

            # quota 通常是整数，需要转换为美元
            quota_per_unit = 500000  # 默认值，可能需要调整
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
                # 加载缓存
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
                        # 验证 session
                        balance_info = await self._get_user_balance(page)
                        if balance_info and balance_info.get("username"):
                            print(f"✅ {self.account_name}: Already logged in as {balance_info.get('username')}")
                            is_logged_in = True
                            results["linuxdo_login"] = True

                    # 如果未登录，执行 Linux.do OAuth 登录
                    if not is_logged_in:
                        print(f"ℹ️ {self.account_name}: Need to login via Linux.do OAuth")

                        # 先到 api.voct.top 的登录页
                        await page.goto(f"{self.API_ORIGIN}/login", wait_until="networkidle")
                        await page.wait_for_timeout(2000)

                        # 查找 Linux.do 登录按钮（参考 checkin.py 的选择器）
                        linuxdo_btn = None
                        for selector in [
                            'button:has-text("使用 LinuxDO 继续")',
                            'button:has-text("使用 LinuxDO")',
                            'button:has-text("使用 Linux Do 登录")',
                            'button:has-text("Linux Do")',
                            'button:has-text("LinuxDO")',
                            'button:has-text("linux.do")',
                            'a:has-text("Linux Do")',
                            'a:has-text("使用 Linux Do 登录")',
                            'a[href*="linuxdo" i]',
                        ]:
                            try:
                                ele = await page.query_selector(selector)
                                if ele:
                                    linuxdo_btn = ele
                                    print(f"ℹ️ {self.account_name}: Found login button with selector: {selector}")
                                    break
                            except Exception:
                                continue

                        if linuxdo_btn:
                            print(f"ℹ️ {self.account_name}: Clicking Linux.do login button...")
                            await linuxdo_btn.click()
                            await page.wait_for_timeout(2000)
                        else:
                            # 兜底：从所有链接/按钮里找包含 linuxdo 的
                            print(f"ℹ️ {self.account_name}: Button not found by selector, trying JS click...")
                            try:
                                clicked = await page.evaluate(
                                    """() => {
                                        const elements = [...document.querySelectorAll('button, a')];
                                        const btn = elements.find(el => {
                                            const text = (el.innerText || '').toLowerCase();
                                            const href = (el.getAttribute('href') || '').toLowerCase();
                                            return text.includes('linuxdo') || text.includes('linux do') ||
                                                   text.includes('linux.do') || href.includes('linuxdo');
                                        });
                                        if (btn) {
                                            btn.click();
                                            return true;
                                        }
                                        return false;
                                    }"""
                                )
                                if clicked:
                                    print(f"ℹ️ {self.account_name}: Clicked via JS evaluation")
                                    await page.wait_for_timeout(2000)
                                else:
                                    await self._take_screenshot(page, "linuxdo_button_not_found")
                                    return False, {"error": "Linux.do login button not found", **results}
                            except Exception as e:
                                await self._take_screenshot(page, "linuxdo_button_click_error")
                                return False, {"error": f"Failed to click login button: {e}", **results}

                        # 检查是否跳转到 linux.do
                        current_url = page.url or ""
                        if "linux.do" in current_url:
                            # 执行 Linux.do 登录
                            if "/login" in current_url or "/oauth2" in current_url:
                                # 检查是否需要登录
                                allow_btn = await page.query_selector('a[href^="/oauth2/approve"]')
                                if not allow_btn:
                                    # 需要登录
                                    login_ok = await self._linuxdo_login(page, linuxdo_username, linuxdo_password)
                                    if not login_ok:
                                        return False, {"error": "Linux.do login failed", **results}

                                # 等待授权按钮
                                try:
                                    await page.wait_for_selector('a[href^="/oauth2/approve"]', timeout=30000)
                                except Exception:
                                    await self._take_screenshot(page, "oauth_approve_not_found")
                                    return False, {"error": "OAuth approve button not found", **results}

                                # 点击授权
                                allow_btn = await page.query_selector('a[href^="/oauth2/approve"]')
                                if allow_btn:
                                    print(f"ℹ️ {self.account_name}: Clicking OAuth authorize button")
                                    await allow_btn.click(no_wait_after=True, timeout=30000)

                                # 等待返回 api.voct.top
                                try:
                                    await page.wait_for_url(f"**{self.API_ORIGIN}/**", timeout=30000)
                                except Exception:
                                    await page.wait_for_timeout(5000)

                        # 验证登录成功
                        await page.goto(f"{self.API_ORIGIN}/console", wait_until="networkidle")
                        await page.wait_for_timeout(2000)

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
