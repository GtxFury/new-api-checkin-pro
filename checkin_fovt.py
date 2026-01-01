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
        return await self._get_gift_checkin_status_with_auth(page, auth_header=None)

    @staticmethod
    def _normalize_authorization_header(value: str | None) -> str | None:
        if not value:
            return None
        v = str(value).strip()
        if not v:
            return None
        low = v.lower()
        # 允许传入完整的 "Bearer xxx" / "Token xxx" / "ApiKey xxx"
        if low.startswith(("bearer ", "token ", "apikey ", "api-key ")):
            return v
        # 兜底：当只拿到 token 本体时，按 Bearer 组装
        return f"Bearer {v}"

    async def _try_capture_backend_authorization_header(self, page, *, timeout_ms: int = 8000) -> str | None:
        """尝试从 gift 页面自身发起的请求中抓取 Authorization（最可靠）。"""
        try:
            req = await page.wait_for_request(
                lambda r: (r.url or "").startswith(self.BACKEND_ORIGIN) and ("authorization" in (r.headers or {})),
                timeout=timeout_ms,
            )
            headers = req.headers or {}
            auth = headers.get("authorization") or headers.get("Authorization")
            return self._normalize_authorization_header(auth)
        except Exception:
            return None

    async def _try_extract_authorization_from_storage(self, page) -> str | None:
        """尝试从 localStorage/sessionStorage 里提取 token。"""
        try:
            token = await page.evaluate(
                """() => {
                    const CANDIDATE_KEYS = [
                        'token', 'access_token', 'accessToken', 'jwt', 'id_token', 'idToken',
                        'Authorization', 'authorization', 'auth', 'authToken', 'auth_token'
                    ];

                    const looksLikeJwt = (s) => typeof s === 'string' && s.split('.').length === 3 && s.length > 40;
                    const looksLikeToken = (s) => typeof s === 'string' && s.length >= 16;

                    const pickFromStorage = (st) => {
                        if (!st) return null;
                        for (const k of CANDIDATE_KEYS) {
                            const v = st.getItem(k);
                            if (v && (looksLikeJwt(v) || looksLikeToken(v))) return v;
                        }
                        // 扫描所有 key，尝试解析 JSON 找 token 字段
                        for (let i = 0; i < st.length; i++) {
                            const key = st.key(i);
                            if (!key) continue;
                            const raw = st.getItem(key);
                            if (!raw) continue;
                            if (looksLikeJwt(raw)) return raw;
                            try {
                                const obj = JSON.parse(raw);
                                if (obj && typeof obj === 'object') {
                                    const candidates = [
                                        obj.token, obj.access_token, obj.accessToken, obj.jwt, obj.id_token, obj.idToken,
                                        obj?.data?.token, obj?.data?.access_token, obj?.data?.accessToken
                                    ].filter(Boolean);
                                    for (const c of candidates) {
                                        if (looksLikeJwt(c) || looksLikeToken(c)) return String(c);
                                    }
                                }
                            } catch (e) {
                                // ignore
                            }
                        }
                        return null;
                    };

                    return pickFromStorage(localStorage) || pickFromStorage(sessionStorage) || null;
                }"""
            )
            return self._normalize_authorization_header(token)
        except Exception:
            return None

    async def _try_extract_authorization_from_cookie(self, page) -> str | None:
        """尝试从 document.cookie 里提取 token（仅适用于非 HttpOnly 的 token cookie）。"""
        try:
            token = await page.evaluate(
                """() => {
                    try {
                        const c = document.cookie || '';
                        const parts = c.split(';').map(x => x.trim()).filter(Boolean);
                        const byName = (name) => {
                            const p = parts.find(x => x.toLowerCase().startsWith(name.toLowerCase() + '='));
                            if (!p) return null;
                            const idx = p.indexOf('=');
                            if (idx < 0) return null;
                            return decodeURIComponent(p.slice(idx + 1));
                        };
                        // 常见命名
                        return byName('token') || byName('access_token') || byName('accessToken') || null;
                    } catch (e) {
                        return null;
                    }
                }"""
            )
            return self._normalize_authorization_header(token)
        except Exception:
            return None

    async def _try_click_gift_checkin_and_capture_auth(self, page, *, timeout_ms: int = 8000) -> str | None:
        """尝试点击 gift 页面自带的“签到”按钮，从其真实请求中抓取 Authorization。"""
        try:
            # 先找按钮（不同站点可能叫“签到/立即签到/Check in”）
            btn = None
            for sel in (
                'button:has-text("签到")',
                'button:has-text("立即签到")',
                'button:has-text("Check")',
                'button:has-text("Check in")',
                'button:has-text("Check-in")',
            ):
                try:
                    ele = await page.query_selector(sel)
                    if ele:
                        btn = ele
                        break
                except Exception:
                    continue

            if not btn:
                return None

            # 点击后等待后端 /api/checkin 的 POST 请求出现
            try:
                await btn.click(no_wait_after=True, timeout=3000)
            except Exception:
                try:
                    await page.evaluate("(el) => el && el.click && el.click()", btn)
                except Exception:
                    return None

            req = await page.wait_for_request(
                lambda r: (r.url or "").startswith(f"{self.BACKEND_ORIGIN}/api/checkin")
                and ((r.method or "") == "POST"),
                timeout=timeout_ms,
            )
            headers = req.headers or {}
            auth = headers.get("authorization") or headers.get("Authorization")
            return self._normalize_authorization_header(auth)
        except Exception:
            return None

    async def _get_gift_checkin_status_with_auth(self, page, *, auth_header: str | None) -> dict:
        """获取 gift.voct.top 签到状态（可选携带 Authorization）"""
        try:
            result = await page.evaluate(
                """async (authHeader) => {
                    try {
                        const resp = await fetch('https://backend.voct.top/api/checkin/status', {
                            credentials: 'include',
                            headers: {
                                'Accept': 'application/json',
                                ...(authHeader ? { 'Authorization': authHeader } : {}),
                            }
                        });
                        return { status: resp.status, data: await resp.json() };
                    } catch (e) {
                        return { status: 0, error: e.message };
                    }
                }""",
                auth_header,
            )
            return result or {}
        except Exception as e:
            print(f"⚠️ {self.account_name}: Failed to get checkin status: {e}")
            return {}

    async def _do_gift_checkin(self, page) -> tuple[bool, str]:
        ok, code, _msg = await self._do_gift_checkin_with_auth(page, auth_header=None)
        return ok, code

    async def _do_gift_checkin_with_auth(self, page, *, auth_header: str | None) -> tuple[bool, str, str]:
        """在 gift.voct.top 执行签到"""
        try:
            result = await page.evaluate(
                """async (authHeader) => {
                    try {
                        const resp = await fetch('https://backend.voct.top/api/checkin', {
                            method: 'POST',
                            credentials: 'include',
                            headers: {
                                'Accept': 'application/json',
                                'Content-Type': 'application/json',
                                ...(authHeader ? { 'Authorization': authHeader } : {}),
                            }
                        });
                        const data = await resp.json();
                        return { status: resp.status, data: data };
                    } catch (e) {
                        return { status: 0, error: e.message };
                    }
                }""",
                auth_header,
            )

            if not result:
                return False, "", "empty response"

            status = result.get("status", 0)
            data = result.get("data", {})

            if status == 200 and data.get("success"):
                code = data.get("data", {}).get("code", "")
                quota = data.get("data", {}).get("quota", 0)
                print(f"✅ {self.account_name}: Gift checkin successful! Quota: {quota}, Code: {code}")
                return True, code, "success"

            message = data.get("message", data.get("error", "Unknown error"))
            if "already" in str(message).lower() or "已签到" in str(message) or "已经签到" in str(message):
                print(f"ℹ️ {self.account_name}: Already checked in today on gift site")
                existing_code = data.get("data", {}).get("code", "")
                return True, existing_code, "already"

            print(f"⚠️ {self.account_name}: Gift checkin failed: {message}")
            return False, "", str(message)
        except Exception as e:
            print(f"❌ {self.account_name}: Gift checkin error: {e}")
            return False, "", str(e)

    async def _redeem_code_on_api(self, page, code: str, api_user: str | None = None) -> bool:
        """在 api.voct.top 兑换码"""
        if not code:
            print(f"ℹ️ {self.account_name}: No code to redeem")
            return True

        # 确保有 api_user
        if not api_user:
            api_user = await self._extract_api_user_from_localstorage(page)
        if not api_user:
            print(f"⚠️ {self.account_name}: No api_user for code redemption")
            return False

        try:
            print(f"ℹ️ {self.account_name}: Navigating to topup page to redeem code")
            await page.goto(f"{self.API_ORIGIN}/console/topup", wait_until="domcontentloaded")
            await page.wait_for_timeout(2000)

            result = await page.evaluate(
                """async ({ code, apiUser }) => {
                    try {
                        const resp = await fetch('/api/user/topup', {
                            method: 'POST',
                            credentials: 'include',
                            headers: {
                                'Accept': 'application/json',
                                'Content-Type': 'application/json',
                                'new-api-user': String(apiUser)
                            },
                            body: JSON.stringify({ key: code })
                        });
                        return { status: resp.status, data: await resp.json() };
                    } catch (e) {
                        return { status: 0, error: e.message };
                    }
                }""",
                {"code": code, "apiUser": api_user},
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

    async def _extract_api_user_from_localstorage(self, page) -> str | None:
        """从 localStorage 中读取 user id"""
        import json as _json
        for storage_key in ("user", "user_info", "userInfo"):
            try:
                user_data = await page.evaluate(f"() => localStorage.getItem('{storage_key}')")
            except Exception:
                user_data = None

            if not user_data:
                continue

            try:
                user_obj = _json.loads(user_data)
            except Exception:
                continue

            if not isinstance(user_obj, dict):
                continue

            for id_key in ("id", "user_id", "userId"):
                api_user = user_obj.get(id_key)
                if api_user:
                    return str(api_user)
        return None

    async def _call_oauth_callback(self, page, code: str, auth_state: str) -> str | None:
        """调用 OAuth 回调 API 建立 session，返回 api_user"""
        import json as _json
        from urllib.parse import urlencode

        callback_url = f"{self.API_ORIGIN}/api/oauth/linuxdo"
        params = {"code": code}
        if auth_state:
            params["state"] = auth_state
        final_url = f"{callback_url}?{urlencode(params)}"

        print(f"ℹ️ {self.account_name}: Calling OAuth callback: {final_url}")

        try:
            # 通过浏览器 fetch 调用回调 API（带 credentials）
            result = await page.evaluate(
                """async (url) => {
                    try {
                        const resp = await fetch(url, {
                            credentials: 'include',
                            headers: {
                                'Accept': 'application/json, text/plain, */*'
                            }
                        });
                        const text = await resp.text();
                        return { status: resp.status, text: text };
                    } catch (e) {
                        return { status: 0, error: e.message };
                    }
                }""",
                final_url,
            )

            status = (result or {}).get("status", 0)
            text = (result or {}).get("text", "")

            if status != 200 or not text:
                print(f"⚠️ {self.account_name}: OAuth callback failed: HTTP {status}, body: {text[:200]}")
                return None

            try:
                data = _json.loads(text)
            except Exception as e:
                print(f"⚠️ {self.account_name}: OAuth callback JSON parse failed: {e}")
                return None

            if not isinstance(data, dict) or not data.get("success"):
                msg = data.get("message") if isinstance(data, dict) else "Invalid response"
                print(f"⚠️ {self.account_name}: OAuth callback returned success=false: {msg}")
                return None

            user_data = data.get("data", {})
            if isinstance(user_data, dict):
                api_user = user_data.get("id") or user_data.get("user_id") or user_data.get("userId")
                if api_user:
                    print(f"✅ {self.account_name}: Got api_user from OAuth callback: {api_user}")
                    return str(api_user)

            return None
        except Exception as e:
            print(f"⚠️ {self.account_name}: OAuth callback error: {e}")
            return None

    async def _get_user_balance(self, page, api_user: str | None = None) -> dict:
        """获取用户余额信息"""
        try:
            # 如果没有传入 api_user，先从 localStorage 提取
            if not api_user:
                api_user = await self._extract_api_user_from_localstorage(page)

            if not api_user:
                print(f"⚠️ {self.account_name}: No api_user found in localStorage")
                return {}

            result = await page.evaluate(
                """async (apiUser) => {
                    try {
                        const resp = await fetch('/api/user/self', {
                            credentials: 'include',
                            headers: {
                                'new-api-user': String(apiUser),
                                'Accept': 'application/json, text/plain, */*'
                            }
                        });
                        return { status: resp.status, data: await resp.json() };
                    } catch (e) {
                        return { status: 0, error: e.message };
                    }
                }""",
                api_user
            )

            print(f"ℹ️ {self.account_name}: /api/user/self response: status={result.get('status')}, data={str(result.get('data', {}))[:200]}")

            if not result or result.get("status") != 200:
                print(f"⚠️ {self.account_name}: API returned non-200 status: {result}")
                return {}

            data = result.get("data", {})
            if not data.get("success"):
                print(f"⚠️ {self.account_name}: API returned success=false: {data.get('message', 'no message')}")
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
                    await page.goto(f"{self.API_ORIGIN}/console", wait_until="domcontentloaded")
                    await page.wait_for_timeout(2000)

                    current_url = page.url or ""
                    if "/login" not in current_url:
                        # 先获取 api_user
                        cached_api_user = await self._extract_api_user_from_localstorage(page)
                        balance_info = await self._get_user_balance(page, cached_api_user)
                        if balance_info and balance_info.get("username"):
                            print(f"✅ {self.account_name}: Already logged in as {balance_info.get('username')}")
                            is_logged_in = True
                            results["linuxdo_login"] = True
                            results["api_user"] = cached_api_user  # 保存 api_user 供后续使用

                    # 如果未登录，执行 Linux.do OAuth 登录
                    if not is_logged_in:
                        print(f"ℹ️ {self.account_name}: Need to login via Linux.do OAuth")

                        # 获取 OAuth state
                        await page.goto(f"{self.API_ORIGIN}/login", wait_until="domcontentloaded")
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

                            # ===== 步骤6: 调用 OAuth 回调建立 session =====
                            api_user = await self._call_oauth_callback(page, code, auth_state)

                            if not api_user:
                                # 回调失败，尝试等待 localStorage
                                print(f"⚠️ {self.account_name}: OAuth callback failed, trying localStorage fallback...")
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
                                        timeout=10000,
                                    )
                                    api_user = await self._extract_api_user_from_localstorage(page)
                                except Exception:
                                    pass
                        else:
                            print(f"⚠️ {self.account_name}: No OAuth code found in redirect URL")
                            api_user = None

                        # 等待 localStorage 中出现 user 数据
                        await page.wait_for_timeout(2000)
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
                            print(f"✅ {self.account_name}: localStorage user detected")
                            if not api_user:
                                api_user = await self._extract_api_user_from_localstorage(page)
                        except Exception:
                            print(f"⚠️ {self.account_name}: localStorage timeout, current URL: {page.url}")
                            # 尝试导航到 /console 触发 SPA 初始化
                            try:
                                await page.goto(f"{self.API_ORIGIN}/console", wait_until="domcontentloaded")
                                await page.wait_for_timeout(3000)
                                if not api_user:
                                    api_user = await self._extract_api_user_from_localstorage(page)
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
                            await page.goto(f"{self.API_ORIGIN}/console", wait_until="domcontentloaded")
                            await page.wait_for_timeout(2000)
                            current_url = page.url or ""

                        if "/login" in current_url:
                            await self._take_screenshot(page, "login_verification_failed")
                            await self._save_page_content(page, "login_verification_failed")
                            return False, {"error": "Login verification failed - redirected to login", **results}

                        # 使用已获取的 api_user 验证登录
                        if not api_user:
                            api_user = await self._extract_api_user_from_localstorage(page)

                        balance_info = await self._get_user_balance(page, api_user)
                        if balance_info and balance_info.get("username"):
                            print(f"✅ {self.account_name}: Login successful as {balance_info.get('username')}")
                            is_logged_in = True
                            results["linuxdo_login"] = True
                            results["api_user"] = api_user  # 保存 api_user 供后续使用

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

                    # 尝试在 api.voct.top 侧提前拿到用于 gift/backend 的 Authorization（避免 gift 侧拿不到 token）
                    api_side_auth_header: str | None = None
                    try:
                        await page.goto(f"{self.API_ORIGIN}/console/token", wait_until="domcontentloaded")
                        await page.wait_for_timeout(1500)
                    except Exception:
                        pass
                    api_side_auth_header = await self._try_extract_authorization_from_storage(page)
                    if api_side_auth_header:
                        print(f"ℹ️ {self.account_name}: Found an auth token in api site storage (will try for gift checkin)")

                    # 步骤2: 访问 gift.voct.top 进行签到
                    print(f"ℹ️ {self.account_name}: Navigating to gift site for checkin")

                    captured_auth: dict[str, str | None] = {"auth": None}

                    def _maybe_capture_auth(req) -> None:
                        try:
                            if captured_auth.get("auth"):
                                return
                            u = getattr(req, "url", "") or ""
                            if not u.startswith(self.BACKEND_ORIGIN):
                                return
                            headers = getattr(req, "headers", None) or {}
                            auth = headers.get("authorization") or headers.get("Authorization")
                            auth2 = self._normalize_authorization_header(auth)
                            if auth2:
                                captured_auth["auth"] = auth2
                        except Exception:
                            return

                    try:
                        page.on("request", _maybe_capture_auth)
                    except Exception:
                        pass

                    await page.goto(f"{self.GIFT_ORIGIN}/dashboard/checkin", wait_until="domcontentloaded")
                    await page.wait_for_timeout(2000)

                    gift_auth_header = captured_auth.get("auth")
                    if not gift_auth_header:
                        gift_auth_header = await self._try_capture_backend_authorization_header(page, timeout_ms=6000)
                    if not gift_auth_header:
                        gift_auth_header = await self._try_extract_authorization_from_storage(page)
                    if not gift_auth_header:
                        gift_auth_header = await self._try_extract_authorization_from_cookie(page)
                    if not gift_auth_header:
                        gift_auth_header = api_side_auth_header
                    if not gift_auth_header:
                        gift_auth_header = await self._try_click_gift_checkin_and_capture_auth(page, timeout_ms=8000)

                    if gift_auth_header:
                        print(f"✅ {self.account_name}: Gift/backend Authorization ready")
                    else:
                        print(
                            f"⚠️ {self.account_name}: No Authorization token detected for gift/backend; "
                            "backend may return 401"
                        )

                    # 检查签到状态
                    checkin_status = await self._get_gift_checkin_status_with_auth(page, auth_header=gift_auth_header)
                    print(f"ℹ️ {self.account_name}: Checkin status: {checkin_status}")

                    # 执行签到
                    checkin_ok, redemption_code, gift_msg = await self._do_gift_checkin_with_auth(
                        page, auth_header=gift_auth_header
                    )
                    # 如果提示缺少鉴权，且我们未能拿到 token，则再尝试一次“点击按钮抓取 token → 重新 fetch”
                    try:
                        status0 = int((checkin_status or {}).get("status", 0) or 0)
                    except Exception:
                        status0 = 0
                    if (not checkin_ok) and (not gift_auth_header) and (
                        status0 == 401 or "authorization" in str(gift_msg).lower()
                    ):
                        retry_auth = await self._try_click_gift_checkin_and_capture_auth(page, timeout_ms=8000)
                        if retry_auth:
                            print(f"ℹ️ {self.account_name}: Captured Authorization after retry, re-trying checkin fetch")
                            checkin_ok, redemption_code, gift_msg = await self._do_gift_checkin_with_auth(
                                page, auth_header=retry_auth
                            )
                    results["gift_checkin"] = checkin_ok
                    if not checkin_ok and gift_msg and not results.get("error"):
                        results["error"] = f"Gift checkin failed: {gift_msg}"

                    # 步骤3: 如果获得了兑换码，去 api.voct.top 兑换
                    # 获取当前的 api_user（可能来自登录流程或 results）
                    current_api_user = results.get("api_user")
                    if not current_api_user:
                        await page.goto(f"{self.API_ORIGIN}/console", wait_until="domcontentloaded")
                        await page.wait_for_timeout(1000)
                        current_api_user = await self._extract_api_user_from_localstorage(page)

                    if redemption_code:
                        print(f"ℹ️ {self.account_name}: Got redemption code: {redemption_code}")
                        redeem_ok = await self._redeem_code_on_api(page, redemption_code, current_api_user)
                        results["code_redeem"] = redeem_ok
                    else:
                        print(f"ℹ️ {self.account_name}: No new code to redeem")
                        results["code_redeem"] = True

                    # 步骤4: 获取最终余额
                    await page.goto(f"{self.API_ORIGIN}/console", wait_until="domcontentloaded")
                    await page.wait_for_timeout(1000)
                    if not current_api_user:
                        current_api_user = await self._extract_api_user_from_localstorage(page)
                    final_balance = await self._get_user_balance(page, current_api_user)
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
