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

    # gift.voct.top 独立的 LinuxDO OAuth（与 api.voct.top 不同）
    GIFT_LINUXDO_CLIENT_ID = "Aw6rTYW8xdo6lC2kdeDjLdsDQyKtQ7py"
    GIFT_REDIRECT_URI = "https://gift.voct.top/api/auth/callback"

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

    async def _safe_goto(
        self,
        page,
        url: str,
        *,
        wait_until: str = "domcontentloaded",
        timeout_ms: int = 30000,
        retries: int = 3,
        expected_prefixes: list[str] | None = None,
    ) -> None:
        """更稳健的 page.goto：处理重定向/并发导航导致的 NS_BINDING_ABORTED。"""
        expected = expected_prefixes or [url.split("?")[0]]
        last_err: Exception | None = None

        for i in range(max(1, retries)):
            try:
                await page.goto(url, wait_until=wait_until, timeout=timeout_ms)
                return
            except Exception as e:
                last_err = e
                msg = str(e)
                cur = ""
                try:
                    cur = page.url or ""
                except Exception:
                    cur = ""

                # 常见：站点在跳转/SPA 内部二次导航时，会中止当前 goto
                aborted = ("NS_BINDING_ABORTED" in msg) or ("net::ERR_ABORTED" in msg) or ("ERR_ABORTED" in msg)
                if aborted:
                    if any(cur.startswith(p) for p in expected):
                        print(f"ℹ️ {self.account_name}: Navigation aborted but already at target: {cur}")
                        return
                    print(f"⚠️ {self.account_name}: Navigation aborted (attempt {i+1}/{retries}), current URL: {cur}")
                    await page.wait_for_timeout(600 * (i + 1))
                    continue

                # 超时也重试一次（gift 偶发慢）
                if "Timeout" in msg or "timeout" in msg:
                    print(f"⚠️ {self.account_name}: Navigation timeout (attempt {i+1}/{retries}), current URL: {cur}")
                    await page.wait_for_timeout(600 * (i + 1))
                    continue

                raise

        # retries exhausted
        if last_err:
            raise last_err

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
    def _mask_secret(value: str | None, *, keep_start: int = 8, keep_end: int = 4) -> str:
        if not value:
            return ""
        v = str(value)
        if len(v) <= keep_start + keep_end + 3:
            return f"{v[: max(0, keep_start)]}***"
        return f"{v[:keep_start]}...{v[-keep_end:]}(len={len(v)})"

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

    @staticmethod
    def _extract_auth_from_headers(headers: dict | None) -> str | None:
        if not headers or not isinstance(headers, dict):
            return None
        # Playwright 的 headers 通常是小写 key
        for k in (
            "authorization",
            "Authorization",
            "x-authorization",
            "X-Authorization",
            "x-auth-token",
            "X-Auth-Token",
            "x-token",
            "X-Token",
        ):
            v = headers.get(k)
            if v:
                return str(v)
        return None

    @staticmethod
    def _expand_auth_header_variants(auth_header: str) -> list[str]:
        v = (auth_header or "").strip()
        if not v:
            return []
        variants: list[str] = []
        low = v.lower()
        variants.append(v)
        if low.startswith("bearer "):
            token = v[7:].strip()
            if token:
                variants.extend([token, f"Token {token}"])
        elif low.startswith("token "):
            token = v[6:].strip()
            if token:
                variants.extend([f"Bearer {token}", token])
        else:
            variants.extend([f"Bearer {v}", f"Token {v}"])

        # 去重（保持顺序）
        seen: set[str] = set()
        out: list[str] = []
        for x in variants:
            x2 = (x or "").strip()
            if not x2 or x2 in seen:
                continue
            seen.add(x2)
            out.append(x2)
        return out

    async def _try_capture_backend_authorization_header(self, page, *, timeout_ms: int = 8000) -> str | None:
        """尝试从 gift 页面自身发起的请求中抓取 Authorization（最可靠）。"""
        try:
            req = await page.wait_for_request(
                lambda r: (r.url or "").startswith(self.BACKEND_ORIGIN)
                and bool(self._extract_auth_from_headers(getattr(r, "headers", None) or {})),
                timeout=timeout_ms,
            )
            headers = req.headers or {}
            auth = self._extract_auth_from_headers(headers)
            return self._normalize_authorization_header(auth)
        except Exception:
            return None

    async def _try_extract_authorization_from_storage(self, page) -> str | None:
        """尝试从 localStorage/sessionStorage 里提取 token。"""
        auth, _src = await self._try_extract_authorization_from_storage_debug(page)
        return auth

    async def _try_extract_authorization_from_storage_debug(self, page) -> tuple[str | None, str | None]:
        """尝试从 localStorage/sessionStorage 里提取 token，并返回来源信息（不打印明文）。"""
        try:
            found = await page.evaluate(
                """() => {
                    const CANDIDATE_KEYS = [
                        'fo_token',
                        'token', 'access_token', 'accessToken', 'jwt', 'id_token', 'idToken',
                        'Authorization', 'authorization', 'auth', 'authToken', 'auth_token'
                    ];

                    const looksLikeJwt = (s) => typeof s === 'string' && s.split('.').length === 3 && s.length > 40;
                    const looksLikeToken = (s) => typeof s === 'string' && s.length >= 24;

                    const pickFromStorage = (st, stName) => {
                        if (!st) return null;
                        for (const k of CANDIDATE_KEYS) {
                            const v = st.getItem(k);
                            if (v && (looksLikeJwt(v) || looksLikeToken(v))) return { value: v, source: `${stName}:${k}` };
                        }
                        // 扫描所有 key，尝试解析 JSON 找 token 字段
                        for (let i = 0; i < st.length; i++) {
                            const key = st.key(i);
                            if (!key) continue;
                            const raw = st.getItem(key);
                            if (!raw) continue;
                            if (looksLikeJwt(raw)) return { value: raw, source: `${stName}:${key}(raw)` };
                            try {
                                const obj = JSON.parse(raw);
                                if (obj && typeof obj === 'object') {
                                    const candidates = [
                                        obj.token, obj.access_token, obj.accessToken, obj.jwt, obj.id_token, obj.idToken,
                                        obj?.data?.token, obj?.data?.access_token, obj?.data?.accessToken
                                    ].filter(Boolean);
                                    for (const c of candidates) {
                                        if (looksLikeJwt(c) || looksLikeToken(c)) return { value: String(c), source: `${stName}:${key}(json)` };
                                    }
                                }
                            } catch (e) {
                                // ignore
                            }
                        }
                        return null;
                    };

                    return pickFromStorage(localStorage, 'localStorage') || pickFromStorage(sessionStorage, 'sessionStorage') || null;
                }"""
            )
            if not found or not isinstance(found, dict):
                return None, None
        except Exception:
            return None, None

        try:
            token = (found or {}).get("value")
            src = (found or {}).get("source")
        except Exception:
            token, src = None, None

        auth = self._normalize_authorization_header(token)
        return auth, (str(src) if src else None)

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

    async def _try_extract_authorization_from_context_cookies(self, context) -> tuple[str | None, str | None]:
        """从浏览器上下文 cookies 中提取 token（支持 HttpOnly）。"""
        try:
            cookies = await context.cookies([self.GIFT_ORIGIN, self.BACKEND_ORIGIN])
        except Exception:
            cookies = []

        best: tuple[str | None, str | None] = (None, None)
        for c in cookies or []:
            try:
                name = str(c.get("name") or "")
                value = str(c.get("value") or "")
                if not name or not value:
                    continue
                low = name.lower()
                if low in ("token", "access_token", "accesstoken", "authorization", "auth", "jwt"):
                    auth = self._normalize_authorization_header(value)
                    if auth:
                        best = (auth, f"cookie:{name}")
                        # 优先 JWT-like（尽早返回）
                        if value.count(".") == 2 and len(value) > 40:
                            return best
            except Exception:
                continue
        return best

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
            auth = self._extract_auth_from_headers(headers)
            return self._normalize_authorization_header(auth)
        except Exception:
            return None

    async def _try_gift_ui_checkin(self, page, *, timeout_ms: int = 12000) -> tuple[bool, str, str]:
        """通过 gift 页面 UI 触发签到（更贴近站点真实流程），并尝试从响应中提取兑换码。"""
        try:
            # 有些页面会直接展示“已签到”，此时不强制点击按钮
            try:
                body_text = await page.evaluate("() => (document.body && document.body.innerText) ? document.body.innerText : ''")
            except Exception:
                body_text = ""
            if isinstance(body_text, str) and ("已签到" in body_text or "已经签到" in body_text):
                return True, "", "ui_already"

            btn = None
            for sel in (
                'button:has-text("立即签到")',
                'button:has-text("签到")',
                'button:has-text("Check in")',
                'button:has-text("Check-in")',
                'button:has-text("Check")',
            ):
                try:
                    ele = await page.query_selector(sel)
                    if ele:
                        btn = ele
                        break
                except Exception:
                    continue

            if not btn:
                return False, "", "ui_button_not_found"

            # 等待点击后触发的后端请求/响应
            try:
                await btn.click(no_wait_after=True, timeout=3000)
            except Exception:
                try:
                    await page.evaluate("(el) => el && el.click && el.click()", btn)
                except Exception:
                    return False, "", "ui_click_failed"

            resp = await page.wait_for_response(
                lambda r: (r.url or "").startswith(f"{self.BACKEND_ORIGIN}/api/checkin")
                and ((r.request.method or "") == "POST"),
                timeout=timeout_ms,
            )

            status = getattr(resp, "status", None) or 0
            try:
                text = await resp.text()
            except Exception:
                text = ""

            # 尝试解析 JSON
            import json as _json

            data = None
            if text:
                try:
                    data = _json.loads(text)
                except Exception:
                    data = text

            if int(status) == 200 and isinstance(data, dict) and data.get("success"):
                code = (data.get("data") or {}).get("code") or ""
                return True, str(code or ""), "ui_success"

            # 已签到也视为成功
            msg = ""
            if isinstance(data, dict):
                msg = str(data.get("message") or data.get("error") or data.get("msg") or "")
            elif isinstance(data, str):
                msg = data

            if "already" in msg.lower() or "已签到" in msg or "已经签到" in msg:
                code = (data.get("data") or {}).get("code") if isinstance(data, dict) else ""
                return True, str(code or ""), "ui_already"

            return False, "", f"ui_failed_http_{status}:{msg[:120]}"
        except Exception as e:
            return False, "", f"ui_exception:{e}"

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
                        const text = await resp.text();
                        let data = null;
                        try { data = JSON.parse(text); } catch (e) { data = text; }
                        return { status: resp.status, data: data, text: text.slice(0, 600) };
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

    async def _get_gift_oauth_url(self, page) -> str | None:
        """获取 gift 站点的 LinuxDO OAuth URL（由 backend 下发）。"""
        try:
            result = await page.evaluate(
                """async () => {
                    try {
                        const url = 'https://backend.voct.top/api/auth/url?redirect_origin=' + encodeURIComponent('https://gift.voct.top');
                        const resp = await fetch(url, {
                            credentials: 'include',
                            headers: { 'Accept': 'application/json, text/plain, */*' },
                        });
                        const text = await resp.text();
                        let data = null;
                        try { data = JSON.parse(text); } catch (e) { data = text; }
                        return { status: resp.status, data, text: text.slice(0, 400) };
                    } catch (e) {
                        return { status: 0, error: e.message };
                    }
                }"""
            )

            status = (result or {}).get("status", 0)
            data = (result or {}).get("data")
            if status != 200 or not isinstance(data, dict):
                print(f"⚠️ {self.account_name}: Failed to get gift auth url: HTTP {status}, body={str((result or {}).get('text',''))[:160]}")
                return None

            # 有时后端会返回 success=false 但仍带 url 字段（兼容处理）
            if not data.get("success"):
                raw_url = None
                try:
                    raw_url = data.get("url")
                except Exception:
                    raw_url = None
                if raw_url and isinstance(raw_url, str) and raw_url.startswith("http"):
                    print(f"⚠️ {self.account_name}: Gift auth url api returned success=false but includes url, will use it")
                    return raw_url
                print(
                    f"⚠️ {self.account_name}: Gift auth url api returned success=false: "
                    f"{data.get('message') or data.get('error') or ''}"
                )
                try:
                    print(f"ℹ️ {self.account_name}: Gift auth url raw body: {str((result or {}).get('text',''))[:200]}")
                except Exception:
                    pass
                return None

            url = None
            payload = data.get("data")
            if isinstance(payload, dict):
                url = payload.get("url") or payload.get("auth_url")
            if not url and isinstance(payload, str):
                url = payload

            if url and isinstance(url, str) and url.startswith("http"):
                return url
            print(f"⚠️ {self.account_name}: Gift auth url missing or invalid")
            return None
        except Exception as e:
            print(f"⚠️ {self.account_name}: Gift auth url error: {e}")
            return None

    async def _start_gift_oauth_via_ui(self, page) -> str | None:
        """从 gift 首页通过点击“立即开始/登录”触发 OAuth 跳转，并返回跳转到的 authorize URL。"""
        try:
            await page.goto(self.GIFT_ORIGIN, wait_until="domcontentloaded")
            await page.wait_for_timeout(1200)
        except Exception:
            pass

        btn = None
        for sel in (
            'button:has-text("立即开始")',
            'a:has-text("立即开始")',
            'button:has-text("登录")',
            'a:has-text("登录")',
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

        try:
            await btn.click(no_wait_after=True, timeout=5000)
        except Exception:
            try:
                await page.evaluate("(el) => el && el.click && el.click()", btn)
            except Exception:
                return None

        try:
            await page.wait_for_url("**connect.linux.do/oauth2/authorize**", timeout=15000)
        except Exception:
            return None

        return page.url

    async def _ensure_gift_logged_in(self, page, context, linuxdo_username: str, linuxdo_password: str) -> str | None:
        """确保 gift 站点已完成 LinuxDO OAuth，并返回可用的 Authorization header（Bearer ...）。"""
        async def _read_fo_token() -> str | None:
            try:
                t = await page.evaluate("() => localStorage.getItem('fo_token')")
            except Exception:
                t = None
            return self._normalize_authorization_header(t)

        # 先尝试直接用本地 fo_token 校验
        existing = await _read_fo_token()
        if existing:
            ok, _resp = await self._validate_gift_auth_header(page, existing)
            if ok:
                return existing

        oauth_url = await self._get_gift_oauth_url(page)
        if not oauth_url:
            # 后端下发失败时，回退到 UI 点击触发（更贴近真实站点逻辑）
            oauth_url = await self._start_gift_oauth_via_ui(page)

        if not oauth_url:
            # 最后兜底：根据实际站点观测到的参数拼一个 authorize URL
            from urllib.parse import quote as _quote

            oauth_url = (
                "https://connect.linux.do/oauth2/authorize?"
                f"client_id={self.GIFT_LINUXDO_CLIENT_ID}&response_type=code"
                f"&redirect_uri={_quote(self.GIFT_REDIRECT_URI, safe='')}&scope=read"
            )
            print(f"⚠️ {self.account_name}: Gift auth url api/ui failed, using fallback authorize URL")

        # 注意：不要直接打印完整 URL（可能包含敏感参数）
        try:
            base = oauth_url.split("?")[0]
            print(f"ℹ️ {self.account_name}: Starting gift OAuth via LinuxDO (authorize: {base})")
        except Exception:
            print(f"ℹ️ {self.account_name}: Starting gift OAuth via LinuxDO")

        try:
            await page.goto(oauth_url, wait_until="domcontentloaded")
        except Exception as e:
            print(f"⚠️ {self.account_name}: Failed to navigate to gift OAuth url: {e}")
            return None

        # 记录 authorize 参数（便于核对 client_id/redirect_uri）
        try:
            from urllib.parse import urlparse, parse_qs
            from utils.redact import redact_value_for_log

            p = urlparse(page.url or "")
            q = parse_qs(p.query)
            cid = (q.get("client_id") or [""])[0]
            ruri = (q.get("redirect_uri") or [""])[0]
            scope = (q.get("scope") or [""])[0]
            print(
                f"ℹ️ {self.account_name}: Gift OAuth params: "
                f"client_id={redact_value_for_log(cid) or '***'}, "
                f"redirect_uri={redact_value_for_log(ruri) or '***'}, "
                f"scope={scope}"
            )
        except Exception:
            pass

        # 若跳到 linux.do/login，自动填表登录
        try:
            await self._linuxdo_login_if_needed(page, linuxdo_username, linuxdo_password)
        except Exception as e:
            print(f"⚠️ {self.account_name}: Gift OAuth linux.do login failed: {e}")
            return None

        # 授权按钮
        try:
            await page.wait_for_selector('a[href^="/oauth2/approve"]', timeout=30000)
        except Exception:
            await self._take_screenshot(page, "gift_oauth_approve_not_found")
            await self._save_page_content(page, "gift_oauth_approve_not_found")
            return None

        allow_btn = await page.query_selector('a[href^="/oauth2/approve"]')
        if not allow_btn:
            return None

        try:
            await allow_btn.click(no_wait_after=True, timeout=15000)
        except Exception:
            try:
                await page.evaluate("(el) => el && el.click && el.click()", allow_btn)
            except Exception:
                return None

        # 等待回到 gift 站点；该站点常见会先落在 /auth/success?token=... 再跳转 dashboard
        try:
            await page.wait_for_url(f"**{self.GIFT_ORIGIN}/**", timeout=30000)
        except Exception:
            # 兜底等待
            await page.wait_for_timeout(3000)

        # 若当前落在 /auth/success?token=...，优先从 URL 读取 token 并写入 localStorage
        try:
            from urllib.parse import urlparse, parse_qs

            u = page.url or ""
            if "/auth/success" in u and "token=" in u:
                qs = parse_qs(urlparse(u).query)
                t_url = (qs.get("token") or [""])[0]
                if t_url:
                    try:
                        await page.evaluate(
                            """(t) => {
                                try {
                                    if (!localStorage.getItem('fo_token')) localStorage.setItem('fo_token', String(t));
                                } catch (e) {}
                            }""",
                            t_url,
                        )
                    except Exception:
                        pass
        except Exception:
            pass

        # 等待 localStorage fo_token 落地（避免 URL 含 token 的瞬态页没来得及写入）
        try:
            await page.wait_for_function(
                """() => {
                    try {
                        const t = localStorage.getItem('fo_token');
                        return t !== null && t !== '';
                    } catch (e) {
                        return false;
                    }
                }""",
                timeout=15000,
            )
        except Exception:
            pass

        token = await _read_fo_token()
        if not token:
            await self._take_screenshot(page, "gift_oauth_no_token")
            return None

        ok, resp = await self._validate_gift_auth_header(page, token)
        if not ok:
            err = ""
            try:
                d = (resp or {}).get("data")
                if isinstance(d, dict):
                    err = str(d.get("error") or d.get("message") or "")
                else:
                    err = str(d or "")
            except Exception:
                err = ""
            print(f"⚠️ {self.account_name}: Gift fo_token validation failed after OAuth: {err[:120]}")
            return None

        # 保存 session（包含 gift 的 localStorage/cookies）
        try:
            await context.storage_state()
        except Exception:
            pass

        return token

    async def _validate_gift_auth_header(self, page, auth_header: str | None) -> tuple[bool, dict]:
        resp = await self._get_gift_checkin_status_with_auth(page, auth_header=auth_header)
        try:
            st = int((resp or {}).get("status", 0) or 0)
        except Exception:
            st = 0
        msg = ""
        try:
            d = (resp or {}).get("data")
            if isinstance(d, dict):
                msg = str(d.get("error") or d.get("message") or "")
            else:
                msg = str(d or "")
        except Exception:
            msg = ""
        if st == 0:
            return False, resp
        if st == 401 and ("invalid token" in msg.lower() or "missing authorization" in msg.lower()):
            return False, resp
        return True, resp

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
                        const text = await resp.text();
                        let data = null;
                        try { data = JSON.parse(text); } catch (e) { data = text; }
                        return { status: resp.status, data: data, text: text.slice(0, 600) };
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
                # code 可能不在同一个字段里，先按常规路径取一次；若为空后续会通过 /api/records 再补取
                code = data.get("data", {}).get("code", "")
                quota = data.get("data", {}).get("quota", 0)
                print(f"✅ {self.account_name}: Gift checkin successful! Quota: {quota}, Code: {self._mask_secret(code)}")
                return True, code, "success"

            message = data.get("message", data.get("error", "Unknown error")) if isinstance(data, dict) else str(data)
            if "already" in str(message).lower() or "已签到" in str(message) or "已经签到" in str(message):
                print(f"ℹ️ {self.account_name}: Already checked in today on gift site")
                existing_code = data.get("data", {}).get("code", "") if isinstance(data, dict) else ""
                return True, existing_code, "already"

            print(f"⚠️ {self.account_name}: Gift checkin failed: {message}")
            return False, "", str(message)
        except Exception as e:
            print(f"❌ {self.account_name}: Gift checkin error: {e}")
            return False, "", str(e)

    async def _get_gift_records(self, page, *, auth_header: str | None) -> dict:
        """获取 gift 历史记录（用于补取兑换码）。"""
        try:
            result = await page.evaluate(
                """async (authHeader) => {
                    try {
                        const resp = await fetch('https://backend.voct.top/api/records', {
                            credentials: 'include',
                            headers: {
                                'Accept': 'application/json',
                                ...(authHeader ? { 'Authorization': authHeader } : {}),
                            }
                        });
                        const text = await resp.text();
                        let data = null;
                        try { data = JSON.parse(text); } catch (e) { data = text; }
                        return { status: resp.status, data: data, text: text.slice(0, 600) };
                    } catch (e) {
                        return { status: 0, error: e.message };
                    }
                }""",
                auth_header,
            )
            return result or {}
        except Exception as e:
            return {"status": 0, "error": str(e)}

    @staticmethod
    def _extract_redeem_code_from_records_payload(payload) -> str | None:
        """从 /api/records 的返回中尽量提取最新的兑换码。"""
        if not payload:
            return None

        # 兼容各种结构：{success,data:[...]}/{success,data:{records:[...]}}/直接 list
        records = None
        if isinstance(payload, dict):
            data = payload.get("data")
            if isinstance(data, list):
                records = data
            elif isinstance(data, dict):
                for k in ("records", "items", "list", "rows"):
                    if isinstance(data.get(k), list):
                        records = data.get(k)
                        break
        elif isinstance(payload, list):
            records = payload

        if not records or not isinstance(records, list):
            return None

        def _pick_code(obj: dict) -> str | None:
            # 常见字段名
            for k in ("code", "cdk", "key"):
                v = obj.get(k)
                if isinstance(v, str) and v.strip():
                    return v.strip()
            # 有些是嵌套在 data 里
            d = obj.get("data")
            if isinstance(d, dict):
                for k in ("code", "cdk", "key"):
                    v = d.get(k)
                    if isinstance(v, str) and v.strip():
                        return v.strip()
            return None

        def _parse_dt_key(obj: dict) -> tuple[int, int, int, int, int, int] | None:
            import re as _re

            for k in ("created_at", "createdAt", "time", "created", "date"):
                v = obj.get(k)
                if not isinstance(v, str) or not v:
                    continue
                m = _re.search(r"(\\d{4})[/-](\\d{1,2})[/-](\\d{1,2})\\s+(\\d{1,2}):(\\d{1,2}):(\\d{1,2})", v)
                if not m:
                    continue
                try:
                    return tuple(int(x) for x in m.groups())  # type: ignore[return-value]
                except Exception:
                    continue
            return None

        # 优先按时间倒序（若有 created_at）
        try:
            sortable: list[tuple[tuple[int, int, int, int, int, int], dict]] = []
            rest: list[dict] = []
            for rec in records:
                if not isinstance(rec, dict):
                    continue
                key = _parse_dt_key(rec)
                if key:
                    sortable.append((key, rec))
                else:
                    rest.append(rec)
            if sortable:
                sortable.sort(key=lambda x: x[0], reverse=True)
                records = [r for _k, r in sortable] + rest
        except Exception:
            pass

        # 从前往后找第一个“像签到”的记录
        for rec in records:
            if not isinstance(rec, dict):
                continue
            typ = str(rec.get("type") or rec.get("record_type") or rec.get("kind") or "")
            if typ and ("check" in typ.lower() or "sign" in typ.lower() or "签到" in typ):
                code = _pick_code(rec)
                if code:
                    return code

        # 兜底：直接找第一个有 code 的记录
        for rec in records:
            if not isinstance(rec, dict):
                continue
            code = _pick_code(rec)
            if code:
                return code

        return None

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
            await self._safe_goto(
                page,
                f"{self.API_ORIGIN}/console/topup",
                wait_until="domcontentloaded",
                retries=3,
                expected_prefixes=[f"{self.API_ORIGIN}/console/topup"],
            )
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

            # 注意：避免把 /api/user/self 的完整返回（包含隐私字段）打到日志里
            try:
                _status = result.get("status")
                _data = result.get("data", {}) or {}
                _success = _data.get("success") if isinstance(_data, dict) else None
                _msg = ""
                if isinstance(_data, dict):
                    _msg = str(_data.get("message") or _data.get("error") or _data.get("msg") or "")
                _ud = _data.get("data", {}) if isinstance(_data, dict) else {}
                if isinstance(_ud, dict) and _success:
                    try:
                        _quota_raw = float(_ud.get("quota", 0) or 0)
                    except Exception:
                        _quota_raw = 0.0
                    quota_per_unit = 500000
                    _balance = round(_quota_raw / quota_per_unit, 2) if _quota_raw else 0.0
                    # 仅输出转换后的余额（不输出用户名等隐私信息）
                    print(
                        f"ℹ️ {self.account_name}: /api/user/self response: status={_status}, success={_success}, "
                        f"balance=${_balance}"
                    )
                else:
                    print(
                        f"ℹ️ {self.account_name}: /api/user/self response: status={_status}, success={_success}, "
                        f"message={_msg[:120]}"
                    )
            except Exception:
                print(f"ℹ️ {self.account_name}: /api/user/self response received")

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
                    # 打印缓存里包含的 origin 概览（不输出任何 localStorage/cookie 明文）
                    try:
                        import json as _json

                        with open(storage_state, "r", encoding="utf-8") as f:
                            ss = _json.load(f)
                        origins = []
                        if isinstance(ss, dict) and isinstance(ss.get("origins"), list):
                            for o in ss.get("origins") or []:
                                if isinstance(o, dict) and o.get("origin"):
                                    origins.append(str(o.get("origin")))
                        if origins:
                            show = ", ".join(origins[:8])
                            more = f" (+{len(origins) - 8})" if len(origins) > 8 else ""
                            print(f"ℹ️ {self.account_name}: Cache origins: {show}{more}")
                    except Exception:
                        pass
                else:
                    print(f"ℹ️ {self.account_name}: No cache file found, starting fresh")

                context = await browser.new_context(storage_state=storage_state)
                page = await context.new_page()

                try:
                    is_logged_in = False

                    # 步骤1: 检查是否已登录 api.voct.top
                    print(f"ℹ️ {self.account_name}: Checking login status on api.voct.top")
                    await self._safe_goto(
                        page,
                        f"{self.API_ORIGIN}/console",
                        wait_until="domcontentloaded",
                        retries=3,
                        expected_prefixes=[f"{self.API_ORIGIN}/console", f"{self.API_ORIGIN}/login"],
                    )
                    await page.wait_for_timeout(2000)

                    current_url = page.url or ""
                    if "/login" not in current_url:
                        # 先获取 api_user
                        cached_api_user = await self._extract_api_user_from_localstorage(page)
                        balance_info = await self._get_user_balance(page, cached_api_user)
                        if balance_info and balance_info.get("raw_quota") is not None:
                            print(f"✅ {self.account_name}: Already logged in")
                            is_logged_in = True
                            results["linuxdo_login"] = True
                            results["api_user"] = cached_api_user  # 保存 api_user 供后续使用

                    # 如果未登录，执行 Linux.do OAuth 登录
                    if not is_logged_in:
                        print(f"ℹ️ {self.account_name}: Need to login via Linux.do OAuth")

                        # 获取 OAuth state
                        await self._safe_goto(
                            page,
                            f"{self.API_ORIGIN}/login",
                            wait_until="domcontentloaded",
                            retries=3,
                            expected_prefixes=[f"{self.API_ORIGIN}/login"],
                        )
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
                                await self._safe_goto(
                                    page,
                                    f"{self.API_ORIGIN}/console",
                                    wait_until="domcontentloaded",
                                    retries=3,
                                    expected_prefixes=[f"{self.API_ORIGIN}/console", f"{self.API_ORIGIN}/login"],
                                )
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
                            await self._safe_goto(
                                page,
                                f"{self.API_ORIGIN}/console",
                                wait_until="domcontentloaded",
                                retries=3,
                                expected_prefixes=[f"{self.API_ORIGIN}/console", f"{self.API_ORIGIN}/login"],
                            )
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
                        if balance_info and balance_info.get("raw_quota") is not None:
                            print(f"✅ {self.account_name}: Login successful")
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
                        await self._safe_goto(
                            page,
                            f"{self.API_ORIGIN}/console/token",
                            wait_until="domcontentloaded",
                            retries=3,
                            expected_prefixes=[f"{self.API_ORIGIN}/console/token", f"{self.API_ORIGIN}/console"],
                        )
                        await page.wait_for_timeout(1500)
                    except Exception:
                        pass
                    api_side_auth_header, api_side_auth_src = await self._try_extract_authorization_from_storage_debug(
                        page
                    )
                    if api_side_auth_header:
                        print(
                            f"ℹ️ {self.account_name}: Found an auth token in api site storage ({api_side_auth_src or 'unknown'}), "
                            "will only use it if validation passes"
                        )

                    # 步骤2: 访问 gift.voct.top 进行签到
                    print(f"ℹ️ {self.account_name}: Navigating to gift site for checkin")

                    # 先访问 gift 首页，再确保 gift 登录（避免直接进 /dashboard/checkin 被 SPA/重定向中断导致 NS_BINDING_ABORTED）
                    try:
                        await self._safe_goto(
                            page,
                            f"{self.GIFT_ORIGIN}/",
                            wait_until="domcontentloaded",
                            retries=3,
                            expected_prefixes=[f"{self.GIFT_ORIGIN}/"],
                        )
                        await page.wait_for_timeout(800)
                    except Exception:
                        pass

                    # 关键：gift 有自己独立的 LinuxDO OAuth（client_id/redirect_uri 与 api.voct 不同）
                    # 如果未登录 gift，就必须跑一遍 gift OAuth 来拿到 fo_token（否则用 api 侧 token 会 invalid token）。
                    ensured = await self._ensure_gift_logged_in(page, context, linuxdo_username, linuxdo_password)
                    if ensured:
                        print(f"✅ {self.account_name}: Gift OAuth session ready (fo_token={self._mask_secret(ensured)})")
                        # 保存包含 gift 登录态的 storage_state，避免下次重复 OAuth
                        try:
                            if cache_file_path:
                                cache_dir = os.path.dirname(cache_file_path)
                                if cache_dir:
                                    os.makedirs(cache_dir, exist_ok=True)
                                await context.storage_state(path=cache_file_path)
                                print(f"✅ {self.account_name}: Gift session saved to cache")
                        except Exception as e:
                            print(f"⚠️ {self.account_name}: Failed to save gift session: {e}")

                    # 进入签到页（无论是否 ensured，都尝试进入；失败也不应直接中断整个流程）
                    try:
                        await self._safe_goto(
                            page,
                            f"{self.GIFT_ORIGIN}/dashboard/checkin",
                            wait_until="domcontentloaded",
                            retries=4,
                            expected_prefixes=[f"{self.GIFT_ORIGIN}/dashboard/checkin"],
                        )
                        await page.wait_for_timeout(1500)
                    except Exception as e:
                        print(f"⚠️ {self.account_name}: Failed to open gift checkin page: {e}")
                        await self._take_screenshot(page, "gift_checkin_page_goto_failed")

                    # gift/back-end 调试信息：抓取请求/响应、存储 key 等（避免打印明文 token）
                    captured_auth: dict[str, str | None] = {"auth": None, "src": None}
                    backend_recent: list[dict] = []

                    def _maybe_capture_auth(req) -> None:
                        try:
                            if captured_auth.get("auth"):
                                return
                            u = getattr(req, "url", "") or ""
                            if not u.startswith(self.BACKEND_ORIGIN):
                                return
                            headers = getattr(req, "headers", None) or {}
                            auth = self._extract_auth_from_headers(headers)
                            auth2 = self._normalize_authorization_header(auth)
                            if auth2:
                                captured_auth["auth"] = auth2
                                captured_auth["src"] = "request:backend"
                        except Exception:
                            return

                    try:
                        page.on("request", _maybe_capture_auth)
                    except Exception:
                        pass

                    def _record_backend_response(resp) -> None:
                        try:
                            url = getattr(resp, "url", "") or ""
                            if not url.startswith(self.BACKEND_ORIGIN):
                                return
                            if len(backend_recent) >= 25:
                                return
                            backend_recent.append(
                                {
                                    "status": getattr(resp, "status", None),
                                    "url": url[:120],
                                }
                            )
                        except Exception:
                            return

                    try:
                        page.on("response", _record_backend_response)
                    except Exception:
                        pass

                    try:
                        print(f"ℹ️ {self.account_name}: Gift page URL: {page.url}")
                        t = await page.title()
                        if t:
                            print(f"ℹ️ {self.account_name}: Gift page title: {t[:80]}")
                    except Exception:
                        pass

                    # 打印 gift/backend cookie 名称（不打印 value）
                    try:
                        ck = await context.cookies([self.GIFT_ORIGIN, self.BACKEND_ORIGIN])
                        ck_names = sorted({str(x.get('name') or '') for x in (ck or []) if x.get('name')})
                        if ck_names:
                            print(f"ℹ️ {self.account_name}: Gift/backend cookies: {', '.join(ck_names[:25])}")
                    except Exception:
                        pass

                    # 打印存储中疑似 token 相关 key（不打印 value）
                    try:
                        keys = await page.evaluate(
                            """() => {
                                const pick = (st) => {
                                    const out = [];
                                    for (let i = 0; i < st.length; i++) {
                                        const k = st.key(i);
                                        if (!k) continue;
                                        const low = k.toLowerCase();
                                        if (low.includes('token') || low.includes('auth') || low.includes('jwt')) out.push(k);
                                    }
                                    return out.slice(0, 25);
                                };
                                return { local: pick(localStorage), session: pick(sessionStorage) };
                            }"""
                        )
                        if keys and isinstance(keys, dict):
                            local_keys = keys.get("local") or []
                            session_keys = keys.get("session") or []
                            if local_keys:
                                print(f"ℹ️ {self.account_name}: Gift localStorage token-like keys: {local_keys}")
                            if session_keys:
                                print(f"ℹ️ {self.account_name}: Gift sessionStorage token-like keys: {session_keys}")
                    except Exception:
                        pass

                    # Best practice：只信任 gift 页自身的登录态/真实请求里拿到的 token；其他来源一律先验证再使用。
                    candidates: list[tuple[str, str]] = []

                    if captured_auth.get("auth"):
                        candidates.append((captured_auth.get("src") or "request:backend", captured_auth["auth"]))

                    req_auth = await self._try_capture_backend_authorization_header(page, timeout_ms=4000)
                    if req_auth:
                        candidates.append(("wait_for_request:backend", req_auth))

                    gift_storage_auth, gift_storage_src = await self._try_extract_authorization_from_storage_debug(page)
                    if gift_storage_auth:
                        candidates.append((gift_storage_src or "gift_storage", gift_storage_auth))

                    gift_cookie_js = await self._try_extract_authorization_from_cookie(page)
                    if gift_cookie_js:
                        candidates.append(("document.cookie", gift_cookie_js))

                    gift_cookie_ctx, gift_cookie_ctx_src = await self._try_extract_authorization_from_context_cookies(context)
                    if gift_cookie_ctx:
                        candidates.append((gift_cookie_ctx_src or "context.cookies", gift_cookie_ctx))

                    # 最后才尝试 api 侧 token，并且必须通过校验
                    if api_side_auth_header:
                        candidates.append((api_side_auth_src or "api_storage", api_side_auth_header))

                    chosen_auth: str | None = None
                    chosen_src: str | None = None
                    chosen_status: dict = {}

                    # 先用“状态接口”校验 token，避免拿错 token 直接导致 401 invalid token
                    max_attempts = 12
                    attempts = 0
                    for src, cand in candidates:
                        for v in self._expand_auth_header_variants(cand):
                            attempts += 1
                            ok_auth, st_resp = await self._validate_gift_auth_header(page, v)
                            st_code = (st_resp or {}).get("status")
                            err_msg = ""
                            try:
                                d = (st_resp or {}).get("data")
                                if isinstance(d, dict):
                                    err_msg = str(d.get("error") or d.get("message") or "")
                                else:
                                    err_msg = str(d or "")
                            except Exception:
                                err_msg = ""
                            print(
                                f"ℹ️ {self.account_name}: Gift auth validate: src={src}, status={st_code}, "
                                f"auth={self._mask_secret(v)}, err={str(err_msg)[:80]}"
                            )
                            if ok_auth:
                                chosen_auth = v
                                chosen_src = src
                                chosen_status = st_resp or {}
                                break
                            if attempts >= max_attempts:
                                break
                        if chosen_auth or attempts >= max_attempts:
                            break

                    # 如果都失败，尝试一次 reload 触发前端刷新 token，再重复一次捕获/校验
                    if not chosen_auth:
                        print(f"⚠️ {self.account_name}: No valid gift token yet, reloading gift page to refresh session/token...")
                        try:
                            await page.reload(wait_until="domcontentloaded")
                            await page.wait_for_timeout(2500)
                        except Exception:
                            pass
                        # 重新抓一轮
                        req_auth2 = await self._try_capture_backend_authorization_header(page, timeout_ms=5000)
                        gift_storage_auth2, gift_storage_src2 = await self._try_extract_authorization_from_storage_debug(page)
                        retry_candidates: list[tuple[str, str]] = []
                        if req_auth2:
                            retry_candidates.append(("reload:wait_for_request", req_auth2))
                        if gift_storage_auth2:
                            retry_candidates.append((f"reload:{gift_storage_src2 or 'gift_storage'}", gift_storage_auth2))
                        gift_cookie_ctx2, gift_cookie_ctx_src2 = await self._try_extract_authorization_from_context_cookies(context)
                        if gift_cookie_ctx2:
                            retry_candidates.append((f"reload:{gift_cookie_ctx_src2 or 'context.cookies'}", gift_cookie_ctx2))
                        for src, cand in retry_candidates:
                            for v in self._expand_auth_header_variants(cand):
                                ok_auth, st_resp = await self._validate_gift_auth_header(page, v)
                                st_code = (st_resp or {}).get("status")
                                err_msg = ""
                                try:
                                    d = (st_resp or {}).get("data")
                                    if isinstance(d, dict):
                                        err_msg = str(d.get("error") or d.get("message") or "")
                                    else:
                                        err_msg = str(d or "")
                                except Exception:
                                    err_msg = ""
                                print(
                                    f"ℹ️ {self.account_name}: Gift auth validate (reload): src={src}, status={st_code}, "
                                    f"auth={self._mask_secret(v)}, err={str(err_msg)[:80]}"
                                )
                                if ok_auth:
                                    chosen_auth = v
                                    chosen_src = src
                                    chosen_status = st_resp or {}
                                    break
                            if chosen_auth:
                                break

                    if chosen_auth:
                        print(f"✅ {self.account_name}: Gift/backend Authorization selected from {chosen_src}")
                    else:
                        print(
                            f"⚠️ {self.account_name}: No valid Authorization token detected for gift/backend; "
                            "backend will likely return 401"
                        )
                        if backend_recent:
                            print(f"ℹ️ {self.account_name}: Recent backend responses: {backend_recent[:10]}")

                    # 检查签到状态（使用通过校验的 token）
                    checkin_status = chosen_status or await self._get_gift_checkin_status_with_auth(
                        page, auth_header=chosen_auth
                    )
                    print(
                        f"ℹ️ {self.account_name}: Checkin status: status={(checkin_status or {}).get('status')}, "
                        f"data={str((checkin_status or {}).get('data'))[:160]}"
                    )

                    # 执行签到：优先走后端 fetch（可控），拿不到/校验不过则回退 UI 流程（更贴近站点真实逻辑）
                    if not chosen_auth:
                        print(f"⚠️ {self.account_name}: No validated Authorization for backend, trying UI checkin fallback...")
                        checkin_ok, redemption_code, gift_msg = await self._try_gift_ui_checkin(page)
                        print(
                            f"ℹ️ {self.account_name}: UI checkin result: ok={checkin_ok}, msg={gift_msg}, "
                            f"code={(redemption_code[:12] + '...' if redemption_code and len(redemption_code) > 12 else redemption_code)}"
                        )
                    else:
                        checkin_ok, redemption_code, gift_msg = await self._do_gift_checkin_with_auth(
                            page, auth_header=chosen_auth
                        )
                    # 如果仍然是 401 invalid token，尝试点击 gift 页面按钮触发其内部流程刷新 token，再重试一次 fetch
                    try:
                        status0 = int((checkin_status or {}).get("status", 0) or 0)
                    except Exception:
                        status0 = 0
                    if (not checkin_ok) and (status0 == 401 or "invalid token" in str(gift_msg).lower()):
                        print(f"⚠️ {self.account_name}: Backend token rejected, trying UI checkin to refresh token/session...")
                        ui_ok, ui_code, ui_msg = await self._try_gift_ui_checkin(page)
                        print(
                            f"ℹ️ {self.account_name}: UI checkin retry result: ok={ui_ok}, msg={ui_msg}, "
                            f"code={(ui_code[:12] + '...' if ui_code and len(ui_code) > 12 else ui_code)}"
                        )
                        if ui_ok:
                            checkin_ok, redemption_code, gift_msg = True, ui_code, ui_msg
                        else:
                            retry_auth = await self._try_click_gift_checkin_and_capture_auth(page, timeout_ms=8000)
                            if retry_auth:
                                print(
                                    f"ℹ️ {self.account_name}: Captured Authorization via gift button, retrying checkin: "
                                    f"{self._mask_secret(retry_auth)}"
                                )
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
                        await self._safe_goto(
                            page,
                            f"{self.API_ORIGIN}/console",
                            wait_until="domcontentloaded",
                            retries=3,
                            expected_prefixes=[f"{self.API_ORIGIN}/console", f"{self.API_ORIGIN}/login"],
                        )
                        await page.wait_for_timeout(1000)
                        current_api_user = await self._extract_api_user_from_localstorage(page)

                    # 补取兑换码：有些情况下 /api/checkin 不直接返回 code，需要从 /api/records 查
                    if (not redemption_code) and chosen_auth and results.get("gift_checkin"):
                        for attempt in range(3):
                            rec_resp = await self._get_gift_records(page, auth_header=chosen_auth)
                            try:
                                rec_status = int((rec_resp or {}).get("status", 0) or 0)
                            except Exception:
                                rec_status = 0
                            if rec_status == 200:
                                payload = (rec_resp or {}).get("data")
                                if isinstance(payload, dict) and payload.get("success") is False:
                                    break
                                redemption_code = self._extract_redeem_code_from_records_payload(payload) or ""
                                if redemption_code:
                                    print(
                                        f"ℹ️ {self.account_name}: Found redemption code from gift records: "
                                        f"{self._mask_secret(redemption_code)}"
                                    )
                                    break
                            await page.wait_for_timeout(1200 * (attempt + 1))

                    if redemption_code:
                        print(f"ℹ️ {self.account_name}: Redeeming code: {self._mask_secret(redemption_code)}")
                        redeem_ok = await self._redeem_code_on_api(page, redemption_code, current_api_user)
                        results["code_redeem"] = redeem_ok
                    else:
                        print(f"ℹ️ {self.account_name}: No new code to redeem")
                        results["code_redeem"] = True

                    # 步骤4: 获取最终余额
                    await self._safe_goto(
                        page,
                        f"{self.API_ORIGIN}/console",
                        wait_until="domcontentloaded",
                        retries=3,
                        expected_prefixes=[f"{self.API_ORIGIN}/console", f"{self.API_ORIGIN}/login"],
                    )
                    await page.wait_for_timeout(1000)
                    if not current_api_user:
                        current_api_user = await self._extract_api_user_from_localstorage(page)
                    final_balance = await self._get_user_balance(page, current_api_user)
                    if final_balance:
                        results["balance"] = final_balance.get("quota", 0)
                        results["used_quota"] = final_balance.get("used_quota", 0)
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
