#!/usr/bin/env python3
"""
CheckIn 类
"""

import json
import hashlib
import os
import re
import tempfile
import time
from datetime import datetime
from urllib.parse import urlparse, parse_qs, quote

import httpx
from camoufox.async_api import AsyncCamoufox
from utils.config import AccountConfig, ProviderConfig
from utils.browser_utils import parse_cookies, get_random_user_agent

# 复用 LinuxDoSignIn 中的 playwright-captcha 解决方案（如果可用）
try:  # pragma: no cover - 仅在存在 playwright-captcha 时生效
    from sign_in_with_linuxdo import solve_captcha as linuxdo_solve_captcha  # type: ignore
except Exception:  # pragma: no cover - 可选依赖缺失时静默跳过
    linuxdo_solve_captcha = None


class CheckIn:
    """newapi.ai 签到管理类"""

    FULI_ORIGIN = "https://fuli.hxi.me"
    FULI_LOGIN_URL = "https://fuli.hxi.me/login"
    FULI_WHEEL_URL = "https://fuli.hxi.me/wheel"

    def __init__(
        self,
        account_name: str,
        account_config: AccountConfig,
        provider_config: ProviderConfig,
        global_proxy: dict | None = None,
        storage_state_dir: str = "storage-states",
    ):
        """初始化签到管理器

        Args:
                account_info: account 用户配置
                proxy_config: 全局代理配置(可选)
        """
        self.account_name = account_name
        self.safe_account_name = "".join(c if c.isalnum() else "_" for c in account_name)
        self.account_config = account_config
        self.provider_config = provider_config

        # 代理优先级: 账号配置 > 全局配置
        self.camoufox_proxy_config = account_config.proxy if account_config.proxy else global_proxy
        # httpx.Client proxy 转换
        self.http_proxy_config = self._get_http_proxy(self.camoufox_proxy_config)

        # storage-states 目录
        self.storage_state_dir = storage_state_dir

        os.makedirs(self.storage_state_dir, exist_ok=True)

        # 为整个会话生成固定的 User-Agent，避免同一会话中 UA 变化触发风控
        self.user_agent = get_random_user_agent()

    @staticmethod
    def _mask_code(code: str) -> str:
        if not code:
            return ""
        if len(code) <= 12:
            return code
        return f"{code[:6]}...{code[-4:]}"

    def _mask_codes(self, codes: list[str]) -> str:
        if not codes:
            return "[]"
        return "[" + ", ".join(self._mask_code(c) for c in codes) + "]"

    @staticmethod
    def _get_http_proxy(proxy_config: dict | None = None) -> httpx.URL | None:
        """将 proxy_config 转换为 httpx.URL 格式的代理 URL

        proxy_config 格式:
        {
            'server': 'http://example.com:8080',
            'username': 'username',
            'password': 'password'
        }

        Returns:
            httpx.URL 格式的代理对象，如果没有配置代理则返回 None
        """
        if not proxy_config:
            return None

        # proxy_config 是字典格式，提取 server 字段
        proxy_url = proxy_config.get("server")
        if not proxy_url:
            return None

        # 如果有用户名和密码，将其嵌入到 URL 中
        username = proxy_config.get("username")
        password = proxy_config.get("password")

        if username and password:
            # 解析原始 URL
            parsed = httpx.URL(proxy_url)
            # 重新构建包含认证信息的 URL
            return parsed.copy_with(username=username, password=password)

        # 转换为 httpx.URL 对象
        return httpx.URL(proxy_url)

    # Cloudflare 相关 cookie 名称（注意：不要缓存站点业务 session，避免用过期 session 覆盖有效登录态）
    CF_COOKIE_NAMES: set[str] = {"cf_clearance", "_cfuvid", "__cf_bm"}

    def _get_api_user_header_keys(self) -> list[str]:
        """返回当前 provider 可能使用的 api_user header 名称列表（按优先级去重）。

        说明：
        - new-api 系站点通常使用 `new-api-user`（或大小写变体）。
        - 旧的 Veloera 系站点使用 `Veloera-User`。
        - runanytime/elysiver 近期站点实现可能切换，故做兼容。
        """
        keys: list[str] = [self.provider_config.api_user_key]

        # runanytime/elysiver 可能在不同实现间切换，额外注入常见 header 名
        if self.provider_config.name in {"runanytime", "elysiver"}:
            keys.extend(["new-api-user", "New-Api-User", "Veloera-User"])

        # 去重（按 header 名大小写不敏感）
        seen: set[str] = set()
        uniq: list[str] = []
        for key in keys:
            low = key.lower()
            if low in seen:
                continue
            seen.add(low)
            uniq.append(key)
        return uniq

    def _inject_api_user_headers(self, headers: dict, api_user_value: str | int) -> None:
        """在 headers 中注入 api_user 标识头（兼容多个实现）。"""
        value = str(api_user_value)
        for key in self._get_api_user_header_keys():
            headers[key] = value

    def _get_cf_cookie_cache_path(self) -> str:
        """生成当前账号 + provider 对应的 Cloudflare cookie 缓存文件路径"""
        provider_name = getattr(self.provider_config, "name", "provider")
        filename = f"cf_{provider_name}_{self.safe_account_name}_cookies.json"
        return os.path.join(self.storage_state_dir, filename)

    def _filter_cf_cookies_for_cache(self, cookies: list[dict]) -> list[dict]:
        """从浏览器/httpx cookies 中筛选出需要缓存的 Cloudflare 相关 cookie"""
        filtered: list[dict] = []
        for cookie in cookies:
            name = cookie.get("name")
            if not name or name not in self.CF_COOKIE_NAMES:
                continue
            filtered.append(
                {
                    "name": name,
                    "value": cookie.get("value", ""),
                    "domain": cookie.get("domain"),
                    "path": cookie.get("path", "/"),
                    "expires": cookie.get("expires"),
                    "secure": cookie.get("secure", False),
                    "httpOnly": cookie.get("httpOnly", False),
                    "sameSite": cookie.get("sameSite", "Lax"),
                }
            )
        return filtered

    def _save_cf_cookies_to_cache(self, cookies: list[dict]) -> None:
        """将 Cloudflare 相关 cookie 持久化到本地文件，供下次运行复用"""
        try:
            cf_cookies = self._filter_cf_cookies_for_cache(cookies)
            if not cf_cookies:
                return

            cache_path = self._get_cf_cookie_cache_path()
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(cf_cookies, f, ensure_ascii=False)

            print(
                f"ℹ️ {self.account_name}: Saved {len(cf_cookies)} Cloudflare cookies to cache: {cache_path}"
            )
        except Exception as e:
            print(f"⚠️ {self.account_name}: Failed to save Cloudflare cookies cache: {e}")

    def _load_cf_cookies_from_cache(self) -> list[dict] | None:
        """从本地文件加载 Cloudflare 相关 cookie，供 httpx 直接复用"""
        cache_path = self._get_cf_cookie_cache_path()
        if not os.path.exists(cache_path):
            return None

        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                # 兼容旧缓存：历史版本可能把 session 也写入缓存，这里强制按白名单过滤
                filtered = [c for c in data if isinstance(c, dict) and c.get("name") in self.CF_COOKIE_NAMES]
                print(
                    f"ℹ️ {self.account_name}: Loaded {len(filtered)} Cloudflare cookies from cache: {cache_path}"
                )
                return filtered
        except Exception as e:
            print(f"⚠️ {self.account_name}: Failed to load Cloudflare cookies cache: {e}")
        return None

    def _apply_cf_cookies_to_client(self, client: httpx.Client, cookies: list[dict]) -> None:
        """将缓存的 Cloudflare 相关 cookie 注入到 httpx Client 中"""
        if not cookies:
            return

        parsed_domain = urlparse(self.provider_config.origin).netloc
        applied = 0
        for cookie in cookies:
            name = cookie.get("name")
            value = cookie.get("value")
            if not name or value is None:
                continue

            domain = cookie.get("domain") or parsed_domain
            path = cookie.get("path") or "/"
            try:
                client.cookies.set(name, value, domain=domain, path=path)
                applied += 1
            except Exception as e:
                print(f"⚠️ {self.account_name}: Failed to apply cached cookie {name}: {e}")

        if applied:
            print(
                f"ℹ️ {self.account_name}: Applied {applied} cached Cloudflare cookies to httpx client"
            )

    @staticmethod
    def _get_origin_host(origin: str) -> str:
        parsed = urlparse(origin)
        if parsed.hostname:
            return parsed.hostname
        return origin.replace("https://", "").replace("http://", "").split("/")[0]

    @classmethod
    def _cookie_dict_to_browser_cookies(cls, cookie_dict: dict, origin: str) -> list[dict]:
        domain = cls._get_origin_host(origin)
        cookies = []
        for name, value in (cookie_dict or {}).items():
            cookies.append(
                {
                    "name": str(name),
                    "value": str(value),
                    "domain": domain,
                    "path": "/",
                }
            )
        return cookies

    @staticmethod
    def _extract_exchange_codes(text: str) -> list[str]:
        if not text:
            return []

        codes: list[str] = []

        # 优先抓取 “兑换码：XXXX” 一类的结构
        # 注意：部分站点兑换码可能包含下划线（_），这里做兼容。
        for match in re.findall(r"(?:兑换码|兑奖码|激活码|兑换券)[:：\\s]*([A-Za-z0-9_-]{6,128})", text):
            if match and match not in codes:
                codes.append(match)

        # 兜底：抓取高置信度的长 token（避免把普通数字/日期误判为兑换码）
        for match in re.findall(r"\\b[A-Za-z0-9][A-Za-z0-9_-]{11,127}\\b", text):
            if match and match not in codes:
                codes.append(match)

        return codes

    async def _extract_exchange_codes_from_page(self, page) -> list[str]:
        """从页面中提取兑换码（兼容兑换码在 input.value 中的情况）。"""
        try:
            combined = await page.evaluate(
                """() => {
                    const parts = [];

                    // 重点兼容：弹窗里兑换码经常在 <p class="font-mono ..."> 或纯文本块中展示。
                    // 注意：把弹窗内容优先放到前面，避免页面“抽奖记录/历史记录”里的旧兑换码抢先匹配。
                    try {
                        const dialogs = Array.from(document.querySelectorAll('div'));
                        const dialog = dialogs.find(d => {
                            const t = (d.innerText || '').trim();
                            return t.includes('兑换码') && (t.includes('复制兑换码') || t.includes('复制') || t.includes('关闭'));
                        });
                        if (dialog) {
                            const mono = dialog.querySelector('p.font-mono') || dialog.querySelector('[class*=\"font-mono\"]');
                            if (mono && (mono.innerText || '').trim()) parts.push((mono.innerText || '').trim());
                            const t = (dialog.innerText || '').trim();
                            if (t) parts.push(t);
                        }
                    } catch (e) {}

                    try {
                        const inputs = Array.from(document.querySelectorAll('input, textarea'));
                        for (const el of inputs) {
                            const v = el && typeof el.value === 'string' ? el.value.trim() : '';
                            if (v) parts.push(v);
                        }
                    } catch (e) {}

                    try {
                        const bodyText = document.body ? (document.body.innerText || document.body.textContent || '') : '';
                        if (bodyText) parts.push(bodyText);
                    } catch (e) {}

                    return parts.join('\\n');
                }"""
            )
        except Exception:
            combined = ""

        return self._extract_exchange_codes(combined or "")

    async def _maybe_solve_cloudflare_interstitial(self, page) -> None:
        if linuxdo_solve_captcha is None:
            return
        try:
            await linuxdo_solve_captcha(page, captcha_type="cloudflare", challenge_type="interstitial")
            await page.wait_for_timeout(3000)
        except Exception:
            pass

    async def _maybe_solve_cloudflare_turnstile(self, page) -> None:
        if linuxdo_solve_captcha is None:
            return
        try:
            await linuxdo_solve_captcha(page, captcha_type="cloudflare", challenge_type="turnstile")
            await page.wait_for_timeout(3000)
        except Exception:
            pass

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

    async def _browser_fetch_json(
        self,
        page,
        url: str,
        *,
        method: str = "GET",
        headers: dict | None = None,
        json_body: dict | None = None,
    ) -> dict:
        """在浏览器上下文内发起 fetch（带 cookies），并尽量解析 JSON。

        返回结构：
        - ok: bool
        - status: int
        - text: str
        - json: dict | list | None
        - content_type: str
        """
        headers = headers or {}
        try:
            resp = await page.evaluate(
                """async ({ url, method, headers, jsonBody }) => {
                    try {
                        const init = { method, credentials: 'include', headers: headers || {} };
                        if (jsonBody !== undefined && jsonBody !== null) {
                            init.headers = { 'Content-Type': 'application/json', ...(init.headers || {}) };
                            init.body = JSON.stringify(jsonBody);
                        }
                        const r = await fetch(url, init);
                        const ct = r.headers.get('content-type') || '';
                        const text = await r.text();
                        let parsed = null;
                        if (ct.includes('application/json')) {
                            try { parsed = JSON.parse(text); } catch (e) { parsed = null; }
                        }
                        return { ok: r.ok, status: r.status, text, json: parsed, contentType: ct };
                    } catch (e) {
                        return { ok: false, status: 0, text: String(e), json: null, contentType: '' };
                    }
                }""",
                {"url": url, "method": method, "headers": headers, "jsonBody": json_body},
            )
        except Exception as e:
            return {"ok": False, "status": 0, "text": str(e), "json": None, "content_type": ""}

        return {
            "ok": bool((resp or {}).get("ok")),
            "status": int((resp or {}).get("status", 0) or 0),
            "text": str((resp or {}).get("text") or ""),
            "json": (resp or {}).get("json"),
            "content_type": str((resp or {}).get("contentType") or ""),
        }

    async def _ensure_page_past_cloudflare(self, page, *, timeout_ms: int = 45000) -> bool:
        """尽量等待/处理 Cloudflare interstitial，避免后续 fetch 一直 403/503。"""
        deadline = time.monotonic() + max(timeout_ms, 1) / 1000
        attempted = False
        while time.monotonic() < deadline:
            try:
                url = page.url or ""
            except Exception:
                url = ""
            try:
                title = await page.title()
            except Exception:
                title = ""

            # 轻量判断：URL/标题/小片段 HTML
            is_cf = ("challenges.cloudflare.com" in url) or ("Just a moment" in (title or ""))
            if not is_cf:
                try:
                    snippet = await page.evaluate(
                        """() => {
                            try {
                                const t = document.title || '';
                                const b = document.body ? (document.body.innerText || '') : '';
                                return (t + '\\n' + b).slice(0, 800);
                            } catch (e) {
                                return '';
                            }
                        }"""
                    )
                except Exception:
                    snippet = ""
                is_cf = self._looks_like_cloudflare_interstitial_html(snippet or "")

            if not is_cf:
                return True

            if not attempted:
                attempted = True
                await self._maybe_solve_cloudflare_interstitial(page)
                await self._maybe_solve_cloudflare_turnstile(page)

            try:
                await page.wait_for_timeout(1000)
            except Exception:
                break
        return False

    async def _linuxdo_login_if_needed(self, page, linuxdo_username: str, linuxdo_password: str) -> None:
        """在 linux.do 登录页（若出现）自动填表提交，兼容近期 selector 变更。"""
        try:
            u = page.url or ""
        except Exception:
            u = ""
        if "linux.do/login" not in u:
            return

        # linux.do 登录页可能出现 Turnstile/Interstitial
        try:
            if linuxdo_solve_captcha is not None:
                try:
                    await linuxdo_solve_captcha(page, captcha_type="cloudflare", challenge_type="interstitial")
                except Exception:
                    pass
                # Turnstile solver 的开关逻辑由 sign_in_with_linuxdo.solve_captcha 内部统一处理
                try:
                    await linuxdo_solve_captcha(page, captcha_type="cloudflare", challenge_type="turnstile")
                except Exception:
                    pass
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
                await page.keyboard.press("Enter")
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
                timeout=30000,
            )
        except Exception:
            await self._take_screenshot(page, "linuxdo_login_timeout")
            raise RuntimeError("linux.do 登录提交超时")

    async def _ensure_fuli_logged_in(self, page, linuxdo_username: str, linuxdo_password: str) -> None:
        # 先尝试直接打开主页，若已登录则无需走 OAuth
        try:
            await page.goto(self.FULI_ORIGIN, wait_until="networkidle")
            # 解决 Cloudflare 验证码
            await self._maybe_solve_cloudflare_interstitial(page)
            if linuxdo_solve_captcha is not None:
                try:
                    await linuxdo_solve_captcha(page, captcha_type="cloudflare", challenge_type="turnstile")
                except Exception:
                    pass
            await page.wait_for_timeout(1000)
            has_nav = await page.evaluate(
                """() => {
                    const text = document.body ? (document.body.innerText || '') : '';
                    return text.includes('每日签到') || text.includes('幸运转盘') || text.includes('转盘');
                }"""
            )
            if has_nav and page.url.startswith(self.FULI_ORIGIN):
                print(f"ℹ️ {self.account_name}: fuli already logged in (url={page.url})")
                return
        except Exception:
            pass

        await page.goto(self.FULI_LOGIN_URL, wait_until="networkidle")
        await self._maybe_solve_cloudflare_interstitial(page)
        if linuxdo_solve_captcha is not None:
            try:
                await linuxdo_solve_captcha(page, captcha_type="cloudflare", challenge_type="turnstile")
            except Exception:
                pass
        print(f"ℹ️ {self.account_name}: fuli login page opened (url={page.url})")

        # 点击 “使用 Linux Do 登录”
        try:
            login_btn = await page.query_selector('button:has-text("使用 Linux Do 登录")')
            if login_btn:
                await login_btn.click()
        except Exception:
            pass

        await page.wait_for_timeout(1200)
        await self._maybe_solve_cloudflare_interstitial(page)
        print(f"ℹ️ {self.account_name}: fuli after login click (url={page.url})")

        # 处理 Linux.do 登录（可能因为缓存已登录而跳过）
        try:
            await self._linuxdo_login_if_needed(page, linuxdo_username, linuxdo_password)

            # 授权页：点击“允许”
            if "connect.linux.do/oauth2/authorize" in page.url:
                try:
                    await page.wait_for_selector('a[href^="/oauth2/approve"]', timeout=30000)
                    allow_btn = await page.query_selector('a[href^="/oauth2/approve"]')
                    if allow_btn:
                        await allow_btn.click()
                except Exception:
                    pass
                print(f"ℹ️ {self.account_name}: fuli linux.do approve clicked (url={page.url})")

            # 回到 fuli 主站
            try:
                await page.wait_for_url(f"**{self.FULI_ORIGIN}/**", timeout=30000)
            except Exception:
                await page.goto(self.FULI_ORIGIN, wait_until="networkidle")
            print(f"ℹ️ {self.account_name}: fuli login finished (url={page.url})")
        except Exception as e:
            print(f"⚠️ {self.account_name}: fuli 登录流程可能未完全成功: {e}")

    async def _runanytime_fetch_user_self_raw(self, page, api_user: str | int) -> dict:
        """在浏览器同源上下文里 fetch /api/user/self，返回 {status,text}。"""
        try:
            headers = {k: str(api_user) for k in self._get_api_user_header_keys()}
            headers.setdefault("Accept", "application/json, text/plain, */*")
            resp = await page.evaluate(
                """async ({ headers }) => {
                    try {
                        const r = await fetch('/api/user/self', { credentials: 'include', headers });
                        const t = await r.text();
                        return { status: r.status, text: t };
                    } catch (e) {
                        return { status: 0, text: String(e) };
                    }
                }""",
                {"headers": headers},
            )
            if isinstance(resp, dict):
                return resp
            return {"status": 0, "text": str(resp)}
        except Exception as e:
            return {"status": 0, "text": str(e)}

    async def _ensure_runanytime_logged_in(
        self,
        page,
        linuxdo_username: str,
        linuxdo_password: str,
        api_user: str | int | None = None,
    ) -> None:
        """确保 runanytime 已登录（否则余额/API 会 401）。

        站点是 New-API SPA：未登录时访问 `/console` 往往会跳回 `/login`，而 `/api/user/self`
        会报“未登录且未提供 access token”。
        """
        origin = (self.provider_config.origin or "").rstrip("/")
        if not origin:
            return

        async def _looks_like_login_page() -> bool:
            try:
                if "/login" in (page.url or ""):
                    return True
            except Exception:
                pass
            try:
                t = await page.evaluate(
                    "() => document.body ? (document.body.innerText || document.body.textContent || '') : ''"
                )
            except Exception:
                t = ""
            if "登 录" in (t or "") and "使用 LinuxDO" in (t or ""):
                return True
            return False

        async def _is_logged_in() -> bool:
            try:
                t = await page.evaluate(
                    "() => document.body ? (document.body.innerText || document.body.textContent || '') : ''"
                )
            except Exception:
                t = ""
            # 明确的过期/未登录提示
            if "未登录或登录已过期" in (t or "") or "expired=true" in (page.url or ""):
                return False
            if await _looks_like_login_page():
                return False
            # 只要没落到登录页，就先视为“可能已登录”；最终用 /api/user/self（带 new-api-user）确认
            return True

        # 1) 快速探测：如果已登录则直接返回
        try:
            print(f"ℹ️ {self.account_name}: checking runanytime login status at {origin}/console")
            await page.goto(f"{origin}/console", wait_until="domcontentloaded")
            await self._maybe_solve_cloudflare_interstitial(page)
            await page.wait_for_timeout(600)
            if await _is_logged_in():
                if api_user is not None:
                    raw = await self._runanytime_fetch_user_self_raw(page, api_user)
                    status = int(raw.get("status", 0) or 0)
                    if status == 200:
                        print(f"ℹ️ {self.account_name}: runanytime session ok via /api/user/self (url={page.url})")
                        return
                    # 401：典型是 session 失效/未登录
                    if status == 401:
                        print(
                            f"⚠️ {self.account_name}: runanytime /api/user/self=401, will re-login (url={page.url})"
                        )
                    else:
                        print(
                            f"⚠️ {self.account_name}: runanytime /api/user/self HTTP {status}, will try re-login"
                        )
                else:
                    print(f"ℹ️ {self.account_name}: runanytime page accessible (url={page.url})")
                    return
            if "/login" not in (page.url or "") and page.url.startswith(origin):
                # 某些情况下首页/控制台会懒加载，给一点时间
                try:
                    await page.wait_for_function(
                        """() => {
                            const t = document.body ? (document.body.innerText || document.body.textContent || '') : '';
                            return t.includes('当前余额') && t.includes('历史消耗');
                        }""",
                        timeout=3000,
                    )
                except Exception:
                    pass
                if await _is_logged_in():
                    if api_user is not None:
                        raw = await self._runanytime_fetch_user_self_raw(page, api_user)
                        status = int(raw.get("status", 0) or 0)
                        if status == 200:
                            print(
                                f"ℹ️ {self.account_name}: runanytime session ok via /api/user/self after wait (url={page.url})"
                            )
                            return
        except Exception:
            pass

        # 2) 走登录页点击 Linux Do
        print(f"ℹ️ {self.account_name}: runanytime not logged in, start login flow")
        try:
            await page.goto(f"{origin}/login", wait_until="networkidle")
            await self._maybe_solve_cloudflare_interstitial(page)
        except Exception:
            # 某些 SPA 会一直 pending，退化到 domcontentloaded
            try:
                await page.goto(f"{origin}/login", wait_until="domcontentloaded")
            except Exception:
                return

        try:
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
                        break
                except Exception:
                    continue
            if login_btn:
                await login_btn.click()
            else:
                # 再兜底：从所有链接里找包含 linuxdo 的跳转
                try:
                    await page.evaluate(
                        """() => {
                            const a = Array.from(document.querySelectorAll('a')).find(x => {
                                const h = (x.getAttribute('href') || '').toLowerCase();
                                const t = (x.innerText || '').toLowerCase();
                                return h.includes('linuxdo') || t.includes('linux do') || t.includes('linuxdo');
                            });
                            if (a) a.click();
                        }"""
                    )
                except Exception:
                    pass
        except Exception:
            pass

        await page.wait_for_timeout(1200)
        await self._maybe_solve_cloudflare_interstitial(page)

        # 3) Linux.do 登录或授权
        try:
            if "linux.do/login" in (page.url or ""):
                await self._linuxdo_login_if_needed(page, linuxdo_username, linuxdo_password)

            # 授权页常见是 /oauth2/authorize，然后页面上有 approve 链接
            try:
                allow_btn = await page.query_selector('a[href^="/oauth2/approve"]')
                if allow_btn:
                    await allow_btn.click()
                else:
                    # 兜底：尝试点“授权/允许/Authorize”按钮
                    for sel in [
                        'button:has-text("授权")',
                        'button:has-text("允许")',
                        'button:has-text("Authorize")',
                        'button[type="submit"]',
                    ]:
                        try:
                            b = await page.query_selector(sel)
                            if b:
                                await b.click()
                                break
                        except Exception:
                            continue
            except Exception:
                pass
        except Exception as e:
            print(f"⚠️ {self.account_name}: runanytime Linux.do 登录/授权可能未完成: {e}")

        # 4) 回到 runanytime：如果落在前端 `/oauth/linuxdo?code=...`，补打一遍后端回调
        try:
            await page.wait_for_url(f"**{origin}/**", timeout=30000)
        except Exception:
            pass

    async def _seed_runanytime_local_storage_user(self, page, api_user: str | int) -> None:
        """为 runanytime/new-api 写入 localStorage.user。

        MCP 实测：当 localStorage 缺少 `user` 时，访问 `/console` 会直接跳到 `/login`；
        UI 也依赖 `user.id` 来拼接 `new-api-user` 请求头，否则余额会长期停留在 NaN。
        """
        try:
            await page.evaluate(
                """(apiUser) => {
                    try {
                        const key = 'user';
                        const cur = localStorage.getItem(key);
                        if (cur) return;
                        const id = typeof apiUser === 'string' ? parseInt(apiUser, 10) : apiUser;
                        const user = {
                            id: id,
                            username: `linuxdo_${id}`,
                            role: 1,
                            status: 1,
                            group: 'default',
                            display_name: 'None',
                        };
                        localStorage.setItem(key, JSON.stringify(user));
                    } catch (e) {}
                }""",
                str(api_user),
            )
        except Exception:
            pass

        try:
            origin = (self.provider_config.origin or "").rstrip("/")
            if not origin:
                return
            cur = page.url or ""
            if cur.startswith(origin) and "/oauth/linuxdo" in cur and "code=" in cur:
                parsed = urlparse(cur)
                qs = parse_qs(parsed.query)
                code = (qs.get("code") or [None])[0]
                state = (qs.get("state") or [None])[0]
                if code:
                    callback_url = f"{origin}/api/oauth/linuxdo?code={quote(str(code))}"
                    if state:
                        callback_url += f"&state={quote(str(state))}"
                    print(f"ℹ️ {self.account_name}: runanytime oauth front-route detected, calling callback: {callback_url}")
                    await page.goto(callback_url, wait_until="networkidle")
        except Exception:
            pass

        # 5) 最终确认
        try:
            await page.goto(f"{origin}/console", wait_until="domcontentloaded")
            await self._maybe_solve_cloudflare_interstitial(page)
            await page.wait_for_timeout(600)
            if api_user is not None:
                raw = await self._runanytime_fetch_user_self_raw(page, api_user)
                status = int(raw.get("status", 0) or 0)
                if status == 200:
                    print(f"ℹ️ {self.account_name}: runanytime login finished (api ok, url={page.url})")
                    return
            print(f"⚠️ {self.account_name}: runanytime login not confirmed (url={page.url})")
            await self._take_screenshot(page, "runanytime_login_not_confirmed")
        except Exception:
            pass

    async def _fuli_daily_checkin_get_code(self, page) -> tuple[bool, str | None, str]:
        """在 fuli 主站执行每日签到，返回 (是否完成, 兑换码, 提示信息)。"""
        await page.goto(self.FULI_ORIGIN, wait_until="networkidle")
        await self._maybe_solve_cloudflare_interstitial(page)
        if linuxdo_solve_captcha is not None:
            try:
                await linuxdo_solve_captcha(page, captcha_type="cloudflare", challenge_type="turnstile")
            except Exception:
                pass
        print(f"ℹ️ {self.account_name}: fuli check-in page opened (url={page.url})")

        # 抽取“操作前”页面已有的兑换码，用于后续 diff（避免历史记录里的旧码被误判为新码）
        try:
            before_codes = set(await self._extract_exchange_codes_from_page(page))
        except Exception:
            before_codes = set()

        # 已签到：按钮禁用
        try:
            already_btn = await page.query_selector('button:has-text("今日已签到")')
            if already_btn:
                return True, None, "今日已签到"
        except Exception:
            pass

        # 尝试长按“签到/长按”按钮
        target = None
        for selector in [
            'button:has-text("长按")',
            'button:has-text("签到")',
            "main button:not([disabled])",
            "main [role=\"button\"]:not([aria-disabled=\"true\"])",
        ]:
            try:
                ele = await page.query_selector(selector)
                if ele:
                    target = ele
                    break
            except Exception:
                continue

        if not target:
            await self._take_screenshot(page, "fuli_checkin_button_not_found")
            return False, None, "未找到签到按钮"

        try:
            box = await target.bounding_box()
            if not box:
                raise RuntimeError("签到按钮无法获取坐标")

            def _pick_code_from_payload(payload: dict) -> str:
                for k in ("code", "key", "exchangeCode", "exchange_code", "redeemCode", "redeem_code"):
                    v = payload.get(k)
                    if isinstance(v, str) and v.strip():
                        return v.strip()
                    if isinstance(v, (int, float)) and str(v).strip():
                        return str(v).strip()
                data = payload.get("data")
                if isinstance(data, dict):
                    return _pick_code_from_payload(data)
                if isinstance(data, str) and data.strip():
                    return data.strip()
                msg = payload.get("message") or payload.get("msg") or ""
                if isinstance(msg, str) and msg.strip():
                    codes = self._extract_exchange_codes(msg)
                    if codes:
                        return codes[0]
                return ""

            # 优先从“浏览器内的 API 响应”抓兑换码：比 DOM 稳（httpx 会被 CF 403，但浏览器通常能过）。
            resp_payload = None
            did_press = False
            async def _do_long_press() -> None:
                nonlocal did_press
                if did_press:
                    return
                await page.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
                await page.mouse.down()
                await page.wait_for_timeout(1600)
                await page.mouse.up()
                did_press = True

            if hasattr(page, "expect_response"):
                try:
                    async with page.expect_response(
                        lambda r: ("/api/checkin" in (r.url or "")) and ((r.request.method or "") == "POST"),
                        timeout=20000,
                    ) as resp_info:
                        await _do_long_press()
                    resp = await resp_info.value
                    try:
                        resp_payload = await resp.json()
                    except Exception:
                        resp_payload = None
                except Exception:
                    if not did_press:
                        try:
                            await _do_long_press()
                        except Exception:
                            pass
                    resp_payload = None
            else:
                await _do_long_press()

            if isinstance(resp_payload, dict):
                msg = resp_payload.get("message") or resp_payload.get("msg") or ""
                if resp_payload.get("success"):
                    code = _pick_code_from_payload(resp_payload)
                    if code:
                        print(f"✅ {self.account_name}: fuli daily check-in code found (api): {self._mask_code(code)}")
                        return True, code, "签到成功"
                if isinstance(msg, str) and msg and any(k in msg for k in ["already", "已经", "已签", "今日已签到"]):
                    return True, None, "今日已签到"

            # 等待兑换码弹窗/文案出现：不同实现可能“先切按钮再弹窗”或相反；用更稳的条件 + diff 兜底。
            try:
                before_list = list(before_codes)
                await page.wait_for_function(
                    """(beforeCodes) => {
                        try {
                            const body = document.body;
                            const text = (body ? (body.innerText || body.textContent || '') : '') || '';

                            if (text.includes('复制兑换码')) return true;
                            if (text.includes('恭喜获得')) return true;
                            if (text.includes('将在') && text.includes('秒后过期')) return true;

                            const tokens = text.match(/\\b[A-Za-z0-9][A-Za-z0-9_-]{11,127}\\b/g) || [];
                            const before = new Set((beforeCodes || []).map(String));
                            for (const tok of tokens) {
                              if (!before.has(tok)) return true;
                            }
                            return false;
                        } catch (e) {
                            return false;
                        }
                    }""",
                    before_list,
                    timeout=15000,
                )
            except Exception:
                pass

            # 轮询一小段时间，给 SPA/弹窗渲染留余量
            for _ in range(10):
                try:
                    after_codes = await self._extract_exchange_codes_from_page(page)
                except Exception:
                    after_codes = []
                new_codes = [c for c in after_codes if c not in before_codes]
                if new_codes:
                    code = new_codes[0]
                    print(f"✅ {self.account_name}: fuli daily check-in code found: {self._mask_code(code)}")
                    return True, code, "签到成功"
                await page.wait_for_timeout(500)

            # 再判断是否已变为“今日已签到”（有些情况下不会弹出/展示兑换码，但签到已生效）
            try:
                already_btn_after = await page.query_selector('button:has-text("今日已签到")')
                if already_btn_after:
                    return True, None, "今日已签到"
            except Exception:
                pass

            # 兜底：无法识别兑换码时，也不要直接判失败（站点 UI 可能变化或兑换码不再展示）
            print(f"⚠️ {self.account_name}: fuli daily check-in done but no code detected")
            return True, None, "已执行签到动作（未识别到兑换码）"
        except Exception as e:
            await self._take_screenshot(page, "fuli_checkin_error")
            # 异常时也尝试从页面捞一次兑换码，避免“弹窗出来了但脚本报错没记到”
            try:
                codes = await self._extract_exchange_codes_from_page(page)
                if codes:
                    print(
                        f"⚠️ {self.account_name}: fuli daily check-in error but code extracted: "
                        f"{self._mask_codes(codes)}"
                    )
                    return True, codes[0], "签到成功（异常兜底提取兑换码）"
            except Exception:
                pass
            return False, None, f"签到异常: {e}"

    async def _fuli_wheel_get_codes(self, page, max_times: int = 3) -> tuple[list[str], str]:
        """在 fuli 转盘抽奖，返回 (兑换码列表, 提示信息)。"""
        await page.goto(self.FULI_WHEEL_URL, wait_until="networkidle")
        await self._maybe_solve_cloudflare_interstitial(page)
        if linuxdo_solve_captcha is not None:
            try:
                await linuxdo_solve_captcha(page, captcha_type="cloudflare", challenge_type="turnstile")
            except Exception:
                pass
        print(f"ℹ️ {self.account_name}: fuli wheel page opened (url={page.url})")

        def _parse_remaining(text: str) -> tuple[int, int] | None:
            if not text:
                return None
            matches = re.findall(r"今日剩余\\s*(\\d+)\\s*/\\s*(\\d+)\\s*次", text)
            if not matches:
                return None
            pairs: list[tuple[int, int]] = []
            for r, t in matches:
                try:
                    pairs.append((int(r), int(t)))
                except Exception:
                    continue
            if not pairs:
                return None
            # 页面 hydration 前可能出现占位的 0/0，优先选择 total 最大的一组（通常是 /3）
            return max(pairs, key=lambda x: (x[1], x[0]))

        # 转盘页是 SPA，会先渲染“0/0 + 次数已用完”占位，稍后才更新为真实的“x/3 + 开始抽奖”
        # 这里先等到 total != 0（或至少出现开始按钮），避免误判“没有次数”。
        try:
            await page.wait_for_function(
                """() => {
                    const t = document.body ? (document.body.innerText || document.body.textContent || '') : '';
                    const m = t.match(/今日剩余\\s*(\\d+)\\s*\\/\\s*(\\d+)\\s*次/);
                    if (m && m[2] && m[2] !== '0') return true;
                    return t.includes('开始抽奖') || t.includes('次数已用完');
                }""",
                timeout=8000,
            )
        except Exception:
            pass

        remaining = None
        try:
            info_text = await page.evaluate(
                """() => {
                    const el = Array.from(document.querySelectorAll('p')).find(p => (p.innerText || '').includes('今日剩余'));
                    return el ? (el.innerText || '') : '';
                }"""
            )
            body_text = await page.evaluate("() => document.body ? (document.body.innerText || '') : ''")
            info_text = info_text or body_text
            parsed = _parse_remaining(info_text or "")
            if parsed:
                remaining = parsed[0]
        except Exception:
            remaining = None

        spins = remaining if remaining is not None else max_times
        spins = min(max_times, max(0, spins))
        if spins == 0:
            return [], "次数已用完"

        all_codes: list[str] = []
        attempted = 0
        for i in range(spins):
            try:
                # 每次循环刷新一次页面文本（次数会变化，且占位渲染可能在第一次读取时未更新）
                try:
                    body_text = await page.evaluate("() => document.body ? (document.body.innerText || '') : ''")
                except Exception:
                    body_text = ""

                # 保险：如果上一次弹窗还没关，先尝试关闭，避免挡住下一次按钮点击
                try:
                    close_btn = await page.query_selector('button:has-text("关闭")')
                    if close_btn:
                        await close_btn.click()
                        await page.wait_for_timeout(800)
                except Exception:
                    pass

                btn = None
                for selector in [
                    'button:has-text("开始抽奖")',
                    'button:has-text("抽奖")',
                    'button:has-text("开始")',
                    'button:has-text("抽")',
                    'button:has-text("转")',
                    "main [role=\"button\"]:not([aria-disabled=\"true\"])",
                ]:
                    try:
                        ele = await page.query_selector(selector)
                        if ele:
                            btn = ele
                            break
                    except Exception:
                        continue

                if not btn:
                    # 如果页面明确提示次数用完，直接按幂等成功处理
                    if "次数已用完" in (body_text or ""):
                        return all_codes, "次数已用完"
                    parsed_now = _parse_remaining(body_text or "")
                    if parsed_now and parsed_now[0] <= 0:
                        return all_codes, "次数已用完"

                    await self._take_screenshot(page, "fuli_wheel_button_not_found")
                    return all_codes, "未找到转盘按钮"

                # 抽奖前再抓一次（避免隐藏元素/历史记录造成误判）
                before_codes = set(await self._extract_exchange_codes_from_page(page))

                # 优先从“浏览器内的 API 响应”抓兑换码：比 DOM 稳（httpx 会被 CF 403，但浏览器通常能过）。
                wheel_payload = None
                did_click = False

                async def _do_click() -> None:
                    nonlocal did_click
                    if did_click:
                        return
                    try:
                        await btn.click()
                    except Exception:
                        # 有时按钮在 overlay 下无法 click，退化为坐标点击
                        box = await btn.bounding_box()
                        if not box:
                            raise
                        await page.mouse.click(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
                    did_click = True

                if hasattr(page, "expect_response"):
                    try:
                        async with page.expect_response(
                            lambda r: (
                                ("/api/wheel" in (r.url or ""))
                                and ("/api/wheel/status" not in (r.url or ""))
                                and ((r.request.method or "") == "POST")
                            ),
                            timeout=20000,
                        ) as resp_info:
                            await _do_click()
                        resp = await resp_info.value
                        try:
                            wheel_payload = await resp.json()
                        except Exception:
                            wheel_payload = None
                    except Exception:
                        if not did_click:
                            try:
                                await _do_click()
                            except Exception:
                                pass
                        wheel_payload = None
                else:
                    await _do_click()

                if isinstance(wheel_payload, dict) and wheel_payload.get("success"):
                    api_code = ""
                    for k in ("code", "key", "exchangeCode", "exchange_code", "redeemCode", "redeem_code"):
                        v = wheel_payload.get(k)
                        if isinstance(v, str) and v.strip():
                            api_code = v.strip()
                            break
                    if not api_code:
                        msg = wheel_payload.get("message") or wheel_payload.get("msg") or ""
                        if isinstance(msg, str) and msg.strip():
                            codes = self._extract_exchange_codes(msg)
                            if codes:
                                api_code = codes[0]
                    if api_code and api_code not in all_codes:
                        all_codes.append(api_code)
                attempted += 1

                # 等待开奖结果弹窗出现（或轮盘动画结束）。
                # 注意：转盘页的“抽奖记录”表头本身就包含“兑换码”文本，
                # 不能用 `text=兑换码` 作为等待条件，否则会立即返回而错过真正的结果弹窗。
                try:
                    before_list = list(before_codes)
                    await page.wait_for_function(
                        """(beforeCodes) => {
                            try {
                                const body = document.body;
                                const text = (body ? (body.innerText || body.textContent || '') : '') || '';

                                // 结果弹窗通常包含“恭喜获得/复制兑换码/关闭”等文本
                                if (text.includes('恭喜获得')) return true;
                                if (text.includes('复制兑换码')) return true;
                                if (text.includes('将在') && text.includes('秒后过期')) return true;

                                // 或者页面上出现“关闭”按钮（常见于结果弹窗）
                                const btnTexts = Array.from(document.querySelectorAll('button'))
                                  .map(b => (b.innerText || '').trim())
                                  .filter(Boolean);
                                if (btnTexts.some(t => t.includes('复制兑换码') || t === '关闭')) return true;

                                // 兜底：页面上出现了新的高置信 token（兑换码）
                                const tokens = text.match(/\\b[A-Za-z0-9][A-Za-z0-9_-]{11,127}\\b/g) || [];
                                const before = new Set((beforeCodes || []).map(String));
                                for (const tok of tokens) {
                                  if (!before.has(tok)) return true;
                                }
                                return false;
                            } catch (e) {
                                return false;
                            }
                        }""",
                        before_list,
                        timeout=20000,
                    )
                except Exception:
                    # 不强制失败，给一个保底等待
                    await page.wait_for_timeout(6500)

                after_codes = await self._extract_exchange_codes_from_page(page)
                new_codes = [c for c in after_codes if c not in before_codes and c not in all_codes]
                all_codes.extend(new_codes)
                if new_codes:
                    print(
                        f"✅ {self.account_name}: fuli wheel spin {i+1}/{spins} new code(s): "
                        f"{self._mask_codes(new_codes)}"
                    )
                else:
                    print(f"ℹ️ {self.account_name}: fuli wheel spin {i+1}/{spins} no new code detected")

                # 尝试关闭弹窗
                try:
                    for close_sel in [
                        'button:has-text("关闭")',
                        'button:has-text("确定")',
                        'button:has-text("取消")',
                    ]:
                        close_btn = await page.query_selector(close_sel)
                        if close_btn:
                            await close_btn.click()
                            break
                except Exception:
                    pass

                # 关闭弹窗后等待剩余次数文本更新，避免下一次循环拿到旧状态
                try:
                    await page.wait_for_timeout(800)
                except Exception:
                    pass
            except Exception:
                await self._take_screenshot(page, f"fuli_wheel_error_{i+1}")
                # 异常时也尝试把弹窗里的兑换码捞出来，避免“抽到了但没记到”
                try:
                    fallback_codes = await self._extract_exchange_codes_from_page(page)
                    for c in fallback_codes:
                        if c not in all_codes:
                            all_codes.append(c)
                    if fallback_codes:
                        print(
                            f"⚠️ {self.account_name}: fuli wheel error {i+1}/{spins}, extracted code(s): "
                            f"{self._mask_codes(fallback_codes)}"
                        )
                except Exception:
                    pass
                continue

        # 最终兜底：再扫一遍页面（抽奖记录表格可能在弹窗关闭后才完成渲染/追加）
        try:
            final_codes = await self._extract_exchange_codes_from_page(page)
            for c in final_codes:
                if c not in all_codes:
                    all_codes.append(c)
        except Exception:
            pass

        return all_codes, f"转盘已尝试 {attempted}/{spins} 次"

    async def _runanytime_get_balance_from_app_me(self, page, api_user: str | int | None = None) -> dict | None:
        """获取 runanytime/new-api 的余额与消耗（纯 UI 解析）。

        说明：
        - 该站点会出现 `/api/user/self` 返回 401（未登录/缺 token）的情况，且不同部署校验逻辑不一致；
          为了稳定性，这里完全改为从 `/console` 文本解析。
        - `/console/topup` 初次渲染可能是 `🏃‍♂️NaN`，仅作为兜底。
        """
        origin = (self.provider_config.origin or "").rstrip("/")
        if not origin:
            return None

        def _parse_amount(text: str) -> float | None:
            if not text:
                return None
            t = text.replace("￥", "").replace("$", "").replace(",", "").strip()
            t = re.sub(r"[^0-9.\\-]", "", t)
            try:
                return float(t)
            except Exception:
                return None

        def _mk_result(quota: float, used_quota: float) -> dict:
            q = round(float(quota), 2)
            u = round(float(used_quota), 2)
            return {
                "success": True,
                "quota": q,
                "used_quota": u,
                "display": f"Current balance: 🏃‍♂️{q:.2f}, Used: 🏃‍♂️{u:.2f}",
            }

        # runanytime 控制台是 SPA：首次加载经常先渲染 NaN，再异步拉取用户信息，适当放宽等待时间
        for path, timeout_ms in (("/console", 20000), ("/console/topup", 25000)):
            try:
                await page.goto(f"{origin}{path}", wait_until="domcontentloaded")
                await self._maybe_solve_cloudflare_interstitial(page)
                await page.wait_for_timeout(600)
            except Exception:
                continue

            # 如果被重定向到登录页，说明 localStorage/user 或 session 失效
            try:
                if "/login" in (page.url or ""):
                    await self._take_screenshot(page, "runanytime_balance_redirected_to_login")
                    continue
            except Exception:
                pass

            # 等待 SPA 渲染出数值（topup 页可能先 NaN）
            try:
                await page.wait_for_function(
                    """() => {
                        const t = document.body ? (document.body.innerText || document.body.textContent || '') : '';
                        if (!t.includes('当前余额')) return false;
                        if (t.includes('NaN')) return false;
                        const m = t.match(/当前余额\\s*\\n\\s*([^\\n\\r]+)/);
                        return !!(m && m[1] && /\\d/.test(m[1]));
                    }""",
                    timeout=timeout_ms,
                )
            except Exception:
                pass

            extracted = None
            try:
                extracted = await page.evaluate(
                    """() => {
                        const bodyText = document.body ? (document.body.innerText || document.body.textContent || '') : '';

                        function pickByLabel(label) {
                            const nodes = Array.from(document.querySelectorAll('*'));
                            // 先找“文本精确等于 label”的节点，优先取其父容器里的金额
                            const exact = nodes.find(n => ((n.innerText || '').trim() === label));
                            if (exact && exact.parentElement) {
                                const t = (exact.parentElement.innerText || '').trim();
                                if (t.includes('🏃‍♂️') || t.includes('$') || t.includes('￥')) return t;
                            }
                            // 再找包含 label 且包含货币符号的最短块（通常就是卡片）
                            const candidates = nodes
                                .map(n => (n.innerText || '').trim())
                                .filter(t => t && t.includes(label) && (t.includes('🏃‍♂️') || t.includes('$') || t.includes('￥')))
                                .sort((a, b) => a.length - b.length);
                            return candidates[0] || null;
                        }

                        return {
                            url: location.href,
                            bodyText,
                            balanceBlock: pickByLabel('当前余额'),
                            usedBlock: pickByLabel('历史消耗'),
                        };
                    }"""
                )
            except Exception:
                extracted = None

            body_text = ""
            balance_block = ""
            used_block = ""
            if isinstance(extracted, dict):
                body_text = extracted.get("bodyText") or ""
                balance_block = extracted.get("balanceBlock") or ""
                used_block = extracted.get("usedBlock") or ""
            if not body_text:
                continue

            def _extract_amount_from_block(label: str, block: str) -> str | None:
                if not block:
                    return None
                # 1) 优先取 label 后紧跟的金额（同一块里可能有多个 🏃‍♂️）
                m = re.search(rf"{re.escape(label)}\\s*[\\n\\r\\t ]+([\\s\\S]{{0,40}})", block)
                if m and m.group(1):
                    seg = m.group(1)
                    m2 = re.search(r"(🏃‍♂️\\s*[-0-9.,]+|\\$\\s*[-0-9.,]+|￥\\s*[-0-9.,]+)", seg)
                    if m2:
                        return m2.group(1).strip()
                # 2) 兜底：取块内第一个金额
                m3 = re.search(r"(🏃‍♂️\\s*[-0-9.,]+|\\$\\s*[-0-9.,]+|￥\\s*[-0-9.,]+)", block)
                if m3:
                    return m3.group(1).strip()
                return None

            balance_line = _extract_amount_from_block("当前余额", balance_block) or _extract_amount_from_block(
                "当前余额", body_text
            )
            used_line = _extract_amount_from_block("历史消耗", used_block) or _extract_amount_from_block(
                "历史消耗", body_text
            )

            quota = _parse_amount(balance_line or "")
            used_quota = _parse_amount(used_line or "")
            if quota is None:
                continue
            if used_quota is None:
                used_quota = 0.0
            return _mk_result(quota, used_quota)

        return None

    async def _runanytime_get_balance_via_browser_fetch(self, page, api_user: str | int) -> dict | None:
        """在 runanytime 页面内用 fetch('/api/user/self') 获取余额（稳定且不依赖 UI 是否 NaN）。"""
        raw = await self._runanytime_fetch_user_self_raw(page, api_user)
        status = int(raw.get("status", 0) or 0)
        text = raw.get("text", "") or ""
        if status != 200 or not text:
            if status:
                print(f"⚠️ {self.account_name}: runanytime balance fetch HTTP {status} (browser fetch)")
            return None
        try:
            data = json.loads(text)
        except Exception:
            return None
        if not isinstance(data, dict) or not data.get("success"):
            return None
        user_data = data.get("data", {}) or {}
        try:
            quota = round(float(user_data.get("quota", 0)) / 500000, 2)
            used_quota = round(float(user_data.get("used_quota", 0)) / 500000, 2)
        except Exception:
            return None
        print(
            f"✅ {self.account_name}: runanytime balance fetched: 🏃‍♂️{quota:.2f} (used 🏃‍♂️{used_quota:.2f})"
        )
        return {
            "success": True,
            "quota": quota,
            "used_quota": used_quota,
            "display": f"Current balance: 🏃‍♂️{quota:.2f}, Used: 🏃‍♂️{used_quota:.2f}",
        }

    async def _runanytime_redeem_code_via_browser(self, page, code: str) -> tuple[bool, str]:
        await page.goto(f"{self.provider_config.origin}/console/topup", wait_until="networkidle")
        await self._maybe_solve_cloudflare_interstitial(page)
        await self._ensure_page_past_cloudflare(page)

        input_ele = None
        for selector in [
            'input[placeholder="请输入兑换码"]',
            'input[type="text"]',
            "input",
        ]:
            try:
                ele = await page.query_selector(selector)
                if ele:
                    input_ele = ele
                    break
            except Exception:
                continue

        if not input_ele:
            await self._take_screenshot(page, "runanytime_topup_input_not_found")
            return False, "未找到兑换码输入框"

        try:
            await input_ele.fill(code)
        except Exception as e:
            return False, f"填写兑换码失败: {e}"

        btn = None
        for selector in [
            'button:has-text("兑换额度")',
            'button:has-text("兑换")',
            "button",
        ]:
            try:
                ele = await page.query_selector(selector)
                if ele:
                    btn = ele
                    break
            except Exception:
                continue

        if not btn:
            await self._take_screenshot(page, "runanytime_topup_button_not_found")
            return False, "未找到兑换按钮"

        await btn.click()
        await page.wait_for_timeout(2500)

        msg = ""
        try:
            msg = await page.evaluate(
                """() => {
                    const candidates = [
                        ...document.querySelectorAll('[role=\"alert\"]'),
                        ...document.querySelectorAll('.ant-message-notice-content'),
                        ...document.querySelectorAll('.ant-notification-notice-message'),
                        ...document.querySelectorAll('.el-message'),
                    ];
                    const text = candidates.map(e => (e.innerText || '').trim()).filter(Boolean).join('\\n');
                    return text || '';
                }"""
            )
        except Exception:
            msg = ""

        success = ("成功" in msg) or ("兑换成功" in msg)

        # 已使用/已兑换：视为幂等成功态（重复跑脚本不报错）
        if not success and any(k in (msg or "") for k in ["已使用", "已兑换"]):
            return True, msg

        if not success and any(k in (msg or "") for k in ["无效", "失败", "错误"]):
            return False, msg or "兑换失败"

        return success, msg or "已提交兑换请求"

    async def _runanytime_check_in_via_fuli_and_topup(
        self,
        runanytime_cookies: dict,
        api_user: str | int,
        linuxdo_username: str,
        linuxdo_password: str,
        linuxdo_cache_file_path: str,
    ) -> tuple[bool, dict]:
        """runanytime 新签到：在 fuli 获取兑换码并通过 API 兑换，再读取余额。

        关键点：
        - fuli 侧：用浏览器完成 linux.do OAuth（必要时），然后用 API 获取签到/转盘兑换码（更快更稳）。
        - runanytime 侧：完全用 API 兑换与读取余额，避免 SPA /console 重定向导致的 N/A。
        """
        print(f"ℹ️ {self.account_name}: runanytime requires fuli exchange codes, starting browser flow")

        origin = (self.provider_config.origin or "").rstrip("/")
        if not origin:
            return False, {"error": "missing provider origin"}

        def _run_headers(referer: str) -> dict:
            # 注意：浏览器 fetch 不能自定义 User-Agent，且 Cloudflare clearance 往往与浏览器指纹绑定；
            # 因此这里不要在浏览器路径中塞随机 UA。
            headers = {
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "Origin": origin,
                "Referer": referer,
            }
            self._inject_api_user_headers(headers, api_user)
            return headers

        before_info: dict | None = None

        async with AsyncCamoufox(
            headless=False,
            humanize=True,
            locale="zh-CN",
            geoip=True if self.camoufox_proxy_config else False,
            proxy=self.camoufox_proxy_config,
            disable_coop=True,
            config={"forceScopeAccess": True},
            i_know_what_im_doing=True,
        ) as browser:
            storage_state = (
                linuxdo_cache_file_path
                if linuxdo_cache_file_path and os.path.exists(linuxdo_cache_file_path)
                else None
            )
            context = await browser.new_context(storage_state=storage_state)

            fuli_page = await context.new_page()
            run_page = await context.new_page()
            try:
                # 尝试复用本地缓存的 Cloudflare cookie（可降低频繁弹验证的概率）
                try:
                    cached_cf = self._load_cf_cookies_from_cache() or []
                    if cached_cf:
                        await context.add_cookies(cached_cf)
                except Exception:
                    pass

                # 注入 runanytime cookies（包含 session/cf_clearance 等），确保后续在浏览器上下文内可直接 fetch API
                try:
                    await context.add_cookies(self._cookie_dict_to_browser_cookies(runanytime_cookies or {}, origin))
                except Exception:
                    pass

                try:
                    await run_page.goto(f"{origin}/console", wait_until="domcontentloaded")
                except Exception:
                    await run_page.goto(origin, wait_until="domcontentloaded")
                await self._ensure_page_past_cloudflare(run_page)

                # 刷新缓存（若本次跑通了 challenge）
                try:
                    self._save_cf_cookies_to_cache(await context.cookies())
                except Exception:
                    pass

                async def _run_get_user_info_via_browser() -> dict:
                    resp = await self._browser_fetch_json(
                        run_page,
                        f"{origin}/api/user/self",
                        method="GET",
                        headers=_run_headers(f"{origin}/console"),
                    )
                    status = int(resp.get("status", 0) or 0)
                    text = (resp.get("text") or "")[:200]

                    if status != 200:
                        if status in (403, 503) and self._looks_like_cloudflare_interstitial_html(text):
                            await self._ensure_page_past_cloudflare(run_page)
                            resp = await self._browser_fetch_json(
                                run_page,
                                f"{origin}/api/user/self",
                                method="GET",
                                headers=_run_headers(f"{origin}/console"),
                            )
                            status = int(resp.get("status", 0) or 0)
                            text = (resp.get("text") or "")[:200]
                        if status:
                            print(f"⚠️ {self.account_name}: runanytime /api/user/self HTTP {status}: {text}")
                            return {"success": False, "error": f"HTTP {status}: {text}", "status_code": status}
                        return {"success": False, "error": f"request_error: {resp.get('text')}"}

                    data = resp.get("json")
                    if not isinstance(data, dict):
                        return {"success": False, "error": "response_not_json"}
                    if not data.get("success"):
                        msg = data.get("message") or data.get("msg") or ""
                        return {"success": False, "error": msg or "response_success=false"}

                    user_data = data.get("data", {}) or {}
                    try:
                        quota = round(float(user_data.get("quota", 0)) / 500000, 2)
                        used_quota = round(float(user_data.get("used_quota", 0)) / 500000, 2)
                    except Exception:
                        return {"success": False, "error": "parse_quota_failed"}
                    print(f"✅ {self.account_name}: runanytime 余额: 🏃‍♂️{quota:.2f}, 历史消耗: 🏃‍♂️{used_quota:.2f}")
                    return {
                        "success": True,
                        "quota": quota,
                        "used_quota": used_quota,
                        "display": f"Current balance: 🏃‍♂️{quota:.2f}, Used: 🏃‍♂️{used_quota:.2f}",
                    }

                async def _run_topup_via_browser(code: str) -> dict:
                    resp = await self._browser_fetch_json(
                        run_page,
                        f"{origin}/api/user/topup",
                        method="POST",
                        headers=_run_headers(f"{origin}/console/topup"),
                        json_body={"key": code},
                    )
                    status = int(resp.get("status", 0) or 0)
                    text_snip = (resp.get("text") or "")[:200]
                    data = resp.get("json")

                    # Cloudflare interstitial：尝试处理后重试一次
                    if status in (403, 503) and self._looks_like_cloudflare_interstitial_html(text_snip):
                        await self._ensure_page_past_cloudflare(run_page)
                        resp = await self._browser_fetch_json(
                            run_page,
                            f"{origin}/api/user/topup",
                            method="POST",
                            headers=_run_headers(f"{origin}/console/topup"),
                            json_body={"key": code},
                        )
                        status = int(resp.get("status", 0) or 0)
                        text_snip = (resp.get("text") or "")[:200]
                        data = resp.get("json")

                    # 解析 JSON
                    if status in (200, 400) and isinstance(data, dict):
                        if data.get("success"):
                            return {
                                "success": True,
                                "message": data.get("message", "Topup successful"),
                                "data": data.get("data"),
                                "status_code": status,
                            }
                        msg = data.get("message") or data.get("msg") or "Unknown error"
                        already_used = any(k in msg for k in ["已被使用", "已使用", "already"])
                        if already_used:
                            return {"success": True, "already_used": True, "message": msg, "status_code": status}
                        return {"success": False, "error": msg, "status_code": status}

                    # 兜底：API 不通/被拦截时回退到浏览器 UI 兑换（更抗站点改动）
                    if status:
                        err = f"topup HTTP {status}: {text_snip}"
                    else:
                        err = f"topup request_error: {resp.get('text')}"
                    ok, msg = await self._runanytime_redeem_code_via_browser(run_page, code)
                    if ok:
                        return {"success": True, "message": msg or "兑换成功(浏览器回退)", "status_code": status or 200}
                    return {"success": False, "error": msg or err, "status_code": status or 0}

                before_info = await _run_get_user_info_via_browser()

                await self._ensure_fuli_logged_in(fuli_page, linuxdo_username, linuxdo_password)
                # 用 API 获取 fuli cookies（更稳定且不用解析弹窗 DOM）
                try:
                    all_cookies = await context.cookies()
                except Exception:
                    all_cookies = []
                from utils.browser_utils import filter_cookies  # 避免循环引用

                fuli_cookies = filter_cookies(all_cookies, self.FULI_ORIGIN)
                if not fuli_cookies:
                    await self._take_screenshot(fuli_page, "fuli_no_cookies_after_login")
                    raise RuntimeError("fuli 登录后未能获取到可用 cookies")

                fuli_client = httpx.Client(http2=True, timeout=30.0, proxy=self.http_proxy_config)
                try:
                    fuli_client.cookies.update(fuli_cookies)
                except Exception:
                    pass

                def _fuli_headers(referer: str) -> dict:
                    return {
                        "User-Agent": self.user_agent,
                        "Accept": "application/json, text/plain, */*",
                        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                        "Cache-Control": "no-store",
                        "Pragma": "no-cache",
                        "Origin": self.FULI_ORIGIN,
                        "Referer": referer,
                    }

                def _fuli_pick_code(payload) -> str:
                    """从 fuli API 响应中尽量提取兑换码（兼容字段/结构变更）。"""
                    if not payload:
                        return ""
                    if isinstance(payload, str):
                        return payload.strip()
                    if not isinstance(payload, dict):
                        return ""

                    # 常见字段：code/key；有些实现会把兑换码放到 data 里
                    for k in ("code", "key", "exchangeCode", "exchange_code", "redeemCode", "redeem_code"):
                        v = payload.get(k)
                        if isinstance(v, str) and v.strip():
                            return v.strip()
                        if isinstance(v, (int, float)) and str(v).strip():
                            return str(v).strip()

                    # 少数实现会返回 codes/keys 列表
                    for lk in ("codes", "keys", "exchangeCodes", "exchange_codes", "redeemCodes", "redeem_codes"):
                        lv = payload.get(lk)
                        if isinstance(lv, list):
                            for item in lv:
                                if isinstance(item, str) and item.strip():
                                    return item.strip()
                                if isinstance(item, (int, float)) and str(item).strip():
                                    return str(item).strip()

                    data = payload.get("data")
                    if isinstance(data, (str, dict)):
                        nested = _fuli_pick_code(data)
                        if nested:
                            return nested
                    if isinstance(data, list):
                        for item in data:
                            nested = _fuli_pick_code(item)
                            if nested:
                                return nested

                    msg = payload.get("message") or payload.get("msg") or ""
                    if isinstance(msg, str) and msg.strip():
                        codes = self._extract_exchange_codes(msg)
                        if codes:
                            return codes[0]
                    return ""

                def _fuli_get_checkin_status() -> tuple[bool, bool, str]:
                    try:
                        resp = fuli_client.get(
                            f"{self.FULI_ORIGIN}/api/checkin/status", headers=_fuli_headers(self.FULI_ORIGIN + "/")
                        )
                    except Exception as e:
                        return False, False, f"request_error: {e}"
                    if resp.status_code != 200:
                        return False, False, f"HTTP {resp.status_code}"
                    data = self._check_and_handle_response(resp, "fuli_checkin_status")
                    if not isinstance(data, dict):
                        return False, False, "响应解析失败"
                    checked = bool(data.get("checked", False))
                    return True, checked, "ok"

                def _fuli_execute_checkin() -> tuple[bool, str, str]:
                    try:
                        resp = fuli_client.post(
                            f"{self.FULI_ORIGIN}/api/checkin", headers=_fuli_headers(self.FULI_ORIGIN + "/"), content=b""
                        )
                    except Exception as e:
                        return False, "", f"request_error: {e}"
                    if resp.status_code not in (200, 400):
                        return False, "", f"HTTP {resp.status_code}"
                    data = self._check_and_handle_response(resp, "fuli_checkin")
                    if not isinstance(data, dict):
                        return False, "", "响应解析失败"
                    msg = data.get("message") or data.get("msg") or ""
                    if data.get("success"):
                        code = _fuli_pick_code(data)
                        if not code:
                            try:
                                os.makedirs("logs", exist_ok=True)
                                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                                p = os.path.join("logs", f"{self.safe_account_name}_{ts}_fuli_checkin_success_no_code.json")
                                with open(p, "w", encoding="utf-8") as f:
                                    f.write(json.dumps(data, ensure_ascii=False, indent=2))
                                print(f"⚠️ {self.account_name}: fuli 签到成功但未解析到兑换码，已保存响应: {p}")
                            except Exception:
                                pass
                        streak = data.get("streak")
                        expire_seconds = data.get("expireSeconds")
                        prize = data.get("prize") or data.get("reward") or data.get("amount") or data.get("value")
                        print(
                            f"✅ {self.account_name}: fuli 签到成功: code={code}, prize={prize}, "
                            f"streak={streak}, expireSeconds={expire_seconds}"
                        )
                        return True, code, msg or "签到成功"
                    # already checked in
                    if any(k in (msg or "") for k in ["already", "已经", "已签", "今日已签到"]):
                        return True, "", "今日已签到"
                    return False, "", msg or "签到失败"

                def _fuli_get_wheel_status() -> tuple[bool, int, str]:
                    try:
                        resp = fuli_client.get(
                            f"{self.FULI_ORIGIN}/api/wheel/status", headers=_fuli_headers(self.FULI_ORIGIN + "/wheel")
                        )
                    except Exception as e:
                        return False, 0, f"request_error: {e}"
                    if resp.status_code != 200:
                        return False, 0, f"HTTP {resp.status_code}"
                    data = self._check_and_handle_response(resp, "fuli_wheel_status")
                    if not isinstance(data, dict):
                        return False, 0, "响应解析失败"
                    try:
                        remaining = int(data.get("remaining", 0) or 0)
                    except Exception:
                        remaining = 0
                    return True, remaining, "ok"

                def _fuli_execute_wheel() -> tuple[bool, str, int, str]:
                    try:
                        resp = fuli_client.post(
                            f"{self.FULI_ORIGIN}/api/wheel", headers=_fuli_headers(self.FULI_ORIGIN + "/wheel"), content=b""
                        )
                    except Exception as e:
                        return False, "", 0, f"request_error: {e}"
                    if resp.status_code not in (200, 400):
                        return False, "", 0, f"HTTP {resp.status_code}"
                    data = self._check_and_handle_response(resp, "fuli_wheel")
                    if not isinstance(data, dict):
                        return False, "", 0, "响应解析失败"
                    msg = data.get("message") or data.get("msg") or ""
                    if data.get("success"):
                        expire_seconds = data.get("expireSeconds")
                        try:
                            remaining = int(data.get("remaining", 0) or 0)
                        except Exception:
                            remaining = 0
                        code = _fuli_pick_code(data)
                        if not code:
                            try:
                                os.makedirs("logs", exist_ok=True)
                                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                                p = os.path.join("logs", f"{self.safe_account_name}_{ts}_fuli_wheel_success_no_code.json")
                                with open(p, "w", encoding="utf-8") as f:
                                    f.write(json.dumps(data, ensure_ascii=False, indent=2))
                                print(f"⚠️ {self.account_name}: fuli 转盘成功但未解析到兑换码，已保存响应: {p}")
                            except Exception:
                                pass
                        prize = data.get("prize") or data.get("reward") or data.get("amount") or data.get("value")
                        print(
                            f"✅ {self.account_name}: fuli 转盘成功: code={code}, prize={prize}, "
                            f"remaining={remaining}, expireSeconds={expire_seconds}"
                        )
                        return True, code, remaining, msg or "转盘成功"
                    if any(k in (msg or "") for k in ["already", "次数", "用完", "已用完"]):
                        return True, "", 0, "次数已用完"
                    return False, "", 0, msg or "转盘失败"

                # 1) fuli 签到：先 status，再 checkin
                status_ok, checked, status_msg = _fuli_get_checkin_status()
                if status_ok and checked:
                    checkin_ok, checkin_code, checkin_msg = True, "", "今日已签到"
                else:
                    checkin_ok, checkin_code, checkin_msg = _fuli_execute_checkin()
                    # API 失败时回退浏览器 DOM 流程（避免误判为未签到）
                    if not checkin_ok and not status_ok:
                        try:
                            print(f"⚠️ {self.account_name}: fuli API 签到失败({status_msg}/{checkin_msg})，回退浏览器流程")
                            checkin_ok, checkin_code2, checkin_msg2 = await self._fuli_daily_checkin_get_code(fuli_page)
                            if checkin_code2:
                                checkin_code = checkin_code2
                            checkin_msg = checkin_msg2
                        except Exception:
                            pass

                if checkin_code:
                    print(f"✅ {self.account_name}: fuli 今日签到兑换码: {checkin_code}")
                else:
                    print(f"ℹ️ {self.account_name}: fuli 今日签到结果: {checkin_msg}")

                # 2) fuli 转盘：最多 3 次（若接口返回 remaining 则以它为准）
                wheel_codes: list[str] = []
                wheel_msg = "未执行"
                wheel_used_browser_fallback = False
                wheel_status_ok, remaining, wheel_status_msg = _fuli_get_wheel_status()
                if wheel_status_ok:
                    wheel_msg = f"剩余 {remaining} 次"
                else:
                    # API 失败则回退浏览器转盘（避免误判“次数已用完”）
                    try:
                        print(f"⚠️ {self.account_name}: fuli API 转盘状态获取失败({wheel_status_msg})，回退浏览器流程")
                        wheel_codes, wheel_msg = await self._fuli_wheel_get_codes(fuli_page, max_times=3)
                        wheel_used_browser_fallback = True
                        remaining = 0
                    except Exception:
                        wheel_msg = f"状态获取失败({wheel_status_msg})"
                        remaining = 0

                if not wheel_used_browser_fallback:
                    initial_remaining = max(int(remaining or 0), 0)
                    last_remaining = initial_remaining
                    spins = min(max(remaining, 0), 3)
                    if spins <= 0:
                        wheel_msg = "次数已用完"
                    else:
                        spun = 0
                        for i in range(spins):
                            ok, code, remaining2, msg = _fuli_execute_wheel()
                            wheel_msg = msg
                            if ok and code:
                                wheel_codes.append(code)
                                spun += 1
                                last_remaining = max(int(remaining2 or 0), 0)
                                print(
                                    f"✅ {self.account_name}: fuli 转盘第 {i+1}/{spins} 次兑换码: {code} (remaining={remaining2})"
                                )
                            elif ok:
                                wheel_msg = "次数已用完"
                                last_remaining = 0
                                break
                            else:
                                print(f"⚠️ {self.account_name}: fuli 转盘第 {i+1}/{spins} 次失败: {msg}")
                                # 允许少量失败，继续尝试
                        # 如果还有次数但本次只转 3 次，明确写入日志，避免误以为“脚本漏转”
                        if spins == 3 and initial_remaining > 3 and last_remaining > 0:
                            wheel_msg = f"已转 {spun} 次(上限3次)，剩余 {last_remaining} 次"

                # 3) 汇总兑换码（全部打印到日志，避免“抽到了但没兑换”）
                codes: list[str] = []
                if checkin_code:
                    codes.append(checkin_code)
                codes.extend([c for c in wheel_codes if c])

                if codes:
                    print(f"ℹ️ {self.account_name}: fuli 本次获取兑换码 {len(codes)} 个: {codes}")
                else:
                    print(f"ℹ️ {self.account_name}: fuli 本次无可兑换码 (checkin={checkin_msg}, wheel={wheel_msg})")

                # 4) runanytime 兑换
                redeem_results: list[dict] = []
                success_redeem = 0
                for code in codes:
                    print(f"💰 {self.account_name}: runanytime 兑换中: {code}")
                    result = await _run_topup_via_browser(code)
                    ok = bool(result.get("success"))
                    redeem_results.append({"code": code, **result})
                    if ok:
                        success_redeem += 1
                        extra = result.get("data")
                        extra_str = ""
                        if extra is not None:
                            extra_str = f" | data={str(extra)[:180]}"
                        print(
                            f"✅ {self.account_name}: runanytime 兑换成功: {code} | {result.get('message','')}{extra_str}"
                        )
                    else:
                        print(f"❌ {self.account_name}: runanytime 兑换失败: {code} | {result.get('error','')}")

                after_info = await _run_get_user_info_via_browser()

                before_quota = before_info.get("quota") if before_info else None
                after_quota = after_info.get("quota") if after_info else None
                before_used = before_info.get("used_quota") if before_info else None
                after_used = after_info.get("used_quota") if after_info else None

                def _fmt_quota(v) -> str:
                    if isinstance(v, (int, float)):
                        return f"🏃‍♂️{v:.2f}"
                    return "N/A"

                cur_quota = after_quota if isinstance(after_quota, (int, float)) else before_quota
                cur_used = after_used if isinstance(after_used, (int, float)) else before_used
                if not isinstance(cur_used, (int, float)):
                    cur_used = 0.0

                summary = (
                    f"RunAnytime 兑换 {success_redeem}/{len(codes)} 个 | "
                    f"fuli: {checkin_msg}, {wheel_msg} | "
                    f"当前余额: {_fmt_quota(cur_quota)} | 历史消耗: {_fmt_quota(cur_used)} | "
                    f"变动: {_fmt_quota(before_quota)} -> {_fmt_quota(after_quota)}"
                )
                # 若余额获取失败，给出最后一次错误信息（避免通知里只有 N/A）
                balance_err = ""
                for info in [after_info, before_info]:
                    if isinstance(info, dict) and not info.get("success") and info.get("error"):
                        balance_err = str(info.get("error"))[:120]
                        break
                if balance_err:
                    summary += f" | 余额获取失败: {balance_err}"

                base_info = None
                if after_info and after_info.get("success"):
                    base_info = after_info
                elif before_info and before_info.get("success"):
                    base_info = before_info
                else:
                    base_info = {"success": False, "quota": 0, "used_quota": 0, "display": ""}

                user_info = dict(base_info)

                # runanytime：转盘不是硬依赖（经常显示“次数已用完”或 UI 变更），只要每日签到已完成且本次无可兑换码，
                # 就视为幂等成功；若拿到兑换码则要求全部兑换成功。
                all_redeemed = len(codes) > 0 and success_redeem == len(codes)
                wheel_done = "次数已用完" in (wheel_msg or "")
                signed_done = bool(checkin_ok) or (checkin_msg in ("今日已签到", "签到成功"))
                # 已签到（包含“已执行签到动作”这种无法识别兑换码的情况）不应判定为本次执行失败
                no_codes_but_done = len(codes) == 0 and signed_done
                quota_increased = (
                    isinstance(before_quota, (int, float))
                    and isinstance(after_quota, (int, float))
                    and after_quota > before_quota
                )
                overall_success = all_redeemed or no_codes_but_done or quota_increased or (signed_done and wheel_done)

                user_info.update(
                    {
                        "success": overall_success,
                        "display": summary,
                        "fuli_codes": codes,
                        "redeem_results": redeem_results,
                    }
                )
                # 通知/余额 hash 依赖 quota/used_quota，保证写入“当前值”（即使 before/after 有缺失）
                if isinstance(cur_quota, (int, float)):
                    user_info["quota"] = float(cur_quota)
                if isinstance(cur_used, (int, float)):
                    user_info["used_quota"] = float(cur_used)

                if not overall_success:
                    return False, user_info
                return True, user_info
            except Exception as e:
                try:
                    await self._take_screenshot(fuli_page, "runanytime_fuli_flow_error_fuli")
                except Exception:
                    pass
                # 这里经常是“已经登录到 fuli 页面但后续流程异常”，必须把异常信息打出来，避免误以为是登录失败。
                try:
                    import traceback

                    tb = traceback.format_exc()
                    os.makedirs("logs", exist_ok=True)
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    p = os.path.join("logs", f"{self.safe_account_name}_{ts}_runanytime_fuli_flow_error.txt")
                    with open(p, "w", encoding="utf-8") as f:
                        f.write(tb)
                    print(f"❌ {self.account_name}: runanytime fuli/topup flow error: {e} (traceback saved: {p})")
                except Exception:
                    print(f"❌ {self.account_name}: runanytime fuli/topup flow error: {e}")
                return False, {"error": f"runanytime fuli/topup flow error: {e}"}
            finally:
                try:
                    await fuli_page.close()
                except Exception:
                    pass
                try:
                    await run_page.close()
                except Exception:
                    pass
                await context.close()
                try:
                    fuli_client.close()
                except Exception:
                    pass
        # runanytime 兑换/余额走浏览器上下文，不需要额外 httpx client

    def _check_and_handle_response(self, response: httpx.Response, context: str = "response") -> dict | None:
        """检查响应类型，如果是 HTML 则保存为文件，否则返回 JSON 数据

        Args:
            response: httpx Response 对象
            context: 上下文描述，用于生成文件名

        Returns:
            JSON 数据字典，如果响应是 HTML 则返回 None
        """

        # 创建 logs 目录
        logs_dir = "logs"
        os.makedirs(logs_dir, exist_ok=True)

        # 如果是 JSON，正常解析
        try:
            return response.json()
        except json.JSONDecodeError as e:
            print(f"❌ {self.account_name}: Failed to parse JSON response: {e}")

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_context = "".join(c if c.isalnum() else "_" for c in context)

            content_type = response.headers.get("content-type", "").lower()

            # 检查是否是 HTML 响应
            if "text/html" in content_type or "text/plain" in content_type:
                # 保存 HTML 内容到文件
                filename = f"{self.safe_account_name}_{timestamp}_{safe_context}.html"
                filepath = os.path.join(logs_dir, filename)

                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(response.text)

                print(f"⚠️ {self.account_name}: Received HTML response, saved to: {filepath}")
            else:
                # 即使不是 HTML，如果 JSON 解析失败，也保存原始内容
                filename = f"{self.safe_account_name}_{timestamp}_{safe_context}_invalid.txt"
                filepath = os.path.join(logs_dir, filename)

                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(response.text)

                print(f"⚠️ {self.account_name}: Invalid response saved to: {filepath}")
            return None
        except Exception as e:
            print(f"❌ {self.account_name}: Error occurred while checking and handling response: {e}")
            return None

    async def _take_screenshot(self, page, reason: str) -> None:
        """截取当前页面的屏幕截图

        Args:
            page: Camoufox 页面对象
            reason: 截图原因描述
        """
        try:
            # 创建 screenshots 目录
            screenshots_dir = "screenshots"
            os.makedirs(screenshots_dir, exist_ok=True)

            # 生成文件名: 账号名_时间戳_原因.png
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_reason = "".join(c if c.isalnum() else "_" for c in reason)
            filename = f"{self.safe_account_name}_{timestamp}_{safe_reason}.png"
            filepath = os.path.join(screenshots_dir, filename)

            await page.screenshot(path=filepath, full_page=True)
            print(f"📸 {self.account_name}: Screenshot saved to {filepath}")
        except Exception as e:
            print(f"⚠️ {self.account_name}: Failed to take screenshot: {e}")

    async def _aliyun_captcha_check(self, page) -> bool:
        """阿里云验证码检查"""

        # 检查是否有 traceid (阿里云验证码页面)
        try:
            traceid = await page.evaluate(
                """() => {
                const traceElement = document.getElementById('traceid');
                if (traceElement) {
                    const text = traceElement.innerText || traceElement.textContent;
                    const match = text.match(/TraceID:\\s*([a-f0-9]+)/i);
                    return match ? match[1] : null;
                }
                return null;
            }"""
            )

            if traceid:
                print(f"⚠️ {self.account_name}: Aliyun captcha detected, " f"traceid: {traceid}")
                try:
                    await page.wait_for_selector("#nocaptcha", timeout=60000)

                    slider_element = await page.query_selector("#nocaptcha .nc_scale")
                    if slider_element:
                        slider = await slider_element.bounding_box()
                        print(f"ℹ️ {self.account_name}: Slider bounding box: {slider}")

                    slider_handle = await page.query_selector("#nocaptcha .btn_slide")
                    if slider_handle:
                        handle = await slider_handle.bounding_box()
                        print(f"ℹ️ {self.account_name}: Slider handle bounding box: {handle}")

                    if slider and handle:
                        await self._take_screenshot(page, "aliyun_captcha_slider_start")

                        await page.mouse.move(
                            handle.get("x") + handle.get("width") / 2,
                            handle.get("y") + handle.get("height") / 2,
                        )
                        await page.mouse.down()
                        await page.mouse.move(
                            handle.get("x") + slider.get("width"),
                            handle.get("y") + handle.get("height") / 2,
                            steps=2,
                        )
                        await page.mouse.up()
                        await self._take_screenshot(page, "aliyun_captcha_slider_completed")

                        # Wait for page to be fully loaded
                        await page.wait_for_timeout(20000)

                        await self._take_screenshot(page, "aliyun_captcha_slider_result")
                        return True
                    else:
                        print(f"❌ {self.account_name}: Slider or handle not found")
                        await self._take_screenshot(page, "aliyun_captcha_error")
                        return False
                except Exception as e:
                    print(f"❌ {self.account_name}: Error occurred while moving slider, {e}")
                    await self._take_screenshot(page, "aliyun_captcha_error")
                    return False
            else:
                print(f"ℹ️ {self.account_name}: No traceid found")
                await self._take_screenshot(page, "aliyun_captcha_traceid_found")
                return True
        except Exception as e:
            print(f"❌ {self.account_name}: Error occurred while getting traceid, {e}")
            await self._take_screenshot(page, "aliyun_captcha_error")
            return False

    async def get_waf_cookies_with_browser(self) -> dict | None:
        """使用 Camoufox 获取 WAF cookies（隐私模式）"""
        print(
            f"ℹ️ {self.account_name}: Starting browser to get WAF cookies (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_waf_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            async with AsyncCamoufox(
                persistent_context=True,
                user_data_dir=tmp_dir,
                headless=False,
                humanize=True,
                # 中文环境，减小与本地浏览器差异
                locale="zh-CN",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
            ) as browser:
                page = await browser.new_page()

                try:
                    print(f"ℹ️ {self.account_name}: Access login page to get initial cookies")
                    await page.goto(self.provider_config.get_login_url(), wait_until="networkidle")

                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    if self.provider_config.aliyun_captcha:
                        captcha_check = await self._aliyun_captcha_check(page)
                        if captcha_check:
                            await page.wait_for_timeout(3000)

                    cookies = await browser.cookies()

                    waf_cookies = {}
                    print(f"ℹ️ {self.account_name}: WAF cookies")
                    for cookie in cookies:
                        cookie_name = cookie.get("name")
                        cookie_value = cookie.get("value")
                        print(f"  📚 Cookie: {cookie_name} (value: {cookie_value})")
                        if cookie_name in ["acw_tc", "cdn_sec_tc", "acw_sc__v2"] and cookie_value is not None:
                            waf_cookies[cookie_name] = cookie_value

                    print(f"ℹ️ {self.account_name}: Got {len(waf_cookies)} WAF cookies after step 1")

                    # 检查是否至少获取到一个 WAF cookie
                    if not waf_cookies:
                        print(f"❌ {self.account_name}: No WAF cookies obtained")
                        return None

                    # 显示获取到的 cookies
                    cookie_names = list(waf_cookies.keys())
                    print(f"✅ {self.account_name}: Successfully got WAF cookies: {cookie_names}")

                    return waf_cookies

                except Exception as e:
                    print(f"❌ {self.account_name}: Error occurred while getting WAF cookies: {e}")
                    return None
                finally:
                    await page.close()

    async def get_aliyun_captcha_cookies_with_browser(self) -> dict | None:
        """使用 Camoufox 获取阿里云验证 cookies"""
        print(
            f"ℹ️ {self.account_name}: Starting browser to get Aliyun captcha cookies (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_aliyun_captcha_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            async with AsyncCamoufox(
                persistent_context=True,
                user_data_dir=tmp_dir,
                headless=False,
                humanize=True,
                locale="zh-CN",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
            ) as browser:
                page = await browser.new_page()

                try:
                    print(f"ℹ️ {self.account_name}: Access login page to get initial cookies")
                    await page.goto(self.provider_config.get_login_url(), wait_until="networkidle")

                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                        # # 提取验证码相关数据
                        # captcha_data = await page.evaluate(
                        #     """() => {
                        #     const data = {};

                        #     // 获取 traceid
                        #     const traceElement = document.getElementById('traceid');
                        #     if (traceElement) {
                        #         const text = traceElement.innerText || traceElement.textContent;
                        #         const match = text.match(/TraceID:\\s*([a-f0-9]+)/i);
                        #         data.traceid = match ? match[1] : null;
                        #     }

                        #     // 获取 window.aliyun_captcha 相关字段
                        #     for (const key in window) {
                        #         if (key.startsWith('aliyun_captcha')) {
                        #             data[key] = window[key];
                        #         }
                        #     }

                        #     // 获取 requestInfo
                        #     if (window.requestInfo) {
                        #         data.requestInfo = window.requestInfo;
                        #     }

                        #     // 获取当前 URL
                        #     data.currentUrl = window.location.href;

                        #     return data;
                        # }"""
                        # )

                        # print(
                        #     f"📋 {self.account_name}: Captcha data extracted: " f"\n{json.dumps(captcha_data, indent=2)}"
                        # )

                        # # 通过 WaitForSecrets 发送验证码数据并等待用户手动验证
                        # from utils.wait_for_secrets import WaitForSecrets

                        # wait_for_secrets = WaitForSecrets()
                        # secret_obj = {
                        #     "CAPTCHA_NEXT_URL": {
                        #         "name": f"{self.account_name} - Aliyun Captcha Verification",
                        #         "description": (
                        #             f"Aliyun captcha verification required.\n"
                        #             f"TraceID: {captcha_data.get('traceid', 'N/A')}\n"
                        #             f"Current URL: {captcha_data.get('currentUrl', 'N/A')}\n"
                        #             f"Please complete the captcha manually in the browser, "
                        #             f"then provide the next URL after verification."
                        #         ),
                        #     }
                        # }

                        # secrets = wait_for_secrets.get(
                        #     secret_obj,
                        #     timeout=300,
                        #     notification={
                        #         "title": "阿里云验证",
                        #         "content": "请在浏览器中完成验证，并提供下一步的 URL。\n"
                        #         f"{json.dumps(captcha_data, indent=2)}\n"
                        #         "📋 操作说明：https://github.com/aceHubert/newapi-ai-check-in/docs/aliyun_captcha/README.md",
                        #     },
                        # )
                        # if not secrets or "CAPTCHA_NEXT_URL" not in secrets:
                        #     print(f"❌ {self.account_name}: No next URL provided " f"for captcha verification")
                        #     return None

                        # next_url = secrets["CAPTCHA_NEXT_URL"]
                        # print(f"🔄 {self.account_name}: Navigating to next URL " f"after captcha: {next_url}")

                        # # 导航到新的 URL
                        # await page.goto(next_url, wait_until="networkidle")

                        try:
                            await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                        except Exception:
                            await page.wait_for_timeout(3000)

                        # 再次检查是否还有 traceid
                        traceid_after = None
                        try:
                            traceid_after = await page.evaluate(
                                """() => {
                                const traceElement = document.getElementById('traceid');
                                if (traceElement) {
                                    const text = traceElement.innerText || traceElement.textContent;
                                    const match = text.match(/TraceID:\\s*([a-f0-9]+)/i);
                                    return match ? match[1] : null;
                                }
                                return null;
                            }"""
                            )
                        except Exception:
                            traceid_after = None

                        if traceid_after:
                            print(
                                f"❌ {self.account_name}: Captcha verification failed, "
                                f"traceid still present: {traceid_after}"
                            )
                            return None

                        print(f"✅ {self.account_name}: Captcha verification successful, " f"traceid cleared")

                    cookies = await browser.cookies()

                    aliyun_captcha_cookies = {}
                    print(f"ℹ️ {self.account_name}: Aliyun Captcha cookies")
                    for cookie in cookies:
                        cookie_name = cookie.get("name")
                        cookie_value = cookie.get("value")
                        print(f"  📚 Cookie: {cookie_name} (value: {cookie_value})")
                        # if cookie_name in ["acw_tc", "cdn_sec_tc", "acw_sc__v2"]
                        # and cookie_value is not None:
                        aliyun_captcha_cookies[cookie_name] = cookie_value

                    print(
                        f"ℹ️ {self.account_name}: "
                        f"Got {len(aliyun_captcha_cookies)} "
                        f"Aliyun Captcha cookies after step 1"
                    )

                    # 检查是否至少获取到一个 Aliyun Captcha cookie
                    if not aliyun_captcha_cookies:
                        print(f"❌ {self.account_name}: " f"No Aliyun Captcha cookies obtained")
                        return None

                    # 显示获取到的 cookies
                    cookie_names = list(aliyun_captcha_cookies.keys())
                    print(f"✅ {self.account_name}: " f"Successfully got Aliyun Captcha cookies: {cookie_names}")

                    return aliyun_captcha_cookies

                except Exception as e:
                    print(f"❌ {self.account_name}: " f"Error occurred while getting Aliyun Captcha cookies, {e}")
                    return None
                finally:
                    await page.close()

    async def get_status_with_browser(self) -> dict | None:
        """使用 Camoufox 获取状态信息并缓存
        Returns:
            状态数据字典
        """
        print(
            f"ℹ️ {self.account_name}: Starting browser to get status (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_status_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            async with AsyncCamoufox(
                user_data_dir=tmp_dir,
                persistent_context=True,
                headless=False,
                humanize=True,
                # 与 playwright-captcha 推荐配置保持一致，方便处理 Cloudflare Shadow DOM
                locale="zh-CN",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
                disable_coop=True,
                config={"forceScopeAccess": True},
                i_know_what_im_doing=True,
            ) as browser:
                page = await browser.new_page()

                try:
                    print(f"ℹ️ {self.account_name}: Access status page to get status from localStorage")
                    await page.goto(self.provider_config.get_login_url(), wait_until="networkidle")

                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    if self.provider_config.aliyun_captcha:
                        captcha_check = await self._aliyun_captcha_check(page)
                        if captcha_check:
                            await page.wait_for_timeout(3000)

                    # 从 localStorage 获取 status
                    status_data = None
                    try:
                        status_str = await page.evaluate("() => localStorage.getItem('status')")
                        if status_str:
                            status_data = json.loads(status_str)
                            print(f"✅ {self.account_name}: Got status from localStorage")
                        else:
                            print(f"⚠️ {self.account_name}: No status found in localStorage")
                    except Exception as e:
                        print(f"⚠️ {self.account_name}: Error reading status from localStorage: {e}")

                    return status_data

                except Exception as e:
                    print(f"❌ {self.account_name}: Error occurred while getting status: {e}")
                    return None
                finally:
                    await page.close()

    async def get_auth_client_id(self, client: httpx.Client, headers: dict, provider: str) -> dict:
        """获取状态信息

        Args:
            client: httpx 客户端
            headers: 请求头
            provider: 提供商类型 (github/linuxdo)

        Returns:
            包含 success 和 client_id 或 error 的字典
        """
        try:
            # 在请求状态接口之前尝试复用已缓存的 Cloudflare 相关 cookies
            try:
                cached_cf_cookies = self._load_cf_cookies_from_cache()
                if cached_cf_cookies:
                    self._apply_cf_cookies_to_client(client, cached_cf_cookies)
            except Exception as e:
                print(f"⚠️ {self.account_name}: Failed to apply cached Cloudflare cookies: {e}")

            response = client.get(self.provider_config.get_status_url(), headers=headers, timeout=30)

            if response.status_code == 200:
                data = self._check_and_handle_response(response, f"get_auth_client_id_{provider}")
                if data is None:

                    # 尝试从浏览器 localStorage 获取状态
                    # print(f"ℹ️ {self.account_name}: Getting status from browser")
                    # try:
                    #     status_data = await self.get_status_with_browser()
                    #     if status_data:
                    #         oauth = status_data.get(f"{provider}_oauth", False)
                    #         if not oauth:
                    #             return {
                    #                 "success": False,
                    #                 "error": f"{provider} OAuth is not enabled.",
                    #             }

                    #         client_id = status_data.get(f"{provider}_client_id", "")
                    #         if client_id:
                    #             print(f"✅ {self.account_name}: Got client ID from localStorage: " f"{client_id}")
                    #             return {
                    #                 "success": True,
                    #                 "client_id": client_id,
                    #             }
                    # except Exception as browser_err:
                    #     print(f"⚠️ {self.account_name}: Failed to get status from browser: " f"{browser_err}")

                    return {
                        "success": False,
                        "error": "Failed to get client id: Invalid response type (saved to logs)",
                    }

                if data.get("success"):
                    status_data = data.get("data", {})
                    oauth = status_data.get(f"{provider}_oauth", False)
                    if not oauth:
                        return {
                            "success": False,
                            "error": f"{provider} OAuth is not enabled.",
                        }

                    client_id = status_data.get(f"{provider}_client_id", "")
                    return {
                        "success": True,
                        "client_id": client_id,
                    }
                else:
                    error_msg = data.get("message", "Unknown error")
                    return {
                        "success": False,
                        "error": f"Failed to get client id: {error_msg}",
                    }
            return {
                "success": False,
                "error": f"Failed to get client id: HTTP {response.status_code}",
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to get client id, {e}",
            }

    async def get_auth_state_with_browser(self) -> dict:
        """使用 Camoufox 获取认证 URL 和 cookies

        Args:
            status: 要存储到 localStorage 的状态数据
            wait_for_url: 要等待的 URL 模式

        Returns:
            包含 success、url、cookies 或 error 的字典
        """
        print(
            f"ℹ️ {self.account_name}: Starting browser to get auth state (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_auth_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            async with AsyncCamoufox(
                user_data_dir=tmp_dir,
                persistent_context=True,
                headless=False,
                humanize=True,
                # 与 playwright-captcha 推荐配置保持一致，方便处理 Cloudflare Shadow DOM
                locale="zh-CN",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
                disable_coop=True,
                config={"forceScopeAccess": True},
                i_know_what_im_doing=True,
            ) as browser:
                page = await browser.new_page()

                try:
                    # 1. 打开登录页，触发基础的 Cloudflare / WAF 校验
                    login_url = self.provider_config.get_login_url()
                    print(f"ℹ️ {self.account_name}: Opening login page {login_url}")
                    await page.goto(login_url, wait_until="networkidle")

                    try:
                        await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                    except Exception:
                        await page.wait_for_timeout(3000)

                    if self.provider_config.aliyun_captcha:
                        captcha_check = await self._aliyun_captcha_check(page)
                        if captcha_check:
                            await page.wait_for_timeout(3000)

                    # 2. 在登录页上优先尝试解决 Cloudflare 整页拦截（interstitial），使用 playwright-captcha
                    if linuxdo_solve_captcha is not None:
                        try:
                            print(
                                f"ℹ️ {self.account_name}: Solving Cloudflare challenge on login page via "
                                "playwright-captcha ClickSolver"
                            )
                            solved_login = await linuxdo_solve_captcha(
                                page,
                                captcha_type="cloudflare",
                                challenge_type="interstitial",
                            )
                            print(
                                f"ℹ️ {self.account_name}: playwright-captcha solve result on login page: {solved_login}"
                            )
                            await page.wait_for_timeout(5000)
                        except Exception as sc_err:
                            print(
                                f"⚠️ {self.account_name}: playwright-captcha error on login page: {sc_err}"
                            )

                    # 2.1 针对 elysiver 站点：确保真正通过 Cloudflare 挑战后再继续
                    if self.provider_config.name == "elysiver":
                        print(f"ℹ️ {self.account_name}: elysiver detected, ensuring page past Cloudflare challenge")
                        cf_passed = await self._ensure_page_past_cloudflare(page, timeout_ms=60000)
                        if not cf_passed:
                            print(f"⚠️ {self.account_name}: Cloudflare challenge may not be fully resolved, will retry")

                    # 3. 使用浏览器内的 fetch 调用 auth_state 接口，复用已通过的 Cloudflare 状态
                    auth_state_url = self.provider_config.get_auth_state_url()
                    print(
                        f"ℹ️ {self.account_name}: Fetching auth state via browser fetch: {auth_state_url}"
                    )
                    # 某些站点会校验 api_user header（例如要求为 -1 才允许获取 state），这里做兼容注入
                    api_user_headers = {k: "-1" for k in self._get_api_user_header_keys()}
                    # 提供基本的 Accept，避免被当成普通页面请求返回 HTML
                    api_user_headers.setdefault("Accept", "application/json, text/plain, */*")

                    # 针对 elysiver：添加重试机制，应对 CF 挑战通过后仍需等待的情况
                    max_attempts = 4 if self.provider_config.name == "elysiver" else 1
                    response = None
                    for attempt in range(max_attempts):
                        if attempt > 0:
                            print(f"ℹ️ {self.account_name}: Retrying auth state fetch (attempt {attempt + 1}/{max_attempts})")
                            await page.wait_for_timeout(3000)

                        response = await page.evaluate(
                            f"""async () => {{
                                try {{
                                    const resp = await fetch('{auth_state_url}', {{
                                        credentials: 'include',
                                        headers: {json.dumps(api_user_headers, ensure_ascii=False)},
                                    }});
                                    const text = await resp.text();
                                    return {{ ok: resp.ok, status: resp.status, text }};
                                }} catch (e) {{
                                    return {{ ok: false, status: 0, text: String(e) }};
                                }}
                            }}"""
                        )

                        if not response or "text" not in response:
                            if attempt < max_attempts - 1:
                                continue
                            return {
                                "success": False,
                                "error": f"Failed to get state via browser fetch, invalid response: {response}",
                            }

                        status = response.get("status", 0)
                        text = response.get("text", "")

                        # 成功获取
                        if response.get("ok") and status == 200:
                            break

                        # 针对 elysiver：检测 CF 拦截并尝试解决后重试
                        if self.provider_config.name == "elysiver" and attempt < max_attempts - 1:
                            if status in (403, 429, 503) and self._looks_like_cloudflare_interstitial_html(text[:4000]):
                                print(
                                    f"⚠️ {self.account_name}: Cloudflare interstitial detected on auth state fetch (HTTP {status}), "
                                    "attempting to solve"
                                )
                                # 尝试解决 interstitial
                                await self._maybe_solve_cloudflare_interstitial(page)
                                # 也尝试解决 turnstile（某些情况下两者可能混用）
                                await self._maybe_solve_cloudflare_turnstile(page)
                                # 等待足够时间让 CF 验证完成
                                await page.wait_for_timeout(10000)
                                # 再次确保通过 CF
                                await self._ensure_page_past_cloudflare(page, timeout_ms=30000)
                                continue
                            elif status == 429:
                                # 限流，等待后重试
                                backoff_ms = min(30000, 5000 * (2 ** attempt))
                                print(f"⚠️ {self.account_name}: Rate limited (HTTP 429), backing off {backoff_ms/1000:.1f}s")
                                await page.wait_for_timeout(backoff_ms)
                                continue

                        # 其他站点或最后一次尝试：直接返回失败
                        if attempt == max_attempts - 1:
                            return {
                                "success": False,
                                "error": f"Failed to get state via browser fetch: HTTP {status}, body: {text[:200]}",
                            }

                    try:
                        data = json.loads(text)
                    except Exception as parse_err:
                        print(
                            f"⚠️ {self.account_name}: Failed to parse auth state JSON in browser: {parse_err}"
                        )
                        return {
                            "success": False,
                            "error": f"Failed to parse auth state JSON in browser: {text[:200]}",
                        }

                    if data and "data" in data:
                        cookies = await browser.cookies()

                        # 将浏览器中成功通过 Cloudflare 后的 cookie 缓存下来，供后续 httpx 直接复用
                        try:
                            self._save_cf_cookies_to_cache(cookies)
                        except Exception as cache_err:
                            print(
                                f"⚠️ {self.account_name}: Failed to cache Cloudflare cookies from browser: "
                                f"{cache_err}"
                            )

                        return {
                            "success": True,
                            "state": data.get("data"),
                            "cookies": cookies,
                        }

                    return {
                        "success": False,
                        "error": f"Failed to get state, \n{json.dumps(data, indent=2)}",
                    }

                except Exception as e:
                    print(f"❌ {self.account_name}: Failed to get state, {e}")
                    await self._take_screenshot(page, "auth_url_error")
                    return {"success": False, "error": "Failed to get state"}
                finally:
                    await page.close()

    async def get_auth_state(
        self,
        client: httpx.Client,
        headers: dict,
    ) -> dict:
        """获取认证状态

        优先通过 httpx 直接请求后端接口；如果遇到 4xx/5xx 或响应类型异常，
        会自动回退到使用 Camoufox 在浏览器环境中调用同一个接口，以兼容
        Cloudflare / WAF / 额外校验等情况。
        """
        auth_state_url = self.provider_config.get_auth_state_url()

        # 0) 尝试从本地缓存中加载 Cloudflare 相关 cookie，直接注入到 httpx Client
        try:
            cached_cf_cookies = self._load_cf_cookies_from_cache()
            if cached_cf_cookies:
                self._apply_cf_cookies_to_client(client, cached_cf_cookies)
        except Exception as e:
            print(f"⚠️ {self.account_name}: Failed to apply cached Cloudflare cookies: {e}")

        # 1) 尝试通过 httpx 直接获取
        try:
            response = client.get(auth_state_url, headers=headers, timeout=30)

            if response.status_code == 200:
                json_data = self._check_and_handle_response(response, "get_auth_state")
                if json_data is None:
                    print(
                        f"⚠️ {self.account_name}: Auth state HTTP 200 but invalid JSON, "
                        "will try browser-based auth state"
                    )
                else:
                    # 检查响应是否成功
                    if json_data.get("success"):
                        auth_data = json_data.get("data")

                        # 将 httpx Cookies 对象转换为 Camoufox 格式
                        cookies = []
                        if response.cookies:
                            parsed_domain = urlparse(self.provider_config.origin).netloc

                            print(
                                f"ℹ️ {self.account_name}: Got {len(response.cookies)} cookies from auth state request"
                            )
                            for cookie in response.cookies.jar:
                                http_only = cookie.httponly if cookie.has_nonstandard_attr("httponly") else False
                                same_site = cookie.samesite if cookie.has_nonstandard_attr("samesite") else "Lax"
                                print(
                                    f"  📚 Cookie: {cookie.name} (Domain: {cookie.domain}, "
                                    f"Path: {cookie.path}, Expires: {cookie.expires}, "
                                    f"HttpOnly: {http_only}, Secure: {cookie.secure}, "
                                    f"SameSite: {same_site})"
                                )
                                cookies.append(
                                    {
                                        "name": cookie.name,
                                        "domain": cookie.domain if cookie.domain else parsed_domain,
                                        "value": cookie.value,
                                        "path": cookie.path,
                                        "expires": cookie.expires,
                                        "secure": cookie.secure,
                                        "httpOnly": http_only,
                                        "sameSite": same_site,
                                    }
                                )

                        # 将当前成功路径中的 Cloudflare 相关 cookie 写入缓存，供下次运行复用
                        try:
                            # 这里 cookies 已经是 Camoufox 格式，直接用于缓存
                            self._save_cf_cookies_to_cache(cookies)
                        except Exception as cache_err:
                            print(
                                f"⚠️ {self.account_name}: Failed to cache Cloudflare cookies from auth state: "
                                f"{cache_err}"
                            )

                        return {
                            "success": True,
                            "state": auth_data,
                            "cookies": cookies,  # 直接返回 Camoufox 格式的 cookies
                        }

                    # JSON 返回 success=false，直接按原语义返回，不做浏览器兜底
                    error_msg = json_data.get("message", "Unknown error")
                    return {
                        "success": False,
                        "error": f"Failed to get auth state: {error_msg}",
                    }

            # 非 200：可能被 WAF / 403/429 等挡住，尝试浏览器兜底
            print(
                f"⚠️ {self.account_name}: Auth state HTTP {response.status_code}, "
                "will try browser-based auth state"
            )
        except Exception as e:
            # 网络层异常，同样尝试浏览器兜底
            print(
                f"⚠️ {self.account_name}: Auth state HTTP request failed: {e}, "
                "will try browser-based auth state"
            )

        # 2) 兜底：用 Camoufox 在浏览器环境中获取 auth state
        try:
            auth_result = await self.get_auth_state_with_browser()
            if not auth_result.get("success"):
                error_msg = auth_result.get("error", "Unknown error")
                return {
                    "success": False,
                    "error": f"Failed to get auth state with browser: {error_msg}",
                }

            return auth_result
        except Exception as browser_err:
            return {
                "success": False,
                "error": f"Failed to get auth state with browser, {browser_err}",
            }

    async def get_user_info_with_browser(self, auth_cookies: list[dict], api_user: str | int | None = None) -> dict:
        """使用 Camoufox 获取用户信息（优先 localStorage，其次页面解析，再次浏览器内 API fetch）。"""
        print(
            f"ℹ️ {self.account_name}: Starting browser to get user info (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_user_info_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            async with AsyncCamoufox(
                user_data_dir=tmp_dir,
                persistent_context=True,
                headless=False,
                humanize=True,
                locale="en-US",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
            ) as browser:
                page = await browser.new_page()

                try:
                    await browser.add_cookies(auth_cookies)
                except Exception as e:
                    print(f"⚠️ {self.account_name}: Failed to add auth cookies to browser context: {e}")

                try:
                    origin = (self.provider_config.origin or "").rstrip("/")
                    if not origin:
                        return {"success": False, "error": "missing provider origin"}

                    # 打开控制台/主页，让站点前端有机会写入 localStorage
                    try:
                        await page.goto(f"{origin}/console", wait_until="domcontentloaded")
                    except Exception:
                        await page.goto(origin, wait_until="domcontentloaded")
                    await self._ensure_page_past_cloudflare(page)

                    # 0) new-api 站点优先从 localStorage.user 读取额度（站点可能改路由，/app/me 不再稳定）
                    try:
                        # 如果已知 api_user，补种最小 user 结构，避免控制台一直停在 /login
                        if api_user is not None:
                            await page.evaluate(
                                """(apiUser) => {
                                    try {
                                        const key = 'user';
                                        const cur = localStorage.getItem(key);
                                        if (cur) return;
                                        const id = typeof apiUser === 'string' ? parseInt(apiUser, 10) : apiUser;
                                        const user = { id, username: `linuxdo_${id}`, role: 1, status: 1, group: 'default', display_name: 'None' };
                                        localStorage.setItem(key, JSON.stringify(user));
                                    } catch (e) {}
                                }""",
                                str(api_user),
                            )
                            await page.reload(wait_until="domcontentloaded")
                            await self._ensure_page_past_cloudflare(page)
                        await page.wait_for_timeout(800)
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

                    if isinstance(ls_user, dict) and ("quota" in ls_user or "used_quota" in ls_user):
                        try:
                            quota = round(float(ls_user.get("quota", 0) or 0) / 500000, 2)
                            used_quota = round(float(ls_user.get("used_quota", 0) or 0) / 500000, 2)
                            bonus_quota = round(float(ls_user.get("bonus_quota", 0) or 0) / 500000, 2)
                        except Exception:
                            quota = None
                        if isinstance(quota, (int, float)):
                            print(
                                f"✅ {self.account_name}: Current balance: ${quota}, Used: ${used_quota}, Bonus: ${bonus_quota}"
                            )
                            return {
                                "success": True,
                                "quota": float(quota),
                                "used_quota": float(used_quota),
                                "bonus_quota": float(bonus_quota),
                                "display": f"Current balance: ${quota}, Used: ${used_quota}, Bonus: ${bonus_quota}",
                            }

                    # 1) 页面解析（兼容新控制台卡片/表格）
                    candidates: list[str] = []
                    configured = getattr(self.provider_config, "checkin_page_path", None)
                    if configured:
                        candidates.append(str(configured))

                    if self.provider_config.name == "elysiver":
                        candidates.extend(
                            [
                                "/console",
                                "/console/personal",
                                "/console/profile",
                                "/console/checkin",
                                "/app/me",
                                "/app",
                            ]
                        )
                    else:
                        candidates.extend(["/app/me", "/console", "/app"])

                    seen: set[str] = set()
                    candidates = [p for p in candidates if p and not (p in seen or seen.add(p))]

                    def _parse_amount(s: str) -> float:
                        s = str(s or "").replace(",", "").strip()
                        m = re.search(r"(-?\\d+(?:\\.\\d+)?)", s)
                        if not m:
                            return 0.0
                        try:
                            return float(m.group(1))
                        except Exception:
                            return 0.0

                    quota_labels = ("当前余额", "当前额度", "剩余额度", "余额", "可用额度", "Current balance", "Balance")
                    used_labels = ("历史消耗", "历史消费", "已用额度", "消耗", "Used", "Usage")
                    login_markers = ("使用 linuxdo 继续", "使用邮箱或用户名登录", "登录", "注册")

                    async def _looks_like_login_page() -> bool:
                        try:
                            body_text = await page.evaluate(
                                "() => document.body ? (document.body.innerText || document.body.textContent || '') : ''"
                            )
                        except Exception:
                            body_text = ""
                        low = (body_text or "").lower()
                        return any(m in low for m in login_markers)

                    async def _extract_summary() -> dict | None:
                        return await page.evaluate(
                            """() => {
                                try {
                                    const result = {};
                                    const textOf = (el) => (el && (el.innerText || el.textContent) || '').trim();

                                    // cards: "当前余额" + 数值
                                    const all = Array.from(document.querySelectorAll('*'));
                                    for (const el of all) {
                                        const t = textOf(el);
                                        if (!t) continue;
                                        if (t.includes('当前余额') || t.includes('历史消耗')) {
                                            // 把父容器文本作为候选
                                            const p = el.closest('div') || el.parentElement;
                                            const pt = textOf(p);
                                            if (pt) result['__block__'] = (result['__block__'] || '') + '\\n' + pt;
                                        }
                                    }

                                    // table
                                    for (const row of Array.from(document.querySelectorAll('table tr'))) {
                                        const header = row.querySelector('th, [role=\"rowheader\"]');
                                        const cell = row.querySelector('td, [role=\"cell\"]');
                                        const label = textOf(header);
                                        const value = textOf(cell);
                                        if (label && value) result[label] = value;
                                    }

                                    // Ant descriptions
                                    for (const item of Array.from(document.querySelectorAll('.ant-descriptions-item'))) {
                                        const labelEl = item.querySelector('.ant-descriptions-item-label');
                                        const contentEl = item.querySelector('.ant-descriptions-item-content');
                                        const label = textOf(labelEl);
                                        const value = textOf(contentEl);
                                        if (label && value) result[label] = value;
                                    }

                                    return Object.keys(result).length ? result : null;
                                } catch (e) {
                                    return null;
                                }
                            }"""
                        )

                    for path in candidates:
                        target_url = f"{origin}{path}"
                        print(f"ℹ️ {self.account_name}: Opening profile page for browser-based user info: {target_url}")
                        try:
                            await page.goto(target_url, wait_until="networkidle")
                            await self._ensure_page_past_cloudflare(page)
                        except Exception:
                            continue

                        try:
                            await page.wait_for_function("document.readyState === 'complete'", timeout=5000)
                        except Exception:
                            await page.wait_for_timeout(1200)

                        if await _looks_like_login_page():
                            continue

                        summary = await _extract_summary()
                        if not isinstance(summary, dict):
                            continue

                        bal = None
                        used = None
                        for k in quota_labels:
                            if summary.get(k):
                                bal = summary.get(k)
                                break
                        for k in used_labels:
                            if summary.get(k):
                                used = summary.get(k)
                                break

                        # 兜底：从 __block__ 中用正则提取
                        block = summary.get("__block__") if isinstance(summary.get("__block__"), str) else ""
                        if bal is None and block:
                            m = re.search(r"(?:当前余额|余额)\\s*[:：]?\\s*([\\s\\S]{0,32})", block)
                            if m:
                                bal = m.group(1)
                        if used is None and block:
                            m = re.search(r"(?:历史消耗|消耗)\\s*[:：]?\\s*([\\s\\S]{0,32})", block)
                            if m:
                                used = m.group(1)

                        if bal is None:
                            continue

                        quota = _parse_amount(bal)
                        used_quota = _parse_amount(used) if used is not None else 0.0
                        print(f"✅ {self.account_name}: Current balance: ${quota}, Used: ${used_quota}")
                        return {
                            "success": True,
                            "quota": quota,
                            "used_quota": used_quota,
                            "display": f"Current balance: ${quota}, Used: ${used_quota}",
                        }

                    # 2) 浏览器内 API fetch（避免 response.json 直接炸）
                    headers: dict = {"Accept": "application/json, text/plain, */*"}
                    if api_user is not None:
                        self._inject_api_user_headers(headers, api_user)

                    resp = await self._browser_fetch_json(
                        page,
                        self.provider_config.get_user_info_url(),
                        method="GET",
                        headers=headers,
                    )
                    status = int(resp.get("status", 0) or 0)
                    text_snip = (resp.get("text") or "")[:200]

                    if status in (403, 429, 503) and self._looks_like_cloudflare_interstitial_html(text_snip):
                        await self._ensure_page_past_cloudflare(page)
                        resp = await self._browser_fetch_json(
                            page,
                            self.provider_config.get_user_info_url(),
                            method="GET",
                            headers=headers,
                        )
                        status = int(resp.get("status", 0) or 0)
                        text_snip = (resp.get("text") or "")[:200]

                    data = resp.get("json")
                    if isinstance(data, dict) and isinstance(data.get("data"), dict):
                        user_data = data.get("data", {}) or {}
                        quota = round(float(user_data.get("quota", 0) or 0) / 500000, 2)
                        used_quota = round(float(user_data.get("used_quota", 0) or 0) / 500000, 2)
                        bonus_quota = round(float(user_data.get("bonus_quota", 0) or 0) / 500000, 2)
                        print(
                            f"✅ {self.account_name}: Current balance: ${quota}, Used: ${used_quota}, Bonus: ${bonus_quota}"
                        )
                        return {
                            "success": True,
                            "quota": quota,
                            "used_quota": used_quota,
                            "bonus_quota": bonus_quota,
                            "display": f"Current balance: ${quota}, Used: ${used_quota}, Bonus: ${bonus_quota}",
                        }

                    return {"success": False, "error": f"Failed to get user info, HTTP {status}, body: {text_snip}"}

                except Exception as e:
                    print(f"❌ {self.account_name}: Failed to get user info, {e}")
                    await self._take_screenshot(page, "user_info_error")
                    return {"success": False, "error": "Failed to get user info"}
                finally:
                    await page.close()

    async def confirm_check_in_with_browser(self, auth_cookies: list[dict], api_user: str | int | None = None) -> dict:
        """用浏览器确认今日是否已签到（用于 turnstile_check 站点在 API 被 403 时的兜底）。

        优先在浏览器上下文内 fetch `check_in_status`（若配置存在），失败再回退到 DOM 文本/按钮判定，
        以适配部分站点前端渲染变化导致 DOM 不稳定的情况。
        """
        print(
            f"ℹ️ {self.account_name}: Starting browser to confirm check-in status (using proxy: {'true' if self.camoufox_proxy_config else 'false'})"
        )

        origin = (self.provider_config.origin or "").rstrip("/")
        if not origin:
            return {"success": False, "error": "missing provider origin"}

        def _dedupe_browser_cookies(cookies: list[dict]) -> list[dict]:
            deduped: dict[tuple[str, str, str], dict] = {}
            for cookie in cookies or []:
                if not isinstance(cookie, dict):
                    continue
                name = str(cookie.get("name") or "")
                domain = str(cookie.get("domain") or "")
                path = str(cookie.get("path") or "/")
                if not name or not domain:
                    continue
                deduped[(name, domain, path)] = cookie
            return list(deduped.values())

        with tempfile.TemporaryDirectory(prefix=f"camoufox_{self.safe_account_name}_checkin_status_") as tmp_dir:
            print(f"ℹ️ {self.account_name}: Using temporary directory: {tmp_dir}")
            async with AsyncCamoufox(
                user_data_dir=tmp_dir,
                persistent_context=True,
                headless=False,
                humanize=True,
                locale="zh-CN",
                geoip=True if self.camoufox_proxy_config else False,
                proxy=self.camoufox_proxy_config,
                disable_coop=True,
                config={"forceScopeAccess": True},
                i_know_what_im_doing=True,
            ) as browser:
                page = await browser.new_page()
                try:
                    cookies_to_add: list[dict] = list(auth_cookies or [])
                    # 同步注入缓存的 Cloudflare cookies，避免浏览器确认路径再次被 interstitial 拦截
                    try:
                        cached_cf_cookies = self._load_cf_cookies_from_cache()
                        if cached_cf_cookies:
                            cookies_to_add.extend(cached_cf_cookies)
                    except Exception as e:
                        print(f"⚠️ {self.account_name}: Failed to load cached Cloudflare cookies: {e}")

                    cookies_to_add = _dedupe_browser_cookies(cookies_to_add)
                    if cookies_to_add:
                        try:
                            await browser.add_cookies(cookies_to_add)
                        except Exception as e:
                            print(f"⚠️ {self.account_name}: Failed to add cookies to browser context: {e}")

                    # 进入控制台/签到页
                    paths = []
                    configured = getattr(self.provider_config, "checkin_page_path", None)
                    if configured:
                        paths.append(str(configured))
                    # elysiver: 签到状态只在 /console/checkin 页面可确认，不需要回退到 /console
                    if self.provider_config.name != "elysiver":
                        paths.extend(["/console/checkin", "/console"])

                    seen: set[str] = set()
                    paths = [p for p in paths if p and not (p in seen or seen.add(p))]

                    status_url = self.provider_config.get_check_in_status_url()
                    for path in paths:
                        target_url = f"{origin}{path}"
                        print(f"ℹ️ {self.account_name}: Opening check-in page for confirmation: {target_url}")
                        try:
                            await page.goto(target_url, wait_until="networkidle")
                        except Exception:
                            continue

                        await self._ensure_page_past_cloudflare(page)

                        # 需要时补种 localStorage.user（新前端有时仅靠 cookie 不渲染控制台）
                        if api_user is not None:
                            try:
                                await page.evaluate(
                                    """(apiUser) => {
                                        try {
                                            const key = 'user';
                                            const cur = localStorage.getItem(key);
                                            if (cur) return;
                                            const id = typeof apiUser === 'string' ? parseInt(apiUser, 10) : apiUser;
                                            const user = { id, username: `linuxdo_${id}`, role: 1, status: 1, group: 'default', display_name: 'None' };
                                            localStorage.setItem(key, JSON.stringify(user));
                                        } catch (e) {}
                                    }""",
                                    str(api_user),
                                )
                                await page.reload(wait_until="domcontentloaded")
                                await self._ensure_page_past_cloudflare(page)
                            except Exception:
                                pass

                        try:
                            # SPA 渲染/接口返回可能较慢（尤其是带 WAF/CF 的站点），
                            # 只 sleep 很短时间容易导致 DOM 还没更新就误判未签到。
                            # 这里等待“签到页关键文本/按钮”出现后再做判定。
                            await page.wait_for_function(
                                """() => {
                                    try {
                                        const body = document.body;
                                        if (!body) return false;
                                        const text = (body.innerText || body.textContent || '').toLowerCase();
                                        if (!text) return false;

                                        // 典型签到页元素
                                        if (text.includes('今日已签到')) return true;
                                        if (text.includes('签到记录')) return true;
                                        if (text.includes('累计签到')) return true;
                                        if (text.includes('每日签到')) return true;

                                        // 按钮兜底：出现“签到”相关按钮说明页面已渲染
                                        const btn = Array.from(document.querySelectorAll('button, [role=\"button\"], a'))
                                          .find(el => ((el.innerText || '').includes('签到')));
                                        return !!btn;
                                    } catch (e) {
                                        return false;
                                    }
                                }""",
                                timeout=25000,
                            )
                        except Exception:
                            try:
                                await page.wait_for_timeout(1500)
                            except Exception:
                                pass

                        # 优先在浏览器上下文内调用签到状态接口（若配置存在）
                        if status_url:
                            try:
                                headers: dict = {"Accept": "application/json, text/plain, */*"}
                                if api_user is not None:
                                    self._inject_api_user_headers(headers, api_user)

                                resp = await self._browser_fetch_json(
                                    page, status_url, method="GET", headers=headers
                                )
                                status = int(resp.get("status", 0) or 0)
                                text_snip = (resp.get("text") or "")[:200]

                                if status in (403, 429, 503) and self._looks_like_cloudflare_interstitial_html(
                                    text_snip
                                ):
                                    await self._ensure_page_past_cloudflare(page)
                                    resp = await self._browser_fetch_json(
                                        page, status_url, method="GET", headers=headers
                                    )
                                    status = int(resp.get("status", 0) or 0)

                                data = resp.get("json")
                                if isinstance(data, dict) and data.get("success"):
                                    payload = data.get("data", {}) or {}
                                    can_check_in = payload.get("can_check_in")
                                    if can_check_in is False:
                                        print(f"✅ {self.account_name}: Check-in confirmed by browser API")
                                        return {"success": True, "checked_in": True, "via": "browser_api"}
                                    if can_check_in is True:
                                        print(
                                            f"❌ {self.account_name}: Check-in status indicates not checked in yet "
                                            f"(can_check_in is true)"
                                        )
                                        return {
                                            "success": True,
                                            "checked_in": False,
                                            "can_check_in": True,
                                            "via": "browser_api",
                                        }
                            except Exception:
                                pass

                        # DOM 判定：按钮"今日已签到"通常 disabled；同时兼容文本提示
                        # elysiver 专用检测：等待页面完全加载后检测签到按钮状态
                        if self.provider_config.name == "elysiver":
                            try:
                                # elysiver 页面初始会显示"签到功能未启用"，需要等待真正的签到按钮出现
                                # 等待"今日已签到"或"立即签到"按钮出现，最多等待 15 秒
                                print(f"ℹ️ {self.account_name}: Waiting for elysiver check-in page to fully load...")
                                await page.wait_for_function(
                                    """() => {
                                        try {
                                            const bodyText = document.body?.innerText || '';
                                            // 页面加载完成的标志：出现签到按钮或签到记录
                                            if (bodyText.includes('今日已签到') || bodyText.includes('立即签到')) {
                                                return true;
                                            }
                                            // 如果有签到记录表格，也说明页面已加载
                                            if (bodyText.includes('签到记录') && bodyText.includes('获得额度')) {
                                                return true;
                                            }
                                            return false;
                                        } catch (e) {
                                            return false;
                                        }
                                    }""",
                                    timeout=15000,
                                )
                                print(f"ℹ️ {self.account_name}: elysiver check-in page loaded, checking status...")

                                # 检测签到状态
                                elysiver_result = await page.evaluate(
                                    """() => {
                                        try {
                                            // 遍历所有按钮，查找签到相关按钮
                                            const buttons = Array.from(document.querySelectorAll('button'));
                                            for (const btn of buttons) {
                                                const btnText = btn.innerText || btn.textContent || '';
                                                if (btnText.includes('今日已签到')) {
                                                    return {
                                                        checkedIn: true,
                                                        btnText: btnText.trim(),
                                                        disabled: btn.disabled || btn.getAttribute('aria-disabled') === 'true'
                                                    };
                                                }
                                                if (btnText.includes('立即签到')) {
                                                    return {
                                                        checkedIn: false,
                                                        btnText: btnText.trim(),
                                                        canCheckIn: true
                                                    };
                                                }
                                            }
                                            // 备用：检查页面文本
                                            const bodyText = document.body?.innerText || '';
                                            if (bodyText.includes('今日已签到')) {
                                                return { checkedIn: true, inBody: true };
                                            }
                                            if (bodyText.includes('签到功能未启用')) {
                                                return { checkedIn: false, disabled: true, reason: 'feature_disabled' };
                                            }
                                            return { checkedIn: false, notFound: true };
                                        } catch (e) {
                                            return { checkedIn: false, error: e.message };
                                        }
                                    }"""
                                )

                                if isinstance(elysiver_result, dict):
                                    if elysiver_result.get("checkedIn"):
                                        btn_text = elysiver_result.get("btnText", "")
                                        print(f"✅ {self.account_name}: Check-in confirmed by elysiver detection (button: {btn_text})")
                                        return {"success": True, "checked_in": True}
                                    elif elysiver_result.get("canCheckIn"):
                                        # elysiver: 检测到"立即签到"按钮，点击执行签到
                                        print(f"ℹ️ {self.account_name}: elysiver shows '立即签到' button, clicking to check in...")
                                        try:
                                            # 点击签到按钮
                                            click_result = await page.evaluate(
                                                """() => {
                                                    try {
                                                        const buttons = Array.from(document.querySelectorAll('button'));
                                                        const btn = buttons.find(b => (b.innerText || '').includes('立即签到'));
                                                        if (btn && !btn.disabled) {
                                                            btn.click();
                                                            return { clicked: true };
                                                        }
                                                        return { clicked: false, reason: 'button not found or disabled' };
                                                    } catch (e) {
                                                        return { clicked: false, error: e.message };
                                                    }
                                                }"""
                                            )
                                            if click_result and click_result.get("clicked"):
                                                print(f"ℹ️ {self.account_name}: Clicked check-in button, waiting for response...")
                                                # 等待签到完成（等待按钮文字变化或出现成功提示）
                                                try:
                                                    await page.wait_for_function(
                                                        """() => {
                                                            try {
                                                                const bodyText = document.body?.innerText || '';
                                                                // 签到成功的标志
                                                                if (bodyText.includes('今日已签到')) return true;
                                                                if (bodyText.includes('签到成功')) return true;
                                                                // 检查按钮是否变成已签到状态
                                                                const buttons = Array.from(document.querySelectorAll('button'));
                                                                const btn = buttons.find(b => {
                                                                    const text = b.innerText || '';
                                                                    return text.includes('今日已签到') ||
                                                                           (text.includes('签到') && (b.disabled || b.getAttribute('aria-disabled') === 'true'));
                                                                });
                                                                return !!btn;
                                                            } catch (e) {
                                                                return false;
                                                            }
                                                        }""",
                                                        timeout=10000,
                                                    )
                                                    print(f"✅ {self.account_name}: elysiver check-in successful!")
                                                    return {"success": True, "checked_in": True}
                                                except Exception:
                                                    # 超时后再次检测状态
                                                    await page.wait_for_timeout(2000)
                                                    recheck_result = await page.evaluate(
                                                        """() => {
                                                            try {
                                                                const bodyText = document.body?.innerText || '';
                                                                if (bodyText.includes('今日已签到') || bodyText.includes('签到成功')) {
                                                                    return { checkedIn: true };
                                                                }
                                                                const buttons = Array.from(document.querySelectorAll('button'));
                                                                for (const btn of buttons) {
                                                                    const text = btn.innerText || '';
                                                                    if (text.includes('今日已签到')) {
                                                                        return { checkedIn: true, btnText: text };
                                                                    }
                                                                    if (text.includes('立即签到') && !btn.disabled) {
                                                                        return { checkedIn: false, stillCanCheckIn: true };
                                                                    }
                                                                }
                                                                return { checkedIn: false, unknown: true };
                                                            } catch (e) {
                                                                return { checkedIn: false, error: e.message };
                                                            }
                                                        }"""
                                                    )
                                                    if recheck_result and recheck_result.get("checkedIn"):
                                                        print(f"✅ {self.account_name}: elysiver check-in confirmed after recheck")
                                                        return {"success": True, "checked_in": True}
                                                    else:
                                                        print(f"⚠️ {self.account_name}: elysiver check-in status unclear after click: {recheck_result}")
                                                        # 如果点击后状态不明确，尝试截图诊断
                                                        try:
                                                            await self._take_screenshot(page, "elysiver_checkin_after_click")
                                                        except Exception:
                                                            pass
                                                        return {"success": False, "checked_in": False, "error": "Check-in status unclear after click"}
                                            else:
                                                print(f"⚠️ {self.account_name}: Failed to click check-in button: {click_result}")
                                                return {"success": False, "checked_in": False, "error": "Failed to click check-in button"}
                                        except Exception as click_err:
                                            print(f"⚠️ {self.account_name}: Error clicking check-in button: {click_err}")
                                            return {"success": False, "checked_in": False, "error": f"Click error: {click_err}"}
                                    elif elysiver_result.get("reason") == "feature_disabled":
                                        print(f"⚠️ {self.account_name}: elysiver check-in feature is disabled by admin")
                                        # 功能被禁用时视为成功（无需签到）
                                        return {"success": True, "checked_in": True, "reason": "feature_disabled"}
                                    else:
                                        print(f"⚠️ {self.account_name}: elysiver check-in status unclear: {elysiver_result}")
                            except Exception as ely_err:
                                print(f"⚠️ {self.account_name}: elysiver check-in detection error: {ely_err}")
                                # 超时可能是页面没有完全加载，尝试截图诊断
                                try:
                                    await self._take_screenshot(page, "elysiver_checkin_timeout")
                                except Exception:
                                    pass

                        try:
                            result = await page.evaluate(
                                """() => {
                                    try {
                                        const text = (document.body ? (document.body.innerText || document.body.textContent || '') : '') || '';
                                        const low = text.toLowerCase();
                                        const hasDoneText = low.includes('今日已签到') || low.includes('已签到') || low.includes('already checked');
                                        const btn = Array.from(document.querySelectorAll('button, [role=\"button\"], a'))
                                            .find(el => ((el.innerText || '').includes('今日已签到') || (el.innerText || '').includes('已签到')));
                                        const disabled = !!(btn && (btn.disabled || (btn.getAttribute && btn.getAttribute('aria-disabled') === 'true')));
                                        return { hasDoneText, disabled, title: document.title || '' };
                                    } catch (e) {
                                        return { hasDoneText: false, disabled: false, title: '' };
                                    }
                                }"""
                            )
                        except Exception:
                            result = None

                        if isinstance(result, dict) and (result.get("disabled") or result.get("hasDoneText")):
                            print(f"✅ {self.account_name}: Check-in confirmed by browser DOM")
                            return {"success": True, "checked_in": True}

                    return {"success": False, "error": "check-in not confirmed by browser DOM"}
                except Exception as e:
                    try:
                        await self._take_screenshot(page, "check_in_confirm_error")
                    except Exception:
                        pass
                    return {"success": False, "error": f"browser confirm error: {e}"}
                finally:
                    try:
                        await page.close()
                    except Exception:
                        pass

    async def get_user_info(self, client: httpx.Client, headers: dict) -> dict:
        """获取用户信息"""
        try:
            # 在请求用户信息之前尝试复用已缓存的 Cloudflare 相关 cookies
            try:
                cached_cf_cookies = self._load_cf_cookies_from_cache()
                if cached_cf_cookies:
                    self._apply_cf_cookies_to_client(client, cached_cf_cookies)
            except Exception as e:
                print(f"⚠️ {self.account_name}: Failed to apply cached Cloudflare cookies: {e}")

            response = client.get(self.provider_config.get_user_info_url(), headers=headers, timeout=30)

            if response.status_code == 200:
                json_data = self._check_and_handle_response(response, "get_user_info")
                if json_data is None:
                    # 尝试从浏览器获取用户信息
                    # print(f"ℹ️ {self.account_name}: Getting user info from browser")
                    # try:
                    #     user_info_result = await self.get_user_info_with_browser()
                    #     if user_info_result.get("success"):
                    #         return user_info_result
                    #     else:
                    #         error_msg = user_info_result.get("error", "Unknown error")
                    #         print(f"⚠️ {self.account_name}: {error_msg}")
                    # except Exception as browser_err:
                    #     print(
                    #         f"⚠️ {self.account_name}: "
                    #         f"Failed to get user info from browser: {browser_err}"
                    #     )

                    return {
                        "success": False,
                        "error": "Failed to get user info: Invalid response type (saved to logs)",
                    }

                if json_data.get("success"):
                    user_data = json_data.get("data", {})
                    quota = round(user_data.get("quota", 0) / 500000, 2)
                    used_quota = round(user_data.get("used_quota", 0) / 500000, 2)
                    return {
                        "success": True,
                        "quota": quota,
                        "used_quota": used_quota,
                        "display": f"Current balance: ${quota}, Used: ${used_quota}",
                    }
                else:
                    error_msg = json_data.get("message", "Unknown error")
                    return {
                        "success": False,
                        "error": f"Failed to get user info: {error_msg}",
                    }
            return {
                "success": False,
                "error": f"Failed to get user info: HTTP {response.status_code}",
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to get user info, {e}",
            }

    def execute_check_in(self, client: httpx.Client, headers: dict, api_user: str | int):
        """执行签到请求"""
        print(f"🌐 {self.account_name}: Executing check-in")

        checkin_headers = headers.copy()
        checkin_headers.update({"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"})

        # 在发起签到请求之前尝试复用已缓存的 Cloudflare 相关 cookies
        try:
            cached_cf_cookies = self._load_cf_cookies_from_cache()
            if cached_cf_cookies:
                self._apply_cf_cookies_to_client(client, cached_cf_cookies)
        except Exception as e:
            print(f"⚠️ {self.account_name}: Failed to apply cached Cloudflare cookies: {e}")

        response = client.post(self.provider_config.get_sign_in_url(api_user), headers=checkin_headers, timeout=30)

        print(f"📨 {self.account_name}: Response status code {response.status_code}")

        if response.status_code == 200:
            json_data = self._check_and_handle_response(response, "execute_check_in")
            if json_data is None:
                # 如果不是 JSON 响应（可能是 HTML），检查是否包含成功标识
                if "success" in response.text.lower():
                    print(f"✅ {self.account_name}: Check-in successful!")
                    return True
                else:
                    print(f"❌ {self.account_name}: Check-in failed - Invalid response format")
                    return False

            # 通用成功判断
            if json_data.get("ret") == 1 or json_data.get("code") == 0 or json_data.get("success"):
                print(f"✅ {self.account_name}: Check-in successful!")
                return True

            # 对于提示“已经签到过”的情况，视为成功，避免重复通知
            error_msg = json_data.get("msg", json_data.get("message", "Unknown error"))
            if isinstance(error_msg, str) and ("已签到" in error_msg or "已经签到" in error_msg):
                print(f"ℹ️ {self.account_name}: {error_msg} (already checked in, treat as success)")
                return True

            print(f"❌ {self.account_name}: Check-in failed - {error_msg}")
            return False
        else:
            print(f"❌ {self.account_name}: Check-in failed - HTTP {response.status_code}")
            return False

    async def get_check_in_status(self, client: httpx.Client, headers: dict) -> dict | None:
        """获取签到状态（仅在配置了 check_in_status_path 时可用）"""
        status_url = self.provider_config.get_check_in_status_url()
        if not status_url:
            return None

        try:
            print(f"ℹ️ {self.account_name}: Fetching check-in status from {status_url}")

            # 在查询签到状态之前尝试复用已缓存的 Cloudflare 相关 cookies
            try:
                cached_cf_cookies = self._load_cf_cookies_from_cache()
                if cached_cf_cookies:
                    self._apply_cf_cookies_to_client(client, cached_cf_cookies)
            except Exception as e:
                print(f"⚠️ {self.account_name}: Failed to apply cached Cloudflare cookies: {e}")

            resp = client.get(status_url, headers=headers, timeout=30)
            if resp.status_code != 200:
                print(
                    f"⚠️ {self.account_name}: Failed to get check-in status - HTTP {resp.status_code}"
                )
                return None

            data = self._check_and_handle_response(resp, "check_in_status")
            if not data or not isinstance(data, dict):
                print(f"⚠️ {self.account_name}: Invalid check-in status response")
                return None

            return data
        except Exception as e:
            print(f"⚠️ {self.account_name}: Error getting check-in status: {e}")
            return None

    async def check_in_with_cookies(
        self, cookies: dict, api_user: str | int, needs_check_in: bool | None = None
    ) -> tuple[bool, dict]:
        """使用已有 cookies 执行签到操作"""
        if self.provider_config.name == "runanytime":
            return False, {"error": "runanytime 新签到方式需要 linux.do 登录 fuli 获取兑换码，cookies 方式不再支持"}

        print(
            f"ℹ️ {self.account_name}: Executing check-in with existing cookies (using proxy: {'true' if self.http_proxy_config else 'false'})"
        )

        client = httpx.Client(http2=True, timeout=30.0, proxy=self.http_proxy_config)
        try:
            client.cookies.update(cookies)

            headers = {
                "User-Agent": self.user_agent,
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Referer": self.provider_config.get_login_url(),
                "Origin": self.provider_config.origin,
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
            }
            self._inject_api_user_headers(headers, api_user)

            # wzw 专用逻辑：先签到，再查余额，避免只拿到签到前的额度
            if self.provider_config.name == "wzw":
                # 只在配置了独立签到接口且未显式禁用签到时调用签到
                if needs_check_in is None and self.provider_config.needs_manual_check_in():
                    success = self.execute_check_in(client, headers, api_user)
                    if not success:
                        return False, {"error": "Check-in failed"}

                user_info = await self.get_user_info(client, headers)
                if user_info and user_info.get("success"):
                    success_msg = user_info.get("display", "User info retrieved successfully")
                    print(f"✅ {success_msg} (after check-in)")
                    return True, user_info
                elif user_info:
                    error_msg = user_info.get("error", "Unknown error")
                    print(f"❌ {self.account_name}: {error_msg}")
                    return False, {"error": "Failed to get user info after check-in"}

                return False, {"error": "Failed to get user info after check-in"}

            # 其它站点沿用原有语义：先查一次用户信息，再按配置决定是否额外调用签到接口
            user_info = await self.get_user_info(client, headers)
            if user_info and user_info.get("success"):
                success_msg = user_info.get("display", "User info retrieved successfully")
                print(f"✅ {success_msg}")
            elif user_info:
                error_msg = user_info.get("error", "Unknown error")
                print(f"❌ {self.account_name}: {error_msg}")

                # 对于启用了 Turnstile 校验的站点（如 runanytime / elysiver），
                # 如果直接通过 HTTP 获取用户信息失败，则回退到在浏览器中通过相同 cookies 获取，
                # 避免前端显示“已签到”但因为 WAF / Cloudflare 导致后端检查失败。
                if getattr(self.provider_config, "turnstile_check", False):
                    try:
                        print(
                            f"ℹ️ {self.account_name}: Falling back to browser-based user info due to previous error"
                        )
                        # 将当前 httpx 客户端的 cookies 转换为 Camoufox add_cookies 所需的列表格式
                        camoufox_cookies: list[dict] = []
                        parsed_domain = urlparse(self.provider_config.origin).netloc
                        for cookie in client.cookies.jar:
                            cookie_dict: dict = {
                                "name": cookie.name,
                                "value": cookie.value,
                                "domain": cookie.domain if cookie.domain else parsed_domain,
                                "path": cookie.path or "/",
                                "secure": cookie.secure,
                                "httpOnly": cookie.has_nonstandard_attr("httponly"),
                                "sameSite": cookie.samesite if cookie.has_nonstandard_attr("samesite") else "Lax",
                            }
                            # 只有在 expires 为数字类型时才设置，避免 Camoufox 类型错误
                            if isinstance(cookie.expires, (int, float)):
                                cookie_dict["expires"] = float(cookie.expires)

                            camoufox_cookies.append(cookie_dict)

                        browser_user_info = await self.get_user_info_with_browser(camoufox_cookies, api_user)
                        if browser_user_info and browser_user_info.get("success"):
                            print(
                                f"✅ {self.account_name}: Got user info via browser fallback: "
                                f"{browser_user_info.get('display', '')}"
                            )
                            user_info = browser_user_info
                        else:
                            fb_err = (
                                browser_user_info.get("error", "Unknown error")
                                if browser_user_info
                                else "Unknown error"
                            )
                            print(
                                f"❌ {self.account_name}: Browser-based user info fallback failed: {fb_err}"
                            )
                            return False, {"error": "Failed to get user info"}
                    except Exception as fb_ex:
                        print(
                            f"❌ {self.account_name}: Exception during browser-based user info fallback: {fb_ex}"
                        )
                        return False, {"error": "Failed to get user info"}
                else:
                    return False, {"error": "Failed to get user info"}

            # 1) 传统站点：通过独立签到接口完成（非 wzw 保持原逻辑：用签到前的余额做展示）
            if needs_check_in is None and self.provider_config.needs_manual_check_in():
                success = self.execute_check_in(client, headers, api_user)
                return success, user_info if user_info else {"error": "No user info available"}

            # 2) 特殊站点（如 runanytime）：需要根据签到状态接口判断是否真的签到成功
            if getattr(self.provider_config, "turnstile_check", False):
                # elysiver：check_in_status 的 HTTP 直连更容易触发 CF/WAF，直接用浏览器上下文确认
                if self.provider_config.name == "elysiver":
                    try:
                        camoufox_cookies = self._cookie_dict_to_browser_cookies(cookies, self.provider_config.origin)
                        confirm = await self.confirm_check_in_with_browser(camoufox_cookies, api_user)
                        if confirm and confirm.get("success") and confirm.get("checked_in") is True:
                            print(f"✅ {self.account_name}: Check-in confirmed by browser")
                            return True, user_info if user_info else confirm
                        if confirm and confirm.get("success") and confirm.get("checked_in") is False:
                            return False, {"error": "Check-in status indicates not checked in yet"}
                        err = confirm.get("error") if isinstance(confirm, dict) else None
                        print(
                            f"❌ {self.account_name}: Unable to confirm check-in status for provider "
                            f"'{self.provider_config.name}'"
                            + (f": {err}" if err else "")
                        )
                        return False, {"error": "Unable to confirm check-in status"}
                    except Exception as e:
                        print(
                            f"❌ {self.account_name}: Unable to confirm check-in status for provider "
                            f"'{self.provider_config.name}': {e}"
                        )
                        return False, {"error": "Unable to confirm check-in status"}
                else:
                    status_data = await self.get_check_in_status(client, headers)
                    if status_data and status_data.get("success"):
                        data = status_data.get("data", {})
                        can_check_in = data.get("can_check_in")

                        # can_check_in 为 False：表示今天已经签到过（本次或之前），视为成功
                        if can_check_in is False:
                            print(
                                f"✅ {self.account_name}: Check-in status confirmed (already checked in today)"
                            )
                            return True, user_info if user_info else status_data

                        # can_check_in 为 True：仍然可以签到，说明本次流程未真正完成签到
                        if can_check_in is True:
                            print(
                                f"❌ {self.account_name}: Check-in status indicates not checked in yet "
                                f"(can_check_in is true)"
                            )
                            return False, {
                                "error": "Check-in status indicates not checked in yet (can_check_in=true)"
                            }

                # API 被 Cloudflare/WAF 拦截时：回退到浏览器 DOM 确认（例如 elysiver /console/checkin 显示“今日已签到”）
                try:
                    camoufox_cookies = self._cookie_dict_to_browser_cookies(cookies, self.provider_config.origin)
                    confirm = await self.confirm_check_in_with_browser(camoufox_cookies, api_user)
                    if confirm and confirm.get("success") and confirm.get("checked_in") is True:
                        print(
                            f"✅ {self.account_name}: Check-in confirmed by browser DOM fallback"
                        )
                        return True, user_info if user_info else confirm
                except Exception:
                    pass

                print(
                    f"❌ {self.account_name}: Unable to confirm check-in status for provider "
                    f"'{self.provider_config.name}'"
                )
                return False, {"error": "Unable to confirm check-in status"}

            # 3) 其它站点：维持原有“访问用户信息即视为签到完成”的语义
            print(f"ℹ️ {self.account_name}: Check-in completed automatically (triggered by user info request)")
            return True, user_info if user_info else {"error": "No user info available"}

        except Exception as e:
            print(f"❌ {self.account_name}: Error occurred during check-in process - {e}")
            return False, {"error": "Error occurred during check-in process"}
        finally:
            client.close()

    async def check_in_with_github(self, username: str, password: str, waf_cookies: dict) -> tuple[bool, dict]:
        """使用 GitHub 账号执行签到操作"""
        print(
            f"ℹ️ {self.account_name}: Executing check-in with GitHub account (using proxy: {'true' if self.http_proxy_config else 'false'})"
        )

        client = httpx.Client(http2=True, timeout=30.0, proxy=self.http_proxy_config)
        try:
            client.cookies.update(waf_cookies)

            headers = {
                "User-Agent": self.user_agent,
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Referer": self.provider_config.get_login_url(),
                "Origin": self.provider_config.origin,
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
            }
            self._inject_api_user_headers(headers, "-1")

            # 获取 OAuth 客户端 ID
            # 优先使用 provider_config 中的 client_id
            if self.provider_config.github_client_id:
                client_id_result = {
                    "success": True,
                    "client_id": self.provider_config.github_client_id,
                }
                print(f"ℹ️ {self.account_name}: Using GitHub client ID from config")
            else:
                client_id_result = await self.get_auth_client_id(client, headers, "github")
                if client_id_result and client_id_result.get("success"):
                    print(f"ℹ️ {self.account_name}: Got client ID for GitHub: {client_id_result['client_id']}")
                else:
                    error_msg = client_id_result.get("error", "Unknown error")
                    print(f"❌ {self.account_name}: {error_msg}")
                    return False, {"error": "Failed to get GitHub client ID"}

            # # 获取 OAuth 认证状态
            auth_state_result = await self.get_auth_state(
                client=client,
                headers=headers,
            )
            if auth_state_result and auth_state_result.get("success"):
                print(f"ℹ️ {self.account_name}: Got auth state for GitHub: {auth_state_result['state']}")
            else:
                error_msg = auth_state_result.get("error", "Unknown error")
                print(f"❌ {self.account_name}: {error_msg}")
                return False, {"error": "Failed to get GitHub auth state"}

            # 生成缓存文件路径
            username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
            cache_file_path = f"{self.storage_state_dir}/github_{username_hash}_storage_state.json"

            from sign_in_with_github import GitHubSignIn

            github = GitHubSignIn(
                account_name=self.account_name,
                provider_config=self.provider_config,
                username=username,
                password=password,
            )

            success, result_data = await github.signin(
                client_id=client_id_result["client_id"],
                auth_state=auth_state_result.get("state"),
                auth_cookies=auth_state_result.get("cookies", []),
                cache_file_path=cache_file_path,
            )

            # 检查是否成功获取 cookies 和 api_user
            if success and "cookies" in result_data and "api_user" in result_data:
                # 统一调用 check_in_with_cookies 执行签到
                user_cookies = result_data["cookies"]
                api_user = result_data["api_user"]

                merged_cookies = {**waf_cookies, **user_cookies}
                # GitHub 认证获取到的 cookies/api_user 已完成登录，后续只需获取用户信息
                return await self.check_in_with_cookies(merged_cookies, api_user, needs_check_in=False)
            elif success and "code" in result_data and "state" in result_data:
                # 收到 OAuth code，通过 HTTP 调用回调接口获取 api_user
                print(f"ℹ️ {self.account_name}: Received OAuth code, calling callback API")

                callback_url = httpx.URL(self.provider_config.get_github_auth_url()).copy_with(params=result_data)
                print(f"ℹ️ {self.account_name}: Callback URL: {callback_url}")
                try:
                    # 将 Camoufox 格式的 cookies 转换为 httpx 格式
                    auth_cookies_list = auth_state_result.get("cookies", [])
                    for cookie_dict in auth_cookies_list:
                        client.cookies.set(cookie_dict["name"], cookie_dict["value"])

                    # 在调用 GitHub OAuth 回调前尝试复用已缓存的 Cloudflare 相关 cookies
                    try:
                        cached_cf_cookies = self._load_cf_cookies_from_cache()
                        if cached_cf_cookies:
                            self._apply_cf_cookies_to_client(client, cached_cf_cookies)
                    except Exception as e:
                        print(f"⚠️ {self.account_name}: Failed to apply cached Cloudflare cookies: {e}")

                    response = client.get(callback_url, headers=headers, timeout=30)

                    if response.status_code == 200:
                        json_data = self._check_and_handle_response(response, "github_oauth_callback")
                        if json_data and json_data.get("success"):
                            user_data = json_data.get("data", {})
                            api_user = user_data.get("id")

                            if api_user:
                                print(f"✅ {self.account_name}: Got api_user from callback: {api_user}")

                                # 提取 cookies
                                user_cookies = {}
                                for cookie in response.cookies.jar:
                                    user_cookies[cookie.name] = cookie.value

                                print(
                                    f"ℹ️ {self.account_name}: Extracted {len(user_cookies)} user cookies: "
                                    f"{list(user_cookies.keys())}"
                                )
                                merged_cookies = {**waf_cookies, **user_cookies}
                                return await self.check_in_with_cookies(
                                    merged_cookies, api_user, needs_check_in=False
                                )
                            else:
                                print(f"❌ {self.account_name}: No user ID in callback response")
                                return False, {"error": "No user ID in OAuth callback response"}
                        else:
                            error_msg = json_data.get("message", "Unknown error") if json_data else "Invalid response"
                            print(f"❌ {self.account_name}: OAuth callback failed: {error_msg}")
                            return False, {"error": f"OAuth callback failed: {error_msg}"}
                    else:
                        print(f"❌ {self.account_name}: OAuth callback HTTP {response.status_code}")
                        return False, {"error": f"OAuth callback HTTP {response.status_code}"}
                except Exception as callback_err:
                    print(f"❌ {self.account_name}: Error calling OAuth callback: {callback_err}")
                    return False, {"error": f"OAuth callback error: {callback_err}"}
            else:
                # 返回错误信息
                return False, result_data

        except Exception as e:
            print(f"❌ {self.account_name}: Error occurred during check-in process - {e}")
            return False, {"error": "GitHub check-in process error"}
        finally:
            client.close()

    async def check_in_with_linuxdo(
        self,
        username: str,
        password: str,
        waf_cookies: dict,
    ) -> tuple[bool, dict]:
        """使用 Linux.do 账号执行签到操作

        Args:
            username: Linux.do 用户名
            password: Linux.do 密码
            waf_cookies: WAF cookies
        """
        print(
            f"ℹ️ {self.account_name}: Executing check-in with Linux.do account (using proxy: {'true' if self.http_proxy_config else 'false'})"
        )

        client = httpx.Client(http2=True, timeout=30.0, proxy=self.http_proxy_config)
        try:
            client.cookies.update(waf_cookies)

            headers = {
                "User-Agent": self.user_agent,
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Referer": self.provider_config.get_login_url(),
                "Origin": self.provider_config.origin,
                "Connection": "keep-alive",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
            }
            self._inject_api_user_headers(headers, "-1")

            # 获取 OAuth 客户端 ID
            # 优先使用 provider_config 中的 client_id
            if self.provider_config.linuxdo_client_id:
                client_id_result = {
                    "success": True,
                    "client_id": self.provider_config.linuxdo_client_id,
                }
                print(f"ℹ️ {self.account_name}: Using Linux.do client ID from config")
            else:
                client_id_result = await self.get_auth_client_id(client, headers, "linuxdo")
                if client_id_result and client_id_result.get("success"):
                    print(f"ℹ️ {self.account_name}: Got client ID for Linux.do: {client_id_result['client_id']}")
                else:
                    error_msg = client_id_result.get("error", "Unknown error")
                    print(f"❌ {self.account_name}: {error_msg}")
                    return False, {"error": "Failed to get Linux.do client ID"}

            # 获取 OAuth 认证状态（与 runanytime 保持一致，统一通过 HTTP 接口获取）
            auth_state_result = await self.get_auth_state(
                client=client,
                headers=headers,
            )
            if auth_state_result and auth_state_result.get("success"):
                print(f"ℹ️ {self.account_name}: Got auth state for Linux.do: {auth_state_result['state']}")
            else:
                error_msg = auth_state_result.get("error", "Unknown error")
                print(f"❌ {self.account_name}: {error_msg}")
                return False, {"error": "Failed to get Linux.do auth state"}

            # 生成缓存文件路径
            username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
            cache_file_path = f"{self.storage_state_dir}/linuxdo_{username_hash}_storage_state.json"

            from sign_in_with_linuxdo import LinuxDoSignIn

            linuxdo = LinuxDoSignIn(
                account_name=self.account_name,
                provider_config=self.provider_config,
                username=username,
                password=password,
            )

            success, result_data = await linuxdo.signin(
                client_id=client_id_result["client_id"],
                auth_state=auth_state_result["state"],
                auth_cookies=auth_state_result.get("cookies", []),
                cache_file_path=cache_file_path,
            )

            # 如果 session verify 失败需要重试，重新获取 auth_state 并执行完整登录流程
            if not success and result_data.get("retry"):
                print(f"ℹ️ {self.account_name}: Session verify failed, retrying with fresh login...")

                # 重新获取 auth_state（因为之前的可能已过期）
                retry_auth_state_result = await self.get_auth_state(
                    client=client,
                    headers=headers,
                )
                if retry_auth_state_result.get("success"):
                    # 第二次调用 signin，由于缓存已删除，会走完整登录流程
                    success, result_data = await linuxdo.signin(
                        client_id=client_id_result["client_id"],
                        auth_state=retry_auth_state_result["state"],
                        auth_cookies=retry_auth_state_result.get("cookies", []),
                        cache_file_path=cache_file_path,
                    )
                else:
                    print(f"⚠️ {self.account_name}: Failed to get new auth_state for retry")

            # 检查是否成功获取 cookies 和 api_user
            if success and "cookies" in result_data and "api_user" in result_data:
                user_cookies = result_data["cookies"]
                api_user = result_data["api_user"]

                # runanytime：改为 fuli 获取兑换码 + 控制台兑换
                if self.provider_config.name == "runanytime":
                    return await self._runanytime_check_in_via_fuli_and_topup(
                        runanytime_cookies=user_cookies,
                        api_user=api_user,
                        linuxdo_username=username,
                        linuxdo_password=password,
                        linuxdo_cache_file_path=cache_file_path,
                    )

                # 对于启用了 Turnstile 的站点（如 runanytime / elysiver），
                # 如果在 LinuxDo 登录流程中已经在 /app/me 页面解析出了余额信息，
                # 则直接使用该信息作为最终结果，避免再次通过 HTTP 或额外浏览器访问。
                if getattr(self.provider_config, "turnstile_check", False) and "user_info" in result_data:
                    user_info = result_data["user_info"]
                    # 维持与其它路径一致的返回格式
                    return True, user_info

                # 其它站点沿用原有逻辑：统一调用 check_in_with_cookies 执行签到 / 获取余额
                merged_cookies = {**waf_cookies, **user_cookies}
                return await self.check_in_with_cookies(merged_cookies, api_user)
            elif success and "code" in result_data and "state" in result_data:
                # 收到 OAuth code，通过 HTTP 调用回调接口获取 api_user
                print(f"ℹ️ {self.account_name}: Received OAuth code, calling callback API")

                callback_url = httpx.URL(self.provider_config.get_linuxdo_auth_url()).copy_with(params=result_data)
                print(f"ℹ️ {self.account_name}: Callback URL: {callback_url}")
                try:
                    # 将 Camoufox 格式的 cookies 转换为 httpx 格式
                    auth_cookies_list = auth_state_result.get("cookies", [])
                    for cookie_dict in auth_cookies_list:
                        client.cookies.set(cookie_dict["name"], cookie_dict["value"])

                    # 在调用 Linux.do OAuth 回调前尝试复用已缓存的 Cloudflare 相关 cookies
                    try:
                        cached_cf_cookies = self._load_cf_cookies_from_cache()
                        if cached_cf_cookies:
                            self._apply_cf_cookies_to_client(client, cached_cf_cookies)
                    except Exception as e:
                        print(f"⚠️ {self.account_name}: Failed to apply cached Cloudflare cookies: {e}")

                    response = client.get(callback_url, headers=headers, timeout=30)

                    if response.status_code == 200:
                        json_data = self._check_and_handle_response(response, "linuxdo_oauth_callback")
                        if json_data and json_data.get("success"):
                            user_data = json_data.get("data", {})
                            api_user = user_data.get("id")

                            if api_user:
                                print(f"✅ {self.account_name}: Got api_user from callback: {api_user}")

                                # 提取 cookies：使用 client 当前 cookie jar（包含回调前已有的 cf_clearance 等），
                                # 避免只拿到 response.set-cookie 的子集导致后续 /api/user/self 401/重定向。
                                try:
                                    user_cookies = dict(client.cookies)
                                except Exception:
                                    user_cookies = {}
                                    try:
                                        for cookie in client.cookies.jar:
                                            user_cookies[cookie.name] = cookie.value
                                    except Exception:
                                        pass

                                print(
                                    f"ℹ️ {self.account_name}: Extracted {len(user_cookies)} user cookies: "
                                    f"{list(user_cookies.keys())}"
                                )

                                # runanytime：改为 fuli 获取兑换码 + 控制台兑换
                                if self.provider_config.name == "runanytime":
                                    return await self._runanytime_check_in_via_fuli_and_topup(
                                        runanytime_cookies=user_cookies,
                                        api_user=api_user,
                                        linuxdo_username=username,
                                        linuxdo_password=password,
                                        linuxdo_cache_file_path=cache_file_path,
                                    )

                                merged_cookies = {**waf_cookies, **user_cookies}
                                return await self.check_in_with_cookies(merged_cookies, api_user)
                            else:
                                print(f"❌ {self.account_name}: No user ID in callback response")
                                return False, {"error": "No user ID in OAuth callback response"}
                        else:
                            error_msg = json_data.get("message", "Unknown error") if json_data else "Invalid response"
                            print(f"❌ {self.account_name}: OAuth callback failed: {error_msg}")
                            return False, {"error": f"OAuth callback failed: {error_msg}"}
                    else:
                        print(f"❌ {self.account_name}: OAuth callback HTTP {response.status_code}")
                        return False, {"error": f"OAuth callback HTTP {response.status_code}"}
                except Exception as callback_err:
                    print(f"❌ {self.account_name}: Error calling OAuth callback: {callback_err}")
                    return False, {"error": f"OAuth callback error: {callback_err}"}
            else:
                # 返回错误信息
                return False, result_data

        except Exception as e:
            print(f"❌ {self.account_name}: Error occurred during check-in process - {e}")
            return False, {"error": "Linux.do check-in process error"}

    async def execute(self) -> list[tuple[str, bool, dict | None]]:
        """为单个账号执行签到操作，支持多种认证方式"""
        print(f"\n\n⏳ Starting to process {self.account_name}")

        waf_cookies = {}
        if self.provider_config.needs_waf_cookies():
            waf_cookies = await self.get_waf_cookies_with_browser()
            if not waf_cookies:
                print(f"❌ {self.account_name}: Unable to get WAF cookies")
                # 获取失败时使用空字典，避免后续合并 cookies 出现 NoneType 错误
                waf_cookies = {}
                print(f"ℹ️ {self.account_name}: Continue without WAF cookies")
        else:
            print(f"ℹ️ {self.account_name}: Bypass WAF not required, using user cookies directly")

        # 解析账号配置
        cookies_data = self.account_config.cookies
        github_info = self.account_config.github
        linuxdo_info = self.account_config.linux_do
        results = []

        # 尝试 cookies 认证
        if cookies_data:
            print(f"\nℹ️ {self.account_name}: Trying cookies authentication")
            try:
                user_cookies = parse_cookies(cookies_data)
                if not user_cookies:
                    print(f"❌ {self.account_name}: Invalid cookies format")
                    results.append(("cookies", False, {"error": "Invalid cookies format"}))
                else:
                    api_user = self.account_config.api_user
                    if not api_user:
                        print(f"❌ {self.account_name}: API user identifier not found for cookies")
                        results.append(("cookies", False, {"error": "API user identifier not found"}))
                    else:
                        # 使用已有 cookies 执行签到
                        all_cookies = {**waf_cookies, **user_cookies}
                        success, user_info = await self.check_in_with_cookies(all_cookies, api_user)
                        if success:
                            print(f"✅ {self.account_name}: Cookies authentication successful")
                            results.append(("cookies", True, user_info))
                        else:
                            print(f"❌ {self.account_name}: Cookies authentication failed")
                            results.append(("cookies", False, user_info))
            except Exception as e:
                print(f"❌ {self.account_name}: Cookies authentication error: {e}")
                results.append(("cookies", False, {"error": str(e)}))

        # 尝试 GitHub 认证
        if github_info:
            print(f"\nℹ️ {self.account_name}: Trying GitHub authentication")
            try:
                username = github_info.get("username")
                password = github_info.get("password")
                if not username or not password:
                    print(f"❌ {self.account_name}: Incomplete GitHub account information")
                    results.append(("github", False, {"error": "Incomplete GitHub account information"}))
                else:
                    # 使用 GitHub 账号执行签到
                    success, user_info = await self.check_in_with_github(username, password, waf_cookies)
                    if success:
                        print(f"✅ {self.account_name}: GitHub authentication successful")
                        results.append(("github", True, user_info))
                    else:
                        print(f"❌ {self.account_name}: GitHub authentication failed")
                        results.append(("github", False, user_info))
            except Exception as e:
                print(f"❌ {self.account_name}: GitHub authentication error: {e}")
                results.append(("github", False, {"error": str(e)}))

        # 尝试 Linux.do 认证
        if linuxdo_info:
            print(f"\nℹ️ {self.account_name}: Trying Linux.do authentication")
            try:
                username = linuxdo_info.get("username")
                password = linuxdo_info.get("password")
                if not username or not password:
                    print(f"❌ {self.account_name}: Incomplete Linux.do account information")
                    results.append(("linux.do", False, {"error": "Incomplete Linux.do account information"}))
                else:
                    # 使用 Linux.do 账号执行签到
                    success, user_info = await self.check_in_with_linuxdo(
                        username,
                        password,
                        waf_cookies,
                    )
                    if success:
                        print(f"✅ {self.account_name}: Linux.do authentication successful")
                        results.append(("linux.do", True, user_info))
                    else:
                        print(f"❌ {self.account_name}: Linux.do authentication failed")
                        results.append(("linux.do", False, user_info))
            except Exception as e:
                # 避免在异常信息中直接打印代理 URL 等敏感数据
                msg = str(e)
                if "Unknown scheme for proxy URL" in msg:
                    safe_msg = (
                        "Linux.do authentication error: invalid proxy configuration "
                        "(missing scheme like 'http://' or 'socks5://')"
                    )
                else:
                    safe_msg = f"Linux.do authentication error: {msg}"
                print(f"❌ {self.account_name}: {safe_msg}")
                results.append(("linux.do", False, {"error": safe_msg}))

        if not results:
            print(f"❌ {self.account_name}: No valid authentication method found in configuration")
            return []

        # 输出最终结果
        print(f"\n📋 {self.account_name} authentication results:")
        successful_count = 0
        for auth_method, success, user_info in results:
            status = "✅" if success else "❌"
            print(f"  {status} {auth_method} authentication")
            if success:
                successful_count += 1

        print(f"\n🎯 {self.account_name}: {successful_count}/{len(results)} authentication methods successful")

        return results
