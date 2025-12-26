#!/usr/bin/env python3
"""
CheckIn 类
"""

import json
import hashlib
import os
import re
import tempfile
from datetime import datetime
from urllib.parse import urlparse

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

    # Cloudflare 相关 cookie 名称（包含站点 session，便于一起复用）
    CF_COOKIE_NAMES: set[str] = {"cf_clearance", "_cfuvid", "__cf_bm", "session"}

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
                print(
                    f"ℹ️ {self.account_name}: Loaded {len(data)} Cloudflare cookies from cache: {cache_path}"
                )
                return data
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
        for match in re.findall(r"(?:兑换码|兑奖码|激活码|兑换券)[:：\\s]*([A-Za-z0-9-]{6,64})", text):
            if match and match not in codes:
                codes.append(match)

        # 兜底：抓取高置信度的长 token（避免把普通数字/日期误判为兑换码）
        for match in re.findall(r"\\b[A-Za-z0-9][A-Za-z0-9-]{11,63}\\b", text):
            if match and match not in codes:
                codes.append(match)

        return codes

    async def _maybe_solve_cloudflare_interstitial(self, page) -> None:
        if linuxdo_solve_captcha is None:
            return
        try:
            await linuxdo_solve_captcha(page, captcha_type="cloudflare", challenge_type="interstitial")
            await page.wait_for_timeout(3000)
        except Exception:
            pass

    async def _ensure_fuli_logged_in(self, page, linuxdo_username: str, linuxdo_password: str) -> None:
        # 先尝试直接打开主页，若已登录则无需走 OAuth
        try:
            await page.goto(self.FULI_ORIGIN, wait_until="networkidle")
            await page.wait_for_timeout(1000)
            has_nav = await page.evaluate(
                """() => {
                    const text = document.body ? (document.body.innerText || '') : '';
                    return text.includes('每日签到') || text.includes('幸运转盘') || text.includes('转盘');
                }"""
            )
            if has_nav and page.url.startswith(self.FULI_ORIGIN):
                return
        except Exception:
            pass

        await page.goto(self.FULI_LOGIN_URL, wait_until="networkidle")
        await self._maybe_solve_cloudflare_interstitial(page)

        # 点击 “使用 Linux Do 登录”
        try:
            login_btn = await page.query_selector('button:has-text("使用 Linux Do 登录")')
            if login_btn:
                await login_btn.click()
        except Exception:
            pass

        await page.wait_for_timeout(1200)
        await self._maybe_solve_cloudflare_interstitial(page)

        # 处理 Linux.do 登录（可能因为缓存已登录而跳过）
        try:
            if "linux.do/login" in page.url:
                await page.wait_for_selector("#login-account-name", timeout=30000)
                await page.fill("#login-account-name", linuxdo_username)
                await page.wait_for_timeout(500)
                await page.fill("#login-account-password", linuxdo_password)
                await page.wait_for_timeout(500)
                await page.click("#login-button")
                await page.wait_for_timeout(5000)

            # 授权页：点击“允许”
            if "connect.linux.do/oauth2/authorize" in page.url:
                try:
                    await page.wait_for_selector('a[href^="/oauth2/approve"]', timeout=30000)
                    allow_btn = await page.query_selector('a[href^="/oauth2/approve"]')
                    if allow_btn:
                        await allow_btn.click()
                except Exception:
                    pass

            # 回到 fuli 主站
            try:
                await page.wait_for_url(f"**{self.FULI_ORIGIN}/**", timeout=30000)
            except Exception:
                await page.goto(self.FULI_ORIGIN, wait_until="networkidle")
        except Exception as e:
            print(f"⚠️ {self.account_name}: fuli 登录流程可能未完全成功: {e}")

    async def _fuli_daily_checkin_get_code(self, page) -> tuple[bool, str | None, str]:
        """在 fuli 主站执行每日签到，返回 (是否完成, 兑换码, 提示信息)。"""
        await page.goto(self.FULI_ORIGIN, wait_until="networkidle")
        await self._maybe_solve_cloudflare_interstitial(page)

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

            await page.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
            await page.mouse.down()
            await page.wait_for_timeout(1600)
            await page.mouse.up()

            await page.wait_for_timeout(1500)
            text = await page.evaluate("() => document.body ? (document.body.innerText || '') : ''")
            codes = self._extract_exchange_codes(text)
            if codes:
                return True, codes[0], "签到成功"

            return False, None, "已执行签到动作，但未识别到兑换码"
        except Exception as e:
            await self._take_screenshot(page, "fuli_checkin_error")
            return False, None, f"签到异常: {e}"

    async def _fuli_wheel_get_codes(self, page, max_times: int = 3) -> tuple[list[str], str]:
        """在 fuli 转盘抽奖，返回 (兑换码列表, 提示信息)。"""
        await page.goto(self.FULI_WHEEL_URL, wait_until="networkidle")
        await self._maybe_solve_cloudflare_interstitial(page)

        remaining = None
        try:
            info_text = await page.evaluate(
                """() => {
                    const el = Array.from(document.querySelectorAll('p')).find(p => (p.innerText || '').includes('今日剩余'));
                    return el ? (el.innerText || '') : '';
                }"""
            )
            m = re.search(r"今日剩余\\s*(\\d+)\\s*/\\s*3\\s*次", info_text or "")
            if m:
                remaining = int(m.group(1))
        except Exception:
            remaining = None

        spins = remaining if remaining is not None else max_times
        spins = min(max_times, max(0, spins))
        if spins == 0:
            return [], "转盘次数已用完"

        all_codes: list[str] = []
        for i in range(spins):
            try:
                btn = None
                for selector in [
                    'button:has-text("开始")',
                    'button:has-text("抽")',
                    'button:has-text("转")',
                    "main button:not([disabled])",
                ]:
                    try:
                        ele = await page.query_selector(selector)
                        if ele:
                            btn = ele
                            break
                    except Exception:
                        continue

                if not btn:
                    await self._take_screenshot(page, "fuli_wheel_button_not_found")
                    break

                before_text = await page.evaluate("() => document.body ? (document.body.innerText || '') : ''")
                await btn.click()

                await page.wait_for_timeout(3500)
                after_text = await page.evaluate("() => document.body ? (document.body.innerText || '') : ''")

                before_codes = set(self._extract_exchange_codes(before_text))
                after_codes = self._extract_exchange_codes(after_text)
                new_codes = [c for c in after_codes if c not in before_codes and c not in all_codes]
                all_codes.extend(new_codes)

                # 尝试关闭弹窗
                try:
                    close_btn = await page.query_selector('button:has-text("确定")')
                    if close_btn:
                        await close_btn.click()
                except Exception:
                    pass
            except Exception:
                await self._take_screenshot(page, f"fuli_wheel_error_{i+1}")
                break

        return all_codes, f"转盘已尝试 {spins} 次"

    async def _runanytime_get_balance_from_app_me(self, page) -> dict | None:
        try:
            target_url = f"{self.provider_config.origin}/app/me"
            await page.goto(target_url, wait_until="networkidle")
            await page.wait_for_timeout(1000)

            summary = await page.evaluate(
                """() => {
                    try {
                        const rows = Array.from(document.querySelectorAll('table tr'));
                        const result = {};
                        for (const row of rows) {
                            const header = row.querySelector('th, [role=\"rowheader\"]');
                            const cell = row.querySelector('td, [role=\"cell\"]');
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
                return None

            balance_str = summary.get("当前余额")
            used_str = summary.get("历史消耗")
            if balance_str is None or used_str is None:
                return None

            def _parse_amount(s: str) -> float:
                s = s.replace("￥", "").replace("$", "").replace(",", "").strip()
                try:
                    return float(s)
                except Exception:
                    return 0.0

            quota = _parse_amount(balance_str)
            used_quota = _parse_amount(used_str)
            return {
                "success": True,
                "quota": quota,
                "used_quota": used_quota,
                "display": f"Current balance: ${quota}, Used: ${used_quota}",
            }
        except Exception:
            return None

    async def _runanytime_redeem_code_via_browser(self, page, code: str) -> tuple[bool, str]:
        await page.goto(f"{self.provider_config.origin}/console/topup", wait_until="networkidle")
        await self._maybe_solve_cloudflare_interstitial(page)

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
        """runanytime 新签到：在 fuli 获取兑换码并到 /console/topup 兑换。"""
        print(f"ℹ️ {self.account_name}: runanytime requires fuli exchange codes, starting browser flow")

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

            # 注入 runanytime cookies + 已缓存的 Cloudflare cookies，尽量避免再次触发挑战
            try:
                await context.add_cookies(
                    self._cookie_dict_to_browser_cookies(runanytime_cookies, self.provider_config.origin)
                )
            except Exception as e:
                print(f"⚠️ {self.account_name}: Failed to add runanytime cookies to browser context: {e}")

            try:
                cached_cf = self._load_cf_cookies_from_cache()
                if cached_cf:
                    await context.add_cookies(cached_cf)
            except Exception:
                pass

            page = await context.new_page()
            try:
                before_info = await self._runanytime_get_balance_from_app_me(page)

                await self._ensure_fuli_logged_in(page, linuxdo_username, linuxdo_password)
                checkin_ok, checkin_code, checkin_msg = await self._fuli_daily_checkin_get_code(page)
                wheel_codes, wheel_msg = await self._fuli_wheel_get_codes(page, max_times=3)

                codes: list[str] = []
                if checkin_code:
                    codes.append(checkin_code)
                codes.extend(wheel_codes)

                redeem_results = []
                success_redeem = 0
                for code in codes:
                    ok, msg = await self._runanytime_redeem_code_via_browser(page, code)
                    redeem_results.append({"code": code, "success": ok, "message": msg})
                    if ok:
                        success_redeem += 1

                after_info = await self._runanytime_get_balance_from_app_me(page)

                before_quota = before_info.get("quota") if before_info else None
                after_quota = after_info.get("quota") if after_info else None

                summary = (
                    f"RunAnytime 兑换 {success_redeem}/{len(codes)} 个 | "
                    f"fuli: {checkin_msg}, {wheel_msg} | "
                    f"余额: ${before_quota} -> ${after_quota}"
                )

                base_info = None
                if after_info and after_info.get("success"):
                    base_info = after_info
                elif before_info and before_info.get("success"):
                    base_info = before_info
                else:
                    base_info = {"success": False, "quota": 0, "used_quota": 0, "display": ""}

                user_info = dict(base_info)

                all_redeemed = len(codes) > 0 and success_redeem == len(codes)
                nothing_to_redeem = len(codes) == 0 and checkin_msg == "今日已签到" and "次数已用完" in wheel_msg
                overall_success = all_redeemed or nothing_to_redeem

                user_info.update(
                    {
                        "success": overall_success,
                        "display": summary,
                        "fuli_codes": codes,
                        "redeem_results": redeem_results,
                    }
                )

                if not overall_success:
                    return False, user_info
                return True, user_info
            except Exception as e:
                await self._take_screenshot(page, "runanytime_fuli_flow_error")
                return False, {"error": f"runanytime fuli/topup flow error: {e}"}
            finally:
                await page.close()
                await context.close()

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

                    # 3. 使用浏览器内的 fetch 调用 auth_state 接口，复用已通过的 Cloudflare 状态
                    auth_state_url = self.provider_config.get_auth_state_url()
                    print(
                        f"ℹ️ {self.account_name}: Fetching auth state via browser fetch: {auth_state_url}"
                    )
                    # 某些站点会校验 api_user header（例如要求为 -1 才允许获取 state），这里做兼容注入
                    api_user_headers = {k: "-1" for k in self._get_api_user_header_keys()}
                    # 提供基本的 Accept，避免被当成普通页面请求返回 HTML
                    api_user_headers.setdefault("Accept", "application/json, text/plain, */*")
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
                        return {
                            "success": False,
                            "error": f"Failed to get state via browser fetch, invalid response: {response}",
                        }

                    status = response.get("status", 0)
                    text = response.get("text", "")

                    if not response.get("ok") or status != 200:
                        # 依然被 Cloudflare 或后端拒绝，保存部分文本便于排查
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

    async def get_user_info_with_browser(self, auth_cookies: list[dict]) -> dict:
        """使用 Camoufox 获取用户信息

        对于启用了 Turnstile 的站点（如 runanytime / elysiver），优先从 /app/me 页面
        的静态表格中解析当前余额和历史消耗，避免再次触发 Cloudflare / WAF 对 API 的拦截。

        Returns:
            包含 success、quota、used_quota 或 error 的字典
        """
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
                    # 对于启用了 Turnstile 的站点（如 runanytime / elysiver），
                    # 直接从 /app/me 页面上解析“当前余额 / 历史消耗”等静态文本。
                    if getattr(self.provider_config, "turnstile_check", False):
                        target_url = f"{self.provider_config.origin}/app/me"
                        print(f"ℹ️ {self.account_name}: Opening profile page for browser-based user info: {target_url}")
                        await page.goto(target_url, wait_until="networkidle")

                        try:
                            await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                        except Exception:
                            await page.wait_for_timeout(3000)

                        # 从页面表格中提取“当前余额”和“历史消耗”两行
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

                        if summary:
                            balance_str = summary.get("当前余额")
                            used_str = summary.get("历史消耗")

                            if balance_str is not None and used_str is not None:
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
                        # 如果未能成功解析，则继续尝试通过 API 获取
                        print(
                            f"⚠️ {self.account_name}: Failed to parse balance from /app/me, "
                            "will try API-based user info in browser"
                        )

                    # 默认分支：在浏览器中直接调用用户信息 API
                    print(f"ℹ️ {self.account_name}: Fetching user info via browser fetch API")
                    response = await page.evaluate(
                        f"""async () => {{
                           try {{
                               const response = await fetch('{self.provider_config.get_user_info_url()}', {{
                                   credentials: 'include',
                               }});
                               const data = await response.json();
                               return data;
                           }} catch (e) {{
                               return {{ error: String(e) }};
                           }}
                        }}"""
                    )

                    if response and "data" in response:
                        user_data = response.get("data", {})
                        quota = round(user_data.get("quota", 0) / 500000, 2)
                        used_quota = round(user_data.get("used_quota", 0) / 500000, 2)
                        print(f"✅ {self.account_name}: " f"Current balance: ${quota}, Used: ${used_quota}")
                        return {
                            "success": True,
                            "quota": quota,
                            "used_quota": used_quota,
                            "display": f"Current balance: ${quota}, Used: ${used_quota}",
                        }

                    return {
                        "success": False,
                        "error": f"Failed to get user info, \n{json.dumps(response, indent=2)}",
                    }

                except Exception as e:
                    print(f"❌ {self.account_name}: Failed to get user info, {e}")
                    await self._take_screenshot(page, "user_info_error")
                    return {"success": False, "error": "Failed to get user info"}
                finally:
                    await page.close()

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

    def execute_check_in(self, client: httpx.Client, headers: dict):
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

        response = client.post(self.provider_config.get_sign_in_url(), headers=checkin_headers, timeout=30)

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
                "User-Agent": get_random_user_agent(),
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
                    success = self.execute_check_in(client, headers)
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

                        browser_user_info = await self.get_user_info_with_browser(camoufox_cookies)
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
                success = self.execute_check_in(client, headers)
                return success, user_info if user_info else {"error": "No user info available"}

            # 2) 特殊站点（如 runanytime）：需要根据签到状态接口判断是否真的签到成功
            if getattr(self.provider_config, "turnstile_check", False):
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

                # 无法获取签到状态时，保守起见按失败处理，避免误报成功
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
                "User-Agent": get_random_user_agent(),
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
                "User-Agent": get_random_user_agent(),
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

                                # 提取 cookies
                                user_cookies = {}
                                for cookie in response.cookies.jar:
                                    user_cookies[cookie.name] = cookie.value

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
