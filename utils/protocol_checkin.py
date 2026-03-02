"""
纯协议签到：使用存储的 newapi session cookie 直接签到。
不需要每次都走 Linux.do OAuth，session cookie 有效期 30 天。

流程：
1. 检查本地缓存的 session cookie 是否有效
2. 有效 → 直接 POST /api/user/checkin
3. 无效/缺失 → 返回 fallback 信号，由上层走浏览器 OAuth 获取新 session
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any

from curl_cffi import requests as curl_requests


class ProtocolCheckIn:
    """纯协议签到，使用 curl_cffi Chrome 指纹 + 缓存的 session cookie。"""

    CHROME_IMPERSONATE = "chrome131"

    def __init__(
        self,
        provider_config,
        account_name: str,
        session_cache_path: str = "",
        proxy: str | None = None,
    ):
        self.provider_config = provider_config
        self.account_name = account_name
        self.session_cache_path = session_cache_path
        self.proxy = proxy
        self.origin = (provider_config.origin or "").rstrip("/")

    def _log(self, msg: str):
        print(f"ℹ️ {self.account_name}: [protocol] {msg}")

    def _load_session_cache(self) -> dict | None:
        """从本地缓存加载 session cookie 和 api_user。"""
        if not self.session_cache_path or not os.path.exists(self.session_cache_path):
            return None
        try:
            with open(self.session_cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not data.get("session_cookie") or not data.get("api_user"):
                return None
            return data
        except Exception:
            return None

    def save_session_cache(self, session_cookie: str, api_user: str | int):
        """保存 session cookie 和 api_user 到本地缓存。"""
        if not self.session_cache_path:
            return
        try:
            os.makedirs(os.path.dirname(self.session_cache_path) or ".", exist_ok=True)
            data = {
                "session_cookie": session_cookie,
                "api_user": str(api_user),
                "saved_at": datetime.now().isoformat(),
                "origin": self.origin,
            }
            with open(self.session_cache_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            self._log(f"session cache saved to {self.session_cache_path}")
        except Exception as e:
            self._log(f"save session cache error: {e}")

    def _validate_session(self, s: curl_requests.Session, api_user: str) -> bool:
        """用 /api/user/self 验证 session 是否有效。"""
        try:
            r = s.get(
                f"{self.origin}/api/user/self",
                headers={
                    "Accept": "application/json, text/plain, */*",
                    "new-api-user": api_user,
                    "New-Api-User": api_user,
                },
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("success"):
                    return True
                self._log(f"validate: HTTP 200 but success={data.get('success')}, msg={data.get('message', '')[:50]}")
            else:
                self._log(f"validate: HTTP {r.status_code}, body={r.text[:100]}")
            return False
        except Exception:
            return False

    async def check_in(self) -> tuple[bool, dict[str, Any]]:
        """执行纯协议签到。"""
        origin = self.origin
        if not origin:
            return False, {"error": "missing provider origin"}

        # 加载缓存
        cache = self._load_session_cache()
        if not cache:
            self._log("无缓存的 session cookie，需要浏览器 OAuth 获取")
            return False, {"error": "no session cache", "fallback_browser": True}

        session_cookie = cache["session_cookie"]
        api_user = cache["api_user"]

        self._log(f"纯协议签到开始: {origin} (api_user={api_user})")

        s = curl_requests.Session(
            impersonate=self.CHROME_IMPERSONATE,
            proxy=self.proxy,
        )
        # 设置 session cookie
        s.cookies.set("session", session_cookie, domain=origin.split("//")[1])

        try:
            # ─── Step 1: 验证 session ───
            self._log("Step 1: 验证 session cookie...")
            if not self._validate_session(s, api_user):
                self._log("session cookie 已失效，需要浏览器 OAuth 刷新")
                # 删除失效缓存
                try:
                    os.remove(self.session_cache_path)
                except Exception:
                    pass
                return False, {"error": "session expired", "fallback_browser": True}

            self._log("session 有效!")

            # ─── Step 2: 查签到前余额 ───
            self._log("Step 2: GET /api/user/self (签到前余额)")
            r = s.get(
                f"{origin}/api/user/self",
                headers={
                    "Accept": "application/json, text/plain, */*",
                    "new-api-user": api_user,
                    "New-Api-User": api_user,
                },
            )
            quota = 0.0
            used_quota = 0.0
            if r.status_code == 200:
                try:
                    ud = r.json()
                    if ud.get("success"):
                        uinfo = ud.get("data", {})
                        quota = round(float(uinfo.get("quota", 0)) / 500000, 2)
                        used_quota = round(float(uinfo.get("used_quota", 0)) / 500000, 2)
                        self._log(f"余额: 🏃‍♂️{quota:.2f}, 历史消耗: 🏃‍♂️{used_quota:.2f}")
                except Exception:
                    pass

            # ─── Step 3: 检查今日是否已签到 ───
            month_str = datetime.now().strftime("%Y-%m")
            already_checked_in = False

            checkin_status_path = self.provider_config.post_checkin_status_path or "/api/user/checkin"
            self._log(f"Step 3: GET {checkin_status_path}?month={month_str}")
            r = s.get(
                f"{origin}{checkin_status_path}?month={month_str}",
                headers={
                    "Accept": "application/json, text/plain, */*",
                    "new-api-user": api_user,
                    "New-Api-User": api_user,
                },
            )
            if r.status_code == 200:
                try:
                    cdata = r.json()
                    if cdata.get("success"):
                        stats = cdata.get("data", {}).get("stats", {})
                        already_checked_in = bool(stats.get("checked_in_today"))
                        if already_checked_in:
                            self._log("今日已签到")
                except Exception:
                    pass

            # ─── Step 4: 签到 ───
            if already_checked_in:
                checkin_msg = "今日已签到"
            else:
                self._log("Step 4: POST /api/user/checkin")
                r = s.post(
                    f"{origin}/api/user/checkin",
                    headers={
                        "Accept": "application/json, text/plain, */*",
                        "new-api-user": api_user,
                        "New-Api-User": api_user,
                        "Content-Length": "0",
                    },
                )
                if r.status_code == 200:
                    try:
                        result = r.json()
                        if result.get("success"):
                            checkin_msg = "签到成功"
                            print(f"✅ {self.account_name}: [protocol] 签到成功!")
                        else:
                            checkin_msg = result.get("message", "签到失败")
                            print(f"⚠️ {self.account_name}: [protocol] {checkin_msg}")
                    except Exception:
                        checkin_msg = f"签到响应解析失败: {r.text[:100]}"
                else:
                    checkin_msg = f"签到 HTTP {r.status_code}"

            # ─── Step 5: 签到后余额 ───
            after_quota = quota
            if not already_checked_in:
                r = s.get(
                    f"{origin}/api/user/self",
                    headers={
                        "Accept": "application/json, text/plain, */*",
                        "new-api-user": api_user,
                        "New-Api-User": api_user,
                    },
                )
                if r.status_code == 200:
                    try:
                        ud = r.json()
                        if ud.get("success"):
                            uinfo = ud.get("data", {})
                            after_quota = round(float(uinfo.get("quota", 0)) / 500000, 2)
                    except Exception:
                        pass

            summary = (
                f"[protocol] 签到: {checkin_msg} | "
                f"余额: 🏃‍♂️{after_quota:.2f} | 历史消耗: 🏃‍♂️{used_quota:.2f} | "
                f"变动: 🏃‍♂️{quota:.2f} → 🏃‍♂️{after_quota:.2f}"
            )
            print(f"ℹ️ {self.account_name}: {summary}")

            success = checkin_msg in ("签到成功", "今日已签到") or after_quota > quota
            return success, {
                "success": success,
                "quota": after_quota,
                "used_quota": used_quota,
                "display": summary,
            }

        except Exception as e:
            import traceback
            traceback.print_exc()
            return False, {"error": f"protocol checkin error: {e}"}
        finally:
            s.close()
