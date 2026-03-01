#!/usr/bin/env python3
"""
linux.do cookies 环境变量覆盖工具
"""

import json
import os
from typing import Any


def _is_cookie_payload(value: Any) -> bool:
    return isinstance(value, (dict, str, list))


def _is_browser_cookie_list(value: list[Any]) -> bool:
    if not value:
        return False
    return all(isinstance(item, dict) and ("name" in item and "value" in item) for item in value)


def _set_linuxdo_cookies(account: dict, payload: Any) -> bool:
    if not _is_cookie_payload(payload):
        return False

    if isinstance(payload, str) and not payload.strip():
        return False

    linuxdo = account.get("linux.do")
    if not isinstance(linuxdo, dict):
        linuxdo = {}
        account["linux.do"] = linuxdo

    linuxdo["cookies"] = payload
    return True


def apply_linuxdo_cookies_override(
    accounts_data: list[dict],
    *,
    accounts_env_key: str,
    env_key: str = "LINUXDO_COOKIES",
) -> int:
    """从环境变量注入 linux.do cookies（优先于账号内配置）。

    支持格式：
    1) 直接 cookie（作用到当前工作流全部账号）：
       - 字符串: "a=b; c=d"
       - 字典: {"_t":"...", "_forum_session":"..."}
       - 浏览器导出数组: [{"name":"_t","value":"..."}, ...]
    2) 按账号索引覆盖（当前工作流）：
       - 数组: [cookie_for_account1, cookie_for_account2, ...]
    3) 多工作流覆盖：
       - 对象: {"ACCOUNTS": <payload>, "ACCOUNTS_KFC": <payload>}
    """
    raw = os.getenv(env_key)
    if not raw:
        return 0

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = raw

    payload = parsed
    if isinstance(parsed, dict):
        # 优先按当前工作流账号环境变量名取子配置（如 ACCOUNTS_KFC）
        if accounts_env_key in parsed:
            payload = parsed[accounts_env_key]
        elif "__all__" in parsed:
            payload = parsed["__all__"]

    applied = 0

    # 直接 cookie（作用到当前工作流全部账号）
    if isinstance(payload, (dict, str)):
        for account in accounts_data:
            if _set_linuxdo_cookies(account, payload):
                applied += 1
        return applied

    if isinstance(payload, list):
        # 浏览器导出的 cookie 对象数组，作用到全部账号
        if _is_browser_cookie_list(payload):
            for account in accounts_data:
                if _set_linuxdo_cookies(account, payload):
                    applied += 1
            return applied

        # 按账号索引覆盖
        for idx, account in enumerate(accounts_data):
            if idx >= len(payload):
                continue
            if _set_linuxdo_cookies(account, payload[idx]):
                applied += 1
        return applied

    return 0

