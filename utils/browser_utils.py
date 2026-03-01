#!/usr/bin/env python3
"""
浏览器自动化相关的公共工具函数
"""

import random
from urllib.parse import urlparse


def parse_cookies(cookies_data) -> dict:
    """解析 cookies 数据

    支持以下 cookies 格式：
    - 字典: {"session": "xxx", "_t": "yyy"}
    - 字符串: "session=xxx; _t=yyy"
    - 列表对象（浏览器导出）: [{"name": "session", "value": "xxx"}, ...]

    Args:
        cookies_data: cookies 数据

    Returns:
        解析后的 cookies 字典
    """
    if isinstance(cookies_data, dict):
        cookies_dict = {}
        for key, value in cookies_data.items():
            k = str(key).strip()
            if not k or value is None:
                continue
            cookies_dict[k] = str(value)
        return cookies_dict

    if isinstance(cookies_data, str):
        cookies_dict = {}
        for cookie in cookies_data.split(";"):
            if "=" in cookie:
                key, value = cookie.strip().split("=", 1)
                key = key.strip()
                if key:
                    cookies_dict[key] = value
        return cookies_dict

    if isinstance(cookies_data, list):
        cookies_dict = {}
        for cookie in cookies_data:
            # 常见浏览器导出格式: {"name": "...", "value": "...", ...}
            if isinstance(cookie, dict):
                name = str(cookie.get("name", "")).strip()
                if not name:
                    continue
                if cookie.get("value") is None:
                    continue
                cookies_dict[name] = str(cookie.get("value"))
                continue

            # 兼容列表字符串项: ["a=b", "c=d"]
            if isinstance(cookie, str) and "=" in cookie:
                key, value = cookie.strip().split("=", 1)
                key = key.strip()
                if key:
                    cookies_dict[key] = value
        return cookies_dict
    return {}


def filter_cookies(cookies: list[dict], origin: str) -> dict:
    """根据 origin 过滤 cookies，只保留匹配域名的 cookies

    Args:
        cookies: Camoufox cookies 列表，每个元素是包含 name, value, domain 等的字典
        origin: Provider 的 origin URL (例如: https://api.example.com)

    Returns:
        过滤后的 cookies 字典 {name: value}
    """
    # 提取 provider origin 的域名
    provider_domain = urlparse(origin).netloc
    print(f"🔍 Provider domain: {provider_domain}")

    # 过滤 cookies，只保留与 provider domain 匹配的
    user_cookies = {}
    filtered_count = 0
    total_count = 0

    for cookie in cookies:
        cookie_name = cookie.get("name")
        cookie_value = cookie.get("value")
        cookie_domain = cookie.get("domain", "")
        total_count += 1

        if cookie_name and cookie_value:
            # 检查 cookie domain 是否匹配 provider domain
            # cookie domain 可能以 . 开头 (如 .example.com)，需要处理
            normalized_cookie_domain = cookie_domain.lstrip(".")
            normalized_provider_domain = provider_domain.lstrip(".")

            # 匹配逻辑：cookie domain 应该是 provider domain 的后缀
            if (
                normalized_provider_domain == normalized_cookie_domain
                or normalized_provider_domain.endswith("." + normalized_cookie_domain)
                or normalized_cookie_domain.endswith("." + normalized_provider_domain)
            ):
                user_cookies[cookie_name] = cookie_value
                print(f"  🔵 Matched cookie: {cookie_name} (domain: {cookie_domain})")
            else:
                filtered_count += 1
                print(f"  🔴 Filtered cookie: {cookie_name} (domain: {cookie_domain})")

    print(
        f"🔍 Cookie filtering result: "
        f"{len(user_cookies)} matched, {filtered_count} filtered, "
        f"{total_count} total"
    )

    return user_cookies


def get_random_user_agent() -> str:
    """获取随机的现代浏览器 User Agent 字符串

    Returns:
        随机选择的 User Agent 字符串
    """
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) " "Gecko/20100101 Firefox/134.0",
    ]
    return random.choice(user_agents)
