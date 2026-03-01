#!/usr/bin/env python3
"""
kfc 自动签到脚本（独立入口）
"""

import asyncio
import hashlib
import json
import os
import sys
from datetime import datetime

from dotenv import load_dotenv

from checkin import CheckIn
from utils.config import AccountConfig, AppConfig
from utils.linuxdo_cookies_override import apply_linuxdo_cookies_override
from utils.notify import notify

load_dotenv(override=True)

BALANCE_HASH_FILE = "balance_hash_kfc.txt"
CACHE_DIR = os.path.join("storage-states", "kfc")


def _load_accounts() -> tuple[list[AccountConfig] | None, str | None]:
    accounts_str = os.getenv("ACCOUNTS_KFC")
    if not accounts_str:
        msg = "❌ ACCOUNTS_KFC environment variable not found"
        print(msg)
        return None, msg

    try:
        data = json.loads(accounts_str)
    except json.JSONDecodeError as e:
        msg = f"❌ Failed to parse ACCOUNTS_KFC as JSON: {e}"
        print(msg)
        return None, msg

    if isinstance(data, dict):
        accounts_data = [data]
    elif isinstance(data, list):
        accounts_data = data
    else:
        msg = "❌ ACCOUNTS_KFC must be a JSON object or array"
        print(msg)
        return None, msg

    overridden = apply_linuxdo_cookies_override(accounts_data, accounts_env_key="ACCOUNTS_KFC")
    if overridden:
        print(f"⚙️ Applied linux.do cookies override for {overridden} account(s) from LINUXDO_COOKIES")

    accounts: list[AccountConfig] = []
    for i, account in enumerate(accounts_data):
        if not isinstance(account, dict):
            msg = f"❌ Account {i + 1} is not a valid object"
            print(msg)
            return None, msg

        linuxdo = account.get("linux.do")
        has_credentials = isinstance(linuxdo, dict) and bool(linuxdo.get("username") and linuxdo.get("password"))
        cookies_cfg = linuxdo.get("cookies") if isinstance(linuxdo, dict) else None
        has_cookie_auth = bool(cookies_cfg.strip()) if isinstance(cookies_cfg, str) else bool(cookies_cfg)

        if has_cookie_auth and not isinstance(cookies_cfg, (dict, str, list)):
            msg = f"❌ Account {i + 1} linux.do cookies must be a dictionary, string, or list"
            print(msg)
            return None, msg

        if not has_credentials and not has_cookie_auth:
            msg = f"❌ Account {i + 1} missing linux.do credentials (username/password or cookies)"
            print(msg)
            return None, msg

        # 默认强制 provider=kfc（也允许用户显式填写）
        account.setdefault("provider", "kfc")

        accounts.append(AccountConfig.from_dict(account, i))

    if not accounts:
        msg = "❌ No valid accounts found"
        print(msg)
        return None, msg
    return accounts, None


def _load_global_proxy() -> dict | None:
    proxy_str = os.getenv("PROXY")
    if not proxy_str:
        return None
    try:
        return json.loads(proxy_str)
    except json.JSONDecodeError:
        return {"server": proxy_str}


def _load_balance_hash() -> str | None:
    try:
        if os.path.exists(BALANCE_HASH_FILE):
            with open(BALANCE_HASH_FILE, "r", encoding="utf-8") as f:
                return f.read().strip()
    except Exception:
        pass
    return None


def _save_balance_hash(balance_hash: str) -> None:
    try:
        with open(BALANCE_HASH_FILE, "w", encoding="utf-8") as f:
            f.write(balance_hash)
    except Exception as e:
        print(f"⚠️ Failed to save balance hash: {e}")


def _generate_balance_hash(balances: dict) -> str:
    simple = {}
    if balances:
        for account_name, info in balances.items():
            if not isinstance(info, dict):
                continue
            simple[account_name] = [info.get("quota", 0)]
    payload = json.dumps(simple, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _notify_fatal(title: str, message: str) -> None:
    try:
        content = "\n\n".join(
            [
                f"🕓 执行时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                message,
            ]
        )
        notify.push_message(title, content, msg_type="text")
    except Exception:
        pass


async def main() -> int:
    print("🚀 kfc 自动签到脚本启动")
    print(f"🕒 执行时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    app_config = AppConfig.load_from_env()
    provider = app_config.get_provider("kfc")
    if not provider:
        msg = "❌ Provider 'kfc' 未加载：请通过 PROVIDERS 注入/覆盖该站点配置"
        print(msg)
        _notify_fatal("kfc 签到告警", msg)
        return 1

    accounts, accounts_err = _load_accounts()
    if not accounts:
        _notify_fatal("kfc 签到告警", accounts_err or "❌ ACCOUNTS_KFC 未配置或格式不正确")
        return 1

    global_proxy = _load_global_proxy()
    os.makedirs(CACHE_DIR, exist_ok=True)

    last_hash = _load_balance_hash()
    print(f"ℹ️ 上次余额 hash: {last_hash or '(首次运行)'}")

    success_count = 0
    total_count = len(accounts)
    any_failed = False
    balances: dict[str, dict] = {}
    notification_lines: list[str] = []

    for i, account_config in enumerate(accounts):
        account_name = account_config.get_display_name(i)
        if notification_lines:
            notification_lines.append("-------------------------------")

        try:
            checkin = CheckIn(
                account_name,
                account_config,
                provider,
                global_proxy=global_proxy,
                storage_state_dir=CACHE_DIR,
            )
            results = await checkin.execute()

            ok_any = False
            best_info: dict | None = None
            for _, ok, info in results:
                if ok and isinstance(info, dict) and info.get("success"):
                    ok_any = True
                    best_info = info
                    break

            if ok_any:
                success_count += 1
                quota = best_info.get("quota", 0) if best_info else 0
                used = best_info.get("used_quota", 0) if best_info else 0
                display = (best_info or {}).get("display", "")
                if display:
                    notification_lines.append(f"✅ {account_name}: {display}")
                else:
                    notification_lines.append(f"✅ {account_name}: 🏃‍♂️{quota} | Used 🏃‍♂️{used}")
                balances[account_name] = {"quota": quota, "used_quota": used}
            else:
                any_failed = True
                err = ""
                if results and isinstance(results[0][2], dict):
                    err = str(results[0][2].get("error", ""))[:160]
                notification_lines.append(f"❌ {account_name}: {err or '签到失败'}")
        except Exception as e:
            any_failed = True
            notification_lines.append(f"❌ {account_name}: Exception: {str(e)[:160]}")

    current_hash = _generate_balance_hash(balances)
    print(f"ℹ️ 当前余额 hash: {current_hash}, 上次: {last_hash}")
    if current_hash:
        _save_balance_hash(current_hash)

    need_notify = False
    if not last_hash:
        need_notify = True
    elif current_hash and current_hash != last_hash:
        need_notify = True
    elif any_failed:
        need_notify = True

    if need_notify and notification_lines:
        summary = [
            "-------------------------------",
            "📢 kfc 签到统计:",
            f"🔵 Success: {success_count}/{total_count}",
            f"🔴 Failed: {total_count - success_count}/{total_count}",
        ]
        content = "\n\n".join(
            [
                f"🕓 执行时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "\n".join(notification_lines),
                "\n".join(summary),
            ]
        )
        title = "kfc 签到成功" if success_count == total_count else "kfc 签到告警"
        print(content)
        notify.push_message(title, content, msg_type="text")

    return 0 if success_count > 0 else 1


def run_main() -> None:
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("\n⚠️ 用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ 程序异常: {e}")
        sys.exit(1)


if __name__ == "__main__":
    run_main()
