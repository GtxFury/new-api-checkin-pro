#!/usr/bin/env python3
"""
gemai (哈基米API站) 自动签到脚本（独立入口）

该站点仅支持账号密码登录，不支持 linux.do/GitHub OAuth。
"""

import asyncio
import hashlib
import json
import os
import sys
from datetime import datetime

from dotenv import load_dotenv

from sign_in_with_credentials import CredentialsSignIn
from utils.config import AccountConfig, AppConfig
from utils.notify import notify

load_dotenv(override=True)

BALANCE_HASH_FILE = "balance_hash_gemai.txt"
CACHE_DIR = os.path.join("storage-states", "gemai")


def _load_accounts() -> tuple[list[AccountConfig] | None, str | None]:
    accounts_str = os.getenv("ACCOUNTS_GEMAI")
    if not accounts_str:
        msg = "❌ ACCOUNTS_GEMAI environment variable not found"
        print(msg)
        return None, msg

    try:
        data = json.loads(accounts_str)
    except json.JSONDecodeError as e:
        msg = f"❌ Failed to parse ACCOUNTS_GEMAI as JSON: {e}"
        print(msg)
        return None, msg

    if isinstance(data, dict):
        accounts_data = [data]
    elif isinstance(data, list):
        accounts_data = data
    else:
        msg = "❌ ACCOUNTS_GEMAI must be a JSON object or array"
        print(msg)
        return None, msg

    accounts: list[AccountConfig] = []
    for i, account in enumerate(accounts_data):
        if not isinstance(account, dict):
            msg = f"❌ Account {i + 1} is not a valid object"
            print(msg)
            return None, msg

        credentials = account.get("credentials")
        if not isinstance(credentials, dict) or not credentials.get("username") or not credentials.get("password"):
            msg = f"❌ Account {i + 1} missing credentials (username/password)"
            print(msg)
            return None, msg

        # 默认强制 provider=gemai
        account.setdefault("provider", "gemai")

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
            simple[account_name] = [info.get("checkin", False)]
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


async def _process_account(
    account_config: AccountConfig,
    provider_config,
    global_proxy: dict | None,
    index: int,
) -> tuple[str, bool, dict]:
    """处理单个账号的登录和签到"""
    account_name = account_config.get_display_name(index)

    credentials = account_config.credentials
    if not credentials:
        return account_name, False, {"error": "No credentials configured"}

    username = credentials.get("username", "")
    password = credentials.get("password", "")

    if not username or not password:
        return account_name, False, {"error": "Missing username or password"}

    # 使用账号级别代理或全局代理
    proxy_config = account_config.proxy if account_config.proxy else global_proxy

    try:
        sign_in = CredentialsSignIn(
            account_name=account_name,
            provider_config=provider_config,
            username=username,
            password=password,
        )

        success, result = await sign_in.sign_in_and_check_in(proxy_config=proxy_config)

        if success:
            checkin_ok = result.get("checkin", False)
            return account_name, True, {
                "success": True,
                "checkin": checkin_ok,
                "api_user": result.get("api_user"),
            }
        else:
            return account_name, False, {"error": result.get("error", "Unknown error")}

    except Exception as e:
        return account_name, False, {"error": str(e)}


async def main() -> int:
    print("🚀 gemai (哈基米API站) 自动签到脚本启动")
    print(f"🕒 执行时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    app_config = AppConfig.load_from_env()
    provider = app_config.get_provider("gemai")
    if not provider:
        msg = "❌ Provider 'gemai' 未加载"
        print(msg)
        _notify_fatal("gemai 签到告警", msg)
        return 1

    accounts, accounts_err = _load_accounts()
    if not accounts:
        _notify_fatal("gemai 签到告警", accounts_err or "❌ ACCOUNTS_GEMAI 未配置或格式不正确")
        return 1

    global_proxy = _load_global_proxy()
    os.makedirs(CACHE_DIR, exist_ok=True)

    last_hash = _load_balance_hash()
    print(f"ℹ️ 上次状态 hash: {last_hash or '(首次运行)'}")

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
            name, ok, info = await _process_account(
                account_config,
                provider,
                global_proxy,
                i,
            )

            if ok and isinstance(info, dict) and info.get("success"):
                success_count += 1
                checkin_ok = info.get("checkin", False)
                if checkin_ok:
                    notification_lines.append(f"✅ {account_name}: 签到成功")
                else:
                    notification_lines.append(f"⚠️ {account_name}: 登录成功，签到失败")
                balances[account_name] = {"checkin": checkin_ok}
            else:
                any_failed = True
                err = str(info.get("error", ""))[:160] if isinstance(info, dict) else ""
                notification_lines.append(f"❌ {account_name}: {err or '签到失败'}")
        except Exception as e:
            any_failed = True
            notification_lines.append(f"❌ {account_name}: Exception: {str(e)[:160]}")

    current_hash = _generate_balance_hash(balances)
    print(f"ℹ️ 当前状态 hash: {current_hash}, 上次: {last_hash}")
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
            "📢 gemai 签到统计:",
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
        title = "gemai 签到成功" if success_count == total_count else "gemai 签到告警"
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
