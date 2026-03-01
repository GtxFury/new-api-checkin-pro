#!/usr/bin/env python3
"""
Fovt (api.voct.top + gift.voct.top) 自动签到脚本（独立入口）
"""

import asyncio
import hashlib
import json
import os
import sys
from datetime import datetime

from dotenv import load_dotenv

from checkin_fovt import FovtCheckIn
from utils.notify import notify

load_dotenv(override=True)

from utils.restore_linuxdot import restore_linuxdot
restore_linuxdot()

BALANCE_HASH_FILE = "balance_hash_fovt.txt"
CACHE_DIR = "storage-states"


def _load_accounts() -> list[dict] | None:
    """加载账号配置"""
    accounts_str = os.getenv("ACCOUNTS_FOVT")
    if not accounts_str:
        print("❌ ACCOUNTS_FOVT environment variable not found")
        return None

    try:
        data = json.loads(accounts_str)
    except json.JSONDecodeError as e:
        print(f"❌ Failed to parse ACCOUNTS_FOVT as JSON: {e}")
        return None

    if isinstance(data, dict):
        accounts = [data]
    elif isinstance(data, list):
        accounts = data
    else:
        print("❌ ACCOUNTS_FOVT must be a JSON object or array")
        return None

    valid: list[dict] = []
    for i, account in enumerate(accounts):
        if not isinstance(account, dict):
            print(f"❌ Account {i + 1} is not a valid object")
            continue
        if not account.get("linux.do"):
            print(f"❌ Account {i + 1} missing linux.do credentials")
            continue
        linuxdo = account.get("linux.do", {})
        if not linuxdo.get("username") or not linuxdo.get("password"):
            print(f"❌ Account {i + 1} linux.do credentials incomplete")
            continue
        valid.append(account)

    if not valid:
        print("❌ No valid accounts found")
        return None

    print(f"✅ Loaded {len(valid)} account(s)")
    return valid


def _load_balance_hash() -> str | None:
    """加载上次余额 hash"""
    try:
        if os.path.exists(BALANCE_HASH_FILE):
            with open(BALANCE_HASH_FILE, "r", encoding="utf-8") as f:
                return f.read().strip()
    except Exception:
        pass
    return None


def _save_balance_hash(balance_hash: str) -> None:
    """保存余额 hash"""
    try:
        with open(BALANCE_HASH_FILE, "w", encoding="utf-8") as f:
            f.write(balance_hash)
    except Exception as e:
        print(f"Warning: Failed to save balance hash: {e}")


def _generate_balance_hash(checkin_results: dict) -> str:
    """生成余额 hash"""
    if not checkin_results:
        return ""
    all_quotas = {}
    for account_key, info in checkin_results.items():
        if info:
            all_quotas[account_key] = str(info.get("balance", 0))
    quotas_json = json.dumps(all_quotas, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(quotas_json.encode("utf-8")).hexdigest()[:16]


def _load_global_proxy() -> dict | None:
    """加载全局代理配置"""
    proxy_str = os.getenv("PROXY")
    if not proxy_str:
        return None
    try:
        return json.loads(proxy_str)
    except json.JSONDecodeError:
        return {"server": proxy_str}


def _get_cache_file_path(account_name: str) -> str:
    """获取账号缓存文件路径"""
    safe_name = "".join(c if c.isalnum() else "_" for c in account_name)
    return os.path.join(CACHE_DIR, f"fovt_{safe_name}.json")


async def main() -> int:
    print("🚀 Fovt 自动签到脚本启动")
    print(f"🕒 执行时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    accounts = _load_accounts()
    if not accounts:
        return 1

    last_hash = _load_balance_hash()
    print(f"ℹ️ 上次余额 hash: {last_hash or '(首次运行)'}")

    global_proxy = _load_global_proxy()
    if global_proxy:
        print("⚙️ 已加载全局代理配置")

    # 确保缓存目录存在
    os.makedirs(CACHE_DIR, exist_ok=True)

    success_count = 0
    total_count = len(accounts)
    notification_lines: list[str] = []
    current_checkin_info: dict[str, dict] = {}
    any_failed = False

    for i, account in enumerate(accounts):
        account_name = account.get("name") or f"fovt_account_{i + 1}"
        linuxdo = account.get("linux.do", {})
        linuxdo_username = linuxdo.get("username", "")
        linuxdo_password = linuxdo.get("password", "")
        account_proxy = account.get("proxy") or global_proxy

        if notification_lines:
            notification_lines.append("-------------------------------")

        try:
            print(f"🌀 处理账号: {account_name}")
            cache_file = _get_cache_file_path(account_name)
            checkin = FovtCheckIn(account_name, proxy_config=account_proxy)
            ok, result = await checkin.execute(linuxdo_username, linuxdo_password, cache_file)
            current_checkin_info[account_name] = result if isinstance(result, dict) else {}

            login_ok = "✓" if (result or {}).get("linuxdo_login") else "✗"
            gift_ok = "✓" if (result or {}).get("gift_checkin") else "✗"
            redeem_ok = "✓" if (result or {}).get("code_redeem") else "✗"
            balance = (result or {}).get("balance", 0)
            # 避免在日志/通知中输出用户名（隐私）
            username = "已隐藏"

            if ok:
                success_count += 1
                notification_lines.append(
                    f"✅ {account_name}: 👤 {username} | 🔐 Login: {login_ok} | 🎁 Gift: {gift_ok} | "
                    f"💳 Redeem: {redeem_ok} | 💰 Balance: ${balance}"
                )
            else:
                any_failed = True
                err = (result or {}).get("error", "Unknown error")
                notification_lines.append(
                    f"❌ {account_name}: 👤 {username} | 🔐 Login: {login_ok} | 🎁 Gift: {gift_ok} | "
                    f"💳 Redeem: {redeem_ok} | 💰 Balance: ${balance} | 🔺 {str(err)[:120]}"
                )
        except Exception as e:
            any_failed = True
            notification_lines.append(f"❌ {account_name}: Exception: {str(e)[:160]}")

    current_hash = _generate_balance_hash(current_checkin_info)
    print(f"ℹ️ 当前余额 hash: {current_hash}, 上次: {last_hash}")

    need_notify = False
    if not last_hash:
        need_notify = True
        print("🔔 首次运行，发送通知")
    elif current_hash and current_hash != last_hash:
        need_notify = True
        print("🔔 余额变化，发送通知")
    elif any_failed:
        need_notify = True
        print("🔔 有失败项，发送通知")
    else:
        print("ℹ️ 无余额变化且全部成功，跳过通知")

    if current_hash:
        _save_balance_hash(current_hash)

    if need_notify and notification_lines:
        summary = [
            "-------------------------------",
            "📢 Fovt 签到统计:",
            f"🔵 Success: {success_count}/{total_count}",
            f"🔴 Failed: {total_count - success_count}/{total_count}",
        ]
        if success_count == total_count:
            summary.append("✅ 全部账号签到成功")
        elif success_count > 0:
            summary.append("⚠️ 部分账号签到成功")
        else:
            summary.append("❌ 全部账号签到失败")

        content = "\n\n".join(
            [
                f"🕓 执行时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                "\n".join(notification_lines),
                "\n".join(summary),
            ]
        )
        title = "Fovt 签到成功" if success_count == total_count else "Fovt 签到告警"
        print(content)
        notify.push_message(title, content, msg_type="text")

    return 0 if success_count > 0 else 1


def run_main():
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
