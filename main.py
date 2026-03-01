#!/usr/bin/env python3
"""
自动签到脚本
"""

import asyncio
import hashlib
import json
import os
import sys
from datetime import datetime
from dotenv import load_dotenv
from utils.config import AppConfig, AccountConfig
from utils.notify import notify
from checkin import CheckIn

load_dotenv(override=True)

# Restore storage states from env var if provided
# Format: base64-encoded JSON: {"filename.json": {storage_state_content}, ...}
_storage_env = os.getenv("LINUXDO_STORAGE_STATES", "").strip()
if _storage_env:
    import base64
    try:
        _decoded = json.loads(base64.b64decode(_storage_env).decode("utf-8"))
        os.makedirs("storage-states", exist_ok=True)
        for fname, content in _decoded.items():
            fpath = os.path.join("storage-states", os.path.basename(fname))
            if not os.path.exists(fpath):
                with open(fpath, "w", encoding="utf-8") as f:
                    json.dump(content, f, ensure_ascii=False)
                print(f"ℹ️ Restored storage state: {fpath}")
            else:
                print(f"ℹ️ Storage state already exists (skip): {fpath}")
    except Exception as e:
        print(f"⚠️ Failed to restore storage states from env: {e}")

BALANCE_HASH_FILE = "balance_hash.txt"


def load_accounts() -> list[AccountConfig] | None:
    """从环境变量加载多账号配置"""
    accounts_str = os.getenv("ACCOUNTS")
    if not accounts_str:
        print("❌ ACCOUNTS environment variable not found")
        return None

    try:
        accounts_data = json.loads(accounts_str)

        # 检查是否为数组格式
        if not isinstance(accounts_data, list):
            print("❌ Account configuration must use array format [{}]")
            return None

        accounts = []
        # 验证账号数据格式
        for i, account in enumerate(accounts_data):
            if not isinstance(account, dict):
                print(f"❌ Account {i + 1} configuration format is incorrect")
                return None

            # 检查必须有 linux.do、github 或 cookies 配置
            has_linux_do = "linux.do" in account
            has_github = "github" in account
            has_cookies = "cookies" in account

            if not has_linux_do and not has_github and not has_cookies:
                print(f"❌ Account {i + 1} must have either 'linux.do', 'github', or 'cookies' " f"configuration")
                return None

                # 确保必要字段存在后再创建 AccountConfig
            if has_cookies:
                if not account.get("cookies"):
                    print(f"❌ Account {i + 1} cookies cannot be empty")
                    return None
                if not account.get("api_user"):
                    print(f"❌ Account {i + 1} api_user cannot be empty")
                    return None

            # 验证 linux.do 配置
            if has_linux_do:
                auth_config = account["linux.do"]
                if not isinstance(auth_config, dict):
                    print(f"❌ Account {i + 1} linux.do configuration must be a " f"dictionary")
                    return None

                # 验证必需字段
                if "username" not in auth_config or "password" not in auth_config:
                    print(f"❌ Account {i + 1} linux.do configuration must contain username and password")
                    return None

                # 验证字段不为空
                if not auth_config["username"] or not auth_config["password"]:
                    print(f"❌ Account {i + 1} linux.do username and password cannot be empty")
                    return None

            # 验证 github 配置
            if has_github:
                auth_config = account["github"]
                if not isinstance(auth_config, dict):
                    print(f"❌ Account {i + 1} github configuration must be a dictionary")
                    return None

                # 验证必需字段
                if "username" not in auth_config or "password" not in auth_config:
                    print(f"❌ Account {i + 1} github configuration must contain username and password")
                    return None

                # 验证字段不为空
                if not auth_config["username"] or not auth_config["password"]:
                    print(f"❌ Account {i + 1} github username and password cannot be empty")
                    return None

            # 验证 cookies 配置
            if has_cookies:
                cookies_config = account["cookies"]
                if not cookies_config:
                    print(f"❌ Account {i + 1} cookies cannot be empty")
                    return None

                # 验证必须要有 api_user 字段
                if "api_user" not in account:
                    print(f"❌ Account {i + 1} with cookies must have api_user field")
                    return None

                if not account["api_user"]:
                    print(f"❌ Account {i + 1} api_user cannot be empty")
                    return None

            # 如果有 name 字段,确保它不是空字符串
            if "name" in account and not account["name"]:
                print(f"❌ Account {i + 1} name field cannot be empty")
                return None

            accounts.append(AccountConfig.from_dict(account, i))

        return accounts
    except Exception as e:
        print(f"❌ Account configuration format is incorrect: {e}")
        return None


def load_balance_hash() -> str | None:
    """加载余额hash"""
    try:
        if os.path.exists(BALANCE_HASH_FILE):
            with open(BALANCE_HASH_FILE, "r", encoding="utf-8") as f:
                return f.read().strip()
    except Exception:
        pass
    return None


def save_balance_hash(balance_hash: str) -> None:
    """保存余额hash"""
    try:
        with open(BALANCE_HASH_FILE, "w", encoding="utf-8") as f:
            f.write(balance_hash)
    except Exception as e:
        print(f"Warning: Failed to save balance hash: {e}")


def generate_balance_hash(balances: dict) -> str:
    """生成余额数据的hash"""
    # 将包含 quota 和 used 的结构转换为 {account_name: [quota]} 格式用于 hash 计算
    simple_balances = {}
    if balances:
        for account_key, account_balances in balances.items():
            quota_list = []
            for _, balance_info in account_balances.items():
                quota_list.append(balance_info["quota"])
            simple_balances[account_key] = quota_list

    balance_json = json.dumps(simple_balances, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(balance_json.encode("utf-8")).hexdigest()[:16]


async def main():
    """运行签到流程

    Returns:
            退出码: 0 表示至少有一个账号成功, 1 表示全部失败
    """

    print("🚀 newapi.ai multi-account auto check-in script started (using Camoufox)")
    print(f'🕒 Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

    app_config = AppConfig.load_from_env()
    print(f"⚙️ Loaded {len(app_config.providers)} provider(s)")

    # 加载全局代理配置
    global_proxy = None
    proxy_str = os.getenv("PROXY")
    if proxy_str:
        try:
            # 尝试解析为 JSON
            global_proxy = json.loads(proxy_str)
            print("⚙️ Global proxy loaded from PROXY environment variable (dict format)")
        except json.JSONDecodeError:
            # 如果不是 JSON，则视为字符串
            global_proxy = {"server": proxy_str}
            # 避免在日志中泄露代理账号密码等敏感信息
            print("⚙️ Global proxy loaded from PROXY environment variable (string format)")

    # 加载账号配置
    accounts = load_accounts()
    if not accounts:
        print("❌ Unable to load account configuration, program exits")
        return 1

    print(f"⚙️ Found {len(accounts)} account(s)")

    # 加载余额hash
    last_balance_hash = load_balance_hash()

    # 为每个账号执行签到
    success_count = 0
    total_count = 0
    notification_content = []
    current_balances = {}
    need_notify = False  # 是否需要发送通知

    for i, account_config in enumerate(accounts):
        account_key = f"account_{i + 1}"
        account_name = account_config.get_display_name(i)
        if len(notification_content) > 0:
            notification_content.append("\n-------------------------------")

        try:
            provider_config = app_config.get_provider(account_config.provider)
            if not provider_config:
                print(f"❌ {account_name}: Provider '{account_config.provider}' configuration not found")
                need_notify = True
                notification_content.append(
                    f"[FAIL] {account_name}: Provider '{account_config.provider}' configuration not found"
                )
                continue

            print(f"🌀 Processing {account_name} using provider '{account_config.provider}'")
            checkin = CheckIn(account_name, account_config, provider_config, global_proxy=global_proxy)
            results = await checkin.execute()

            total_count += len(results)

            # 处理多个认证方式的结果
            account_success = False
            successful_methods = []
            failed_methods = []

            this_account_balances = {}
            # 构建详细的结果报告
            account_result = f"📣 {account_name} Summary:\n"
            for auth_method, success, user_info in results:
                status = "✅ SUCCESS" if success else "❌ FAILED"
                account_result += f"  {status} with {auth_method} authentication\n"

                if success and user_info and user_info.get("success"):
                    account_success = True
                    success_count += 1
                    successful_methods.append(auth_method)
                    display = user_info.get("display", "")
                    if not display:
                        quota = user_info.get("quota")
                        used_quota = user_info.get("used_quota")
                        if quota is not None and used_quota is not None:
                            display = f"Current balance: {quota}, Used: {used_quota}"
                        else:
                            display = "余额获取成功（但未提供 display 字段）"
                    account_result += f"    💰 {display}\n"
                    # 记录余额信息
                    current_quota = user_info["quota"]
                    current_used = user_info["used_quota"]
                    this_account_balances[f"{auth_method}"] = {
                        "quota": current_quota,
                        "used": current_used,
                    }
                else:
                    failed_methods.append(auth_method)
                    error_msg = user_info.get("error", "Unknown error") if user_info else "Unknown error"
                    account_result += f"    🔺 {str(error_msg)[:100]}...\n"

            if account_success:
                current_balances[account_key] = this_account_balances

            # 如果所有认证方式都失败，需要通知
            if not account_success and results:
                need_notify = True
                print(f"🔔 {account_name} all authentication methods failed, will send notification")

            # 如果有失败的认证方式，也通知
            if failed_methods and successful_methods:
                need_notify = True
                print(f"🔔 {account_name} has some failed authentication methods, will send notification")

            # 添加统计信息
            success_count_methods = len(successful_methods)
            failed_count_methods = len(failed_methods)

            account_result += f"\n📊 Statistics: {success_count_methods}/{len(results)} methods successful"
            if failed_count_methods > 0:
                account_result += f" ({failed_count_methods} failed)"

            notification_content.append(account_result)

        except Exception as e:
            print(f"❌ {account_name} processing exception: {e}")
            need_notify = True  # 异常也需要通知
            notification_content.append(f"❌ {account_name} Exception: {str(e)[:100]}...")

    # 检查余额变化
    current_balance_hash = generate_balance_hash(current_balances) if current_balances else None
    print(f"\n\nℹ️ Current balance hash: {current_balance_hash}, Last balance hash: {last_balance_hash}")
    if current_balance_hash:
        if last_balance_hash is None:
            # 首次运行
            need_notify = True
            print("🔔 First run detected, will send notification with current balances")
        elif current_balance_hash != last_balance_hash:
            # 余额有变化
            need_notify = True
            print("🔔 Balance changes detected, will send notification")
        else:
            print("ℹ️ No balance changes detected")

    # 保存当前余额hash
    if current_balance_hash:
        save_balance_hash(current_balance_hash)

    if need_notify and notification_content:
        # 构建通知内容
        summary = [
            "-------------------------------",
            "📢 Check-in result statistics:",
            f"🔵 Success: {success_count}/{total_count}",
            f"🔴 Failed: {total_count - success_count}/{total_count}",
        ]

        if success_count == total_count:
            summary.append("✅ All accounts check-in successful!")
        elif success_count > 0:
            summary.append("⚠️ Some accounts check-in successful")
        else:
            summary.append("❌ All accounts check-in failed")

        time_info = f'🕓 Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'

        notify_content = "\n\n".join([time_info, "\n".join(notification_content), "\n".join(summary)])

        print(notify_content)
        notify.push_message("Check-in Alert", notify_content, msg_type="text")
        print("🔔 Notification sent due to failures or balance changes")
    else:
        print("ℹ️ All accounts successful and no balance changes detected, notification skipped")

    # 设置退出码
    sys.exit(0 if success_count > 0 else 1)


def run_main():
    """运行主函数的包装函数"""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⚠️ Program interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error occurred during program execution: {e}")
        sys.exit(1)


if __name__ == "__main__":
    run_main()
