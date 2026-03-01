#!/usr/bin/env python3
"""
x666.me 自动签到脚本（独立入口）
"""

import asyncio
import hashlib
import json
import os
import sys
from datetime import datetime

from dotenv import load_dotenv

from checkin_x666 import X666CheckIn
from utils.notify import notify

load_dotenv(override=True)

from utils.restore_linuxdot import restore_linuxdot
restore_linuxdot()

BALANCE_HASH_FILE = 'balance_hash_x666.txt'
CACHE_DIR = os.path.join('storage-states', 'x666')


def _load_accounts() -> list[dict] | None:
	accounts_str = os.getenv('ACCOUNTS_X666')
	if not accounts_str:
		print('❌ ACCOUNTS_X666 environment variable not found')
		return None

	try:
		data = json.loads(accounts_str)
	except json.JSONDecodeError as e:
		print(f'❌ Failed to parse ACCOUNTS_X666 as JSON: {e}')
		return None

	if isinstance(data, dict):
		accounts = [data]
	elif isinstance(data, list):
		accounts = data
	else:
		print('❌ ACCOUNTS_X666 must be a JSON object or array')
		return None

	valid: list[dict] = []
	for i, account in enumerate(accounts):
		if not isinstance(account, dict):
			print(f'❌ Account {i + 1} is not a valid object')
			continue

		linuxdo = account.get('linux.do') or {}
		has_linuxdo = isinstance(linuxdo, dict) and linuxdo.get('username') and linuxdo.get('password')

		# 兼容旧配置：access_token + cookies + api_user
		has_legacy = bool(account.get('access_token') and account.get('cookies') and account.get('api_user'))

		if not has_linuxdo and not has_legacy:
			print(
				f'❌ Account {i + 1} 配置不完整：需要提供 linux.do 账号密码，或旧版 access_token/cookies/api_user'
			)
			continue

		valid.append(account)

	if not valid:
		print('❌ No valid accounts found')
		return None

	print(f'✅ Loaded {len(valid)} account(s)')
	return valid


def _load_balance_hash() -> str | None:
	try:
		if os.path.exists(BALANCE_HASH_FILE):
			with open(BALANCE_HASH_FILE, 'r', encoding='utf-8') as f:
				return f.read().strip()
	except Exception:
		pass
	return None


def _save_balance_hash(balance_hash: str) -> None:
	try:
		with open(BALANCE_HASH_FILE, 'w', encoding='utf-8') as f:
			f.write(balance_hash)
	except Exception as e:
		print(f'Warning: Failed to save balance hash: {e}')


def _generate_balance_hash(checkin_results: dict) -> str:
	if not checkin_results:
		return ''
	all_quotas = {}
	for account_key, info in checkin_results.items():
		if info:
			# 新流程优先用站点余额 quota；旧流程沿用 total_quota
			if 'quota' in info:
				all_quotas[account_key] = str(info.get('quota', 0))
			else:
				all_quotas[account_key] = str(info.get('total_quota', 0))
	quotas_json = json.dumps(all_quotas, sort_keys=True, separators=(',', ':'))
	return hashlib.sha256(quotas_json.encode('utf-8')).hexdigest()[:16]


def _load_global_proxy() -> dict | None:
	proxy_str = os.getenv('PROXY')
	if not proxy_str:
		return None
	try:
		return json.loads(proxy_str)
	except json.JSONDecodeError:
		return {'server': proxy_str}


async def main() -> int:
	print('🚀 x666 自动签到脚本启动')
	print(f'🕒 执行时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
	os.makedirs(CACHE_DIR, exist_ok=True)

	accounts = _load_accounts()
	if not accounts:
		return 1

	last_hash = _load_balance_hash()
	print(f'ℹ️ 上次余额 hash: {last_hash or "(首次运行)"}')

	global_proxy = _load_global_proxy()
	if global_proxy:
		print('⚙️ 已加载全局代理配置')

	success_count = 0
	total_count = len(accounts)
	notification_lines: list[str] = []
	current_checkin_info: dict[str, dict] = {}
	any_failed = False

	for i, account in enumerate(accounts):
		account_name = account.get('name') or f'account_{i + 1}'
		access_token = account.get('access_token')
		cookies = account.get('cookies')
		api_user = account.get('api_user')
		account_proxy = account.get('proxy') or global_proxy

		if notification_lines:
			notification_lines.append('-------------------------------')

		try:
			print(f'🌀 处理账号: {account_name}')
			checkin = X666CheckIn(account_name, proxy_config=account_proxy)
			linuxdo = account.get('linux.do') or {}
			if isinstance(linuxdo, dict) and linuxdo.get('username') and linuxdo.get('password'):
				ok, result = await checkin.execute_with_linuxdo(str(linuxdo.get('username')), str(linuxdo.get('password')))
			else:
				ok, result = await checkin.execute(str(access_token), cookies or {}, api_user)
			current_checkin_info[account_name] = result if isinstance(result, dict) else {}

			# 新流程：checkin + quota；旧流程：spin/topup + total_quota
			if (result or {}).get('checkin') is not None:
				checkin_ok = '✓' if (result or {}).get('checkin') else '✗'
				quota = (result or {}).get('quota', 0)
				used = (result or {}).get('used_quota', 0)
				bonus = (result or {}).get('bonus_quota', 0)
				status_line = f'✅ {account_name}: 🧾 Check-in: {checkin_ok} | 💳 Balance: {quota} | Used: {used} | Bonus: {bonus}'
				fail_line = f'❌ {account_name}: 🧾 Check-in: {checkin_ok} | 💳 Balance: {quota} | 🔺 {str((result or {}).get("error",""))[:120]}'
			else:
				spin_ok = '✓' if (result or {}).get('spin') else '✗'
				topup_ok = '✓' if (result or {}).get('topup') else '✗'
				quota = (result or {}).get('quota_amount', 0)
				total_quota = (result or {}).get('total_quota', 0)
				status_line = (
					f'✅ {account_name}: 🎰 Spin: {spin_ok} | 💰 Topup: {topup_ok} | 📊 Quota: {quota} | Total: {total_quota}'
				)
				fail_line = (
					f'❌ {account_name}: 🎰 Spin: {spin_ok} | 💰 Topup: {topup_ok} | 📊 Quota: {quota} | Total: {total_quota} | 🔺 {str((result or {}).get("error",""))[:120]}'
				)

			if ok:
				success_count += 1
				notification_lines.append(status_line)
			else:
				any_failed = True
				notification_lines.append(fail_line)
		except Exception as e:
			any_failed = True
			notification_lines.append(f'❌ {account_name}: Exception: {str(e)[:160]}')

	current_hash = _generate_balance_hash(current_checkin_info)
	print(f'ℹ️ 当前余额 hash: {current_hash}, 上次: {last_hash}')

	need_notify = False
	if not last_hash:
		need_notify = True
		print('🔔 首次运行，发送通知')
	elif current_hash and current_hash != last_hash:
		need_notify = True
		print('🔔 余额变化，发送通知')
	elif any_failed:
		need_notify = True
		print('🔔 有失败项，发送通知')
	else:
		print('ℹ️ 无余额变化且全部成功，跳过通知')

	if current_hash:
		_save_balance_hash(current_hash)

	if need_notify and notification_lines:
		summary = [
			'-------------------------------',
			'📢 x666 签到统计:',
			f'🔵 Success: {success_count}/{total_count}',
			f'🔴 Failed: {total_count - success_count}/{total_count}',
		]
		if success_count == total_count:
			summary.append('✅ 全部账号签到成功')
		elif success_count > 0:
			summary.append('⚠️ 部分账号签到成功')
		else:
			summary.append('❌ 全部账号签到失败')

		content = '\n\n'.join(
			[
				f'🕓 执行时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}',
				'\n'.join(notification_lines),
				'\n'.join(summary),
			]
		)
		title = 'x666 签到成功' if success_count == total_count else 'x666 签到告警'
		print(content)
		notify.push_message(title, content, msg_type='text')

	return 0 if success_count > 0 else 1


def run_main():
	try:
		sys.exit(asyncio.run(main()))
	except KeyboardInterrupt:
		print('\n⚠️ 用户中断')
		sys.exit(1)
	except Exception as e:
		print(f'\n❌ 程序异常: {e}')
		sys.exit(1)


if __name__ == '__main__':
	run_main()
