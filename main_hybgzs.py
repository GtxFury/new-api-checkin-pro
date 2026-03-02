#!/usr/bin/env python3
"""
黑与白公益站自动签到脚本（独立入口）
"""

import asyncio
import hashlib
import json
import os
import sys
from datetime import datetime

from dotenv import load_dotenv

from checkin_hybgzs import HybgzsCheckIn
from utils.notify import notify

load_dotenv(override=True)

from utils.restore_linuxdot import restore_linuxdot
restore_linuxdot()

BALANCE_HASH_FILE = 'balance_hash_hybgzs.txt'
CACHE_DIR = "storage-states"


def _load_accounts() -> list[dict] | None:
	accounts_str = os.getenv('ACCOUNTS_HYBGZS')
	if not accounts_str:
		print('❌ ACCOUNTS_HYBGZS environment variable not found')
		return None

	try:
		data = json.loads(accounts_str)
	except json.JSONDecodeError as e:
		print(f'❌ Failed to parse ACCOUNTS_HYBGZS as JSON: {e}')
		return None

	if isinstance(data, dict):
		accounts = [data]
	elif isinstance(data, list):
		accounts = data
	else:
		print('❌ ACCOUNTS_HYBGZS must be a JSON object or array')
		return None

	valid: list[dict] = []
	for i, account in enumerate(accounts):
		if not isinstance(account, dict):
			print(f'❌ Account {i + 1} is not a valid object')
			continue

		linuxdo = account.get('linux.do') or {}
		if not (isinstance(linuxdo, dict) and linuxdo.get('username') and linuxdo.get('password')):
			print(f'❌ Account {i + 1} 配置不完整：需要提供 linux.do 账号密码')
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
			all_quotas[account_key] = str(info.get('wallet_balance', 0))
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


def _load_transfer_threshold() -> float:
	"""从环境变量加载自动转出阈值，默认 0（不自动转出）"""
	raw = os.getenv('HYBGZS_TRANSFER_THRESHOLD', '0')
	try:
		return float(raw)
	except (ValueError, TypeError):
		return 0


async def main() -> int:
	print('🚀 黑与白公益站自动签到脚本启动')
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

	transfer_threshold = _load_transfer_threshold()
	if transfer_threshold > 0:
		print(f'⚙️ 自动转出阈值: ${transfer_threshold:.2f}')

	success_count = 0
	total_count = len(accounts)
	notification_lines: list[str] = []
	current_checkin_info: dict[str, dict] = {}
	any_failed = False

	for i, account in enumerate(accounts):
		account_name = account.get('name') or f'account_{i + 1}'
		account_proxy = account.get('proxy') or global_proxy
		linuxdo = account.get('linux.do') or {}

		if notification_lines:
			notification_lines.append('-------------------------------')

		try:
			print(f'🌀 处理账号: {account_name}')
			checkin = HybgzsCheckIn(
				account_name,
				proxy_config=account_proxy,
				transfer_threshold=account.get('transfer_threshold', transfer_threshold),
			)
			ok, result = await checkin.execute(
				str(linuxdo.get('username')),
				str(linuxdo.get('password')),
			)
			current_checkin_info[account_name] = result if isinstance(result, dict) else {}

			r = result or {}
			checkin_ok = '✓' if r.get('checkin') else '✗'
			wallet = r.get('wallet_balance', 0)
			main_site = r.get('main_site_balance', 0)
			wheel_reward = r.get('wheel_reward', 0)
			wheel_spins = r.get('wheel_spins', 0)
			transfer = r.get('transfer', '')

			if ok:
				success_count += 1
				line = (
					f'✅ {account_name}: 🧾签到: {checkin_ok} ({r.get("checkin_msg", "")})'
					f' | 🎡转盘: {wheel_spins}次 +${wheel_reward:.2f}'
					f' | 💰钱包: ${wallet:.2f} | 主站: ${main_site:.2f}'
				)
				if transfer:
					line += f' | 💸{transfer}'
			else:
				any_failed = True
				error = r.get('error', '')
				line = (
					f'❌ {account_name}: 🧾签到: {checkin_ok}'
					f' | 🎡转盘: {wheel_spins}次 +${wheel_reward:.2f}'
					f' | 💰钱包: ${wallet:.2f} | 主站: ${main_site:.2f}'
					f' | 🔺{str(error)[:120]}'
				)

			notification_lines.append(line)
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
			'📢 黑与白公益站签到统计:',
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
		title = '黑与白公益站签到成功' if success_count == total_count else '黑与白公益站签到告警'
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



