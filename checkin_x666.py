#!/usr/bin/env python3
"""
x666.me 自动签到（从 qd.x666.me 抽奖拿 CDK，然后到 x666.me 充值）
"""

import json
import os
from datetime import datetime

import httpx


class X666CheckIn:
	"""x666 签到管理类"""

	def __init__(self, account_name: str, *, proxy_config: dict | None = None):
		self.account_name = account_name
		self.safe_account_name = ''.join(c if c.isalnum() else '_' for c in account_name)

		self.http_proxy_config = self._get_http_proxy(proxy_config)

	def _new_httpx_client(self, *, http2: bool = False, timeout: float = 30.0) -> httpx.Client:
		kwargs: dict = {'http2': http2, 'timeout': timeout}
		proxy = self.http_proxy_config
		if proxy is not None:
			kwargs['proxy'] = proxy
		return httpx.Client(**kwargs)

	@staticmethod
	def _get_http_proxy(proxy_config: dict | None = None) -> httpx.URL | None:
		if not proxy_config:
			return None
		proxy_url = proxy_config.get('server')
		if not proxy_url:
			return None
		username = proxy_config.get('username')
		password = proxy_config.get('password')
		if username and password:
			parsed = httpx.URL(proxy_url)
			return parsed.copy_with(username=username, password=password)
		return httpx.URL(proxy_url)

	def _check_and_handle_response(self, response: httpx.Response, context: str = 'response') -> dict | None:
		logs_dir = 'logs'
		os.makedirs(logs_dir, exist_ok=True)

		try:
			return response.json()
		except json.JSONDecodeError as e:
			print(f'❌ {self.account_name}: Failed to parse JSON response: {e}')

			timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
			safe_context = ''.join(c if c.isalnum() else '_' for c in context)
			content_type = response.headers.get('content-type', '').lower()

			if 'text/html' in content_type or 'text/plain' in content_type:
				filename = f'{self.safe_account_name}_{timestamp}_{safe_context}.html'
			else:
				filename = f'{self.safe_account_name}_{timestamp}_{safe_context}_invalid.txt'

			filepath = os.path.join(logs_dir, filename)
			try:
				with open(filepath, 'w', encoding='utf-8') as f:
					f.write(response.text)
				print(f'⚠️ {self.account_name}: Invalid/HTML response saved to: {filepath}')
			except Exception:
				pass
			return None
		except Exception as e:
			print(f'❌ {self.account_name}: Error occurred while checking response: {e}')
			return None

	def get_user_info(self, client: httpx.Client, headers: dict, auth_token: str) -> tuple[bool, bool, str, float, float]:
		print(f'ℹ️ {self.account_name}: Getting user info')

		info_headers = headers.copy()
		info_headers.update(
			{
				'authorization': f'Bearer {auth_token}',
				'content-length': '0',
				'content-type': 'application/json',
				'origin': 'https://qd.x666.me',
				'referer': 'https://qd.x666.me/',
				'sec-fetch-dest': 'empty',
				'sec-fetch-mode': 'cors',
				'sec-fetch-site': 'same-origin',
			}
		)

		resp = client.post('https://qd.x666.me/api/user/info', headers=info_headers, timeout=30)
		print(f'📨 {self.account_name}: User info response status code {resp.status_code}')

		if resp.status_code != 200:
			return False, False, '', 0.0, 0.0

		json_data = self._check_and_handle_response(resp, 'x666_get_user_info')
		if not isinstance(json_data, dict) or not json_data.get('success'):
			return False, False, '', 0.0, 0.0

		data = json_data.get('data', {}) or {}
		can_spin = bool(data.get('can_spin', False))
		today_record = data.get('today_record')
		cdk = today_record.get('cdk', '') if isinstance(today_record, dict) else ''
		quota_amount = today_record.get('quota_amount', 0) if isinstance(today_record, dict) else 0

		user = data.get('user', {}) or {}
		username = user.get('username', 'Unknown')
		total_quota = user.get('total_quota', 0)
		try:
			total_quota_f = float(total_quota) / 500
		except Exception:
			total_quota_f = 0.0
		print(f'✅ {self.account_name}: User: {username}, Total Quota: {total_quota_f}')
		print(f'ℹ️ {self.account_name}: Can spin: {can_spin}, CDK: {cdk}')

		try:
			quota_amount_f = float(quota_amount) / 500
		except Exception:
			quota_amount_f = 0.0
		return True, can_spin, str(cdk or ''), quota_amount_f, total_quota_f

	def execute_spin(self, client: httpx.Client, headers: dict, auth_token: str) -> tuple[bool, str, float]:
		print(f'🎰 {self.account_name}: Executing spin')

		spin_headers = headers.copy()
		spin_headers.update(
			{
				'authorization': f'Bearer {auth_token}',
				'content-length': '0',
				'content-type': 'application/json',
				'origin': 'https://qd.x666.me',
				'referer': 'https://qd.x666.me/',
				'sec-fetch-dest': 'empty',
				'sec-fetch-mode': 'cors',
				'sec-fetch-site': 'same-origin',
			}
		)

		resp = client.post('https://qd.x666.me/api/lottery/spin', headers=spin_headers, timeout=30)
		print(f'📨 {self.account_name}: Spin response status code {resp.status_code}')

		if resp.status_code not in (200, 400):
			return False, '', 0.0

		json_data = self._check_and_handle_response(resp, 'x666_execute_spin')
		if not isinstance(json_data, dict):
			print(f'❌ {self.account_name}: Spin failed - Invalid response format')
			return False, '', 0.0

		message = json_data.get('message', json_data.get('msg', '')) or ''
		if json_data.get('success'):
			data = json_data.get('data', {}) or {}
			label = data.get('label', 'Unknown')
			cdk = data.get('cdk', '')
			quota = data.get('quota', 0)
			print(f'✅ {self.account_name}: Spin successful! Prize: {label}, CDK: {cdk}')
			try:
				quota_f = float(quota) / 500
			except Exception:
				quota_f = 0.0
			return True, str(cdk or ''), quota_f

		if isinstance(message, str) and ('already' in message.lower() or '已经' in message or '已抽' in message):
			print(f'✅ {self.account_name}: Already spun today!')
			return True, '', 0.0

		print(f'❌ {self.account_name}: Spin failed - {message or "Unknown error"}')
		return False, '', 0.0

	def execute_topup(self, client: httpx.Client, headers: dict, cookies: dict, api_user: str | int, cdk: str) -> bool:
		print(f'💰 {self.account_name}: Executing topup with CDK: {cdk}')

		client.cookies.update(cookies or {})

		topup_headers = headers.copy()
		topup_headers.update(
			{
				'accept': 'application/json, text/plain, */*',
				'content-type': 'application/json',
				'cache-control': 'no-store',
				'new-api-user': str(api_user),
				'origin': 'https://x666.me',
				'referer': 'https://x666.me/console/topup',
				'sec-fetch-dest': 'empty',
				'sec-fetch-mode': 'cors',
				'sec-fetch-site': 'same-origin',
			}
		)

		resp = client.post('https://x666.me/api/user/topup', headers=topup_headers, json={'key': cdk}, timeout=30)
		print(f'📨 {self.account_name}: Topup response status code {resp.status_code}')

		if resp.status_code not in (200, 400):
			print(f'❌ {self.account_name}: Topup failed - HTTP {resp.status_code}')
			return False

		json_data = self._check_and_handle_response(resp, 'x666_execute_topup')
		if not isinstance(json_data, dict):
			print(f'❌ {self.account_name}: Topup failed - Invalid response format')
			return False

		message = json_data.get('message', json_data.get('msg', '')) or ''
		if json_data.get('success') or json_data.get('code') == 0:
			print(f'✅ {self.account_name}: Topup successful!')
			return True

		if isinstance(message, str) and ('already' in message.lower() or '已被使用' in message or '已使用' in message):
			print(f'✅ {self.account_name}: Already claimed topup today!')
			return True

		print(f'❌ {self.account_name}: Topup failed - {message or "Unknown error"}')
		return False

	async def execute(self, access_token: str, cookies: dict, api_user: str | int) -> tuple[bool, dict]:
		print(f'\n\n⏳ 开始处理 {self.account_name}')
		print(f'ℹ️ {self.account_name}: 执行 x666 签到 (using proxy: {"true" if self.http_proxy_config else "false"})')

		client = self._new_httpx_client(http2=False, timeout=30.0)
		try:
			headers = {
				'accept': '*/*',
				'accept-language': 'en,en-US;q=0.9,zh;q=0.8,en-CN;q=0.7,zh-CN;q=0.6,am;q=0.5',
				'cache-control': 'no-cache',
				'pragma': 'no-cache',
				'priority': 'u=1, i',
				'sec-ch-ua': '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
				'sec-ch-ua-mobile': '?0',
				'sec-ch-ua-platform': '"macOS"',
				'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
				'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
			}

			# 站点需要这个 cookie（原实现如此）
			client.cookies.set('i18next', 'en')

			results = {'spin': False, 'topup': False, 'quota_amount': 0.0, 'total_quota': 0.0}
			cdk = ''
			quota_amount = 0.0
			total_quota = 0.0

			info_success, can_spin, existing_cdk, existing_quota, total_quota = self.get_user_info(
				client, headers, access_token
			)
			if not info_success:
				return False, {'error': '获取用户信息失败（/api/user/info）'}

			results['total_quota'] = total_quota

			if can_spin:
				spin_success, cdk, quota_amount = self.execute_spin(client, headers, access_token)
				results['spin'] = bool(spin_success)
				results['quota_amount'] = quota_amount
				if spin_success:
					total_quota += quota_amount
					results['total_quota'] = total_quota
			else:
				print(f'✅ {self.account_name}: 今日已抽奖，使用已有 CDK')
				results['spin'] = True
				cdk = existing_cdk
				quota_amount = existing_quota
				results['quota_amount'] = quota_amount

			if cdk:
				topup_success = self.execute_topup(client, headers, cookies, api_user, cdk)
				results['topup'] = bool(topup_success)
			else:
				print(f'⚠️ {self.account_name}: 无可用 CDK，跳过 topup')
				results['topup'] = True

			overall_success = bool(results['spin']) and bool(results['topup'])
			return overall_success, results
		except Exception as e:
			return False, {'error': f'x666 签到异常: {e}'}
		finally:
			client.close()
