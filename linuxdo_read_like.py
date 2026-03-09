#!/usr/bin/env python3
"""
linux.do 自动阅读 + 点赞（GitHub Actions 友好）

实现思路参考 linux.do.js：
- 使用 /latest.json 或 /unread.json 拉取主题列表
- 打开真实主题页并滚动停留，让前端自然累计阅读行为
- 依据 /session/current.json 获取信任等级，并按等级设置每日点赞上限
- 使用 /user_actions.json?filter=1 同步近 24 小时点赞，避免超限
- 监听 429 rate_limit，触发后立即停止点赞
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import time
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from camoufox.async_api import AsyncCamoufox
from dotenv import load_dotenv

from utils.config import AccountConfig
from utils.notify import notify

try:  # pragma: no cover - 可选依赖
	from sign_in_with_linuxdo import solve_captcha as linuxdo_solve_captcha  # type: ignore
except Exception:  # pragma: no cover - 可选依赖缺失时静默跳过
	linuxdo_solve_captcha = None

# hcaptcha-challenger: 用于自动解 hCaptcha 验证码（登录时可能触发）
try:  # pragma: no cover
	from sign_in_with_linuxdo import _handle_hcaptcha  # type: ignore
except Exception:  # pragma: no cover
	_handle_hcaptcha = None


UTC = timezone.utc
PROJECT_ROOT = Path(__file__).resolve().parent
DOTENV_PATH = PROJECT_ROOT / ".env"

# 显式读取脚本同目录下的 .env，避免从其他工作目录启动时丢失配置。
load_dotenv(DOTENV_PATH, override=True)


def _now_ts() -> int:
	return int(time.time())


def _safe_name(name: str) -> str:
	return "".join(c if c.isalnum() else "_" for c in (name or "account"))


def _env_int(key: str, default: int) -> int:
	v = os.getenv(key)
	if not v:
		return default
	try:
		return int(v)
	except Exception:
		return default


def _env_str(key: str, default: str) -> str:
	v = os.getenv(key)
	return v.strip() if isinstance(v, str) and v.strip() else default


def _load_proxy() -> dict | None:
	proxy_str = os.getenv("PROXY")
	if not proxy_str:
		return None
	try:
		return json.loads(proxy_str)
	except Exception:
		return {"server": proxy_str}


def _env_bool(key: str, default: bool = False) -> bool:
	raw = os.getenv(key)
	if raw is None:
		return default
	s = str(raw).strip().lower()
	if s in {"1", "true", "yes", "y", "on"}:
		return True
	if s in {"0", "false", "no", "n", "off"}:
		return False
	return default


def _clamp(n: int, lo: int, hi: int) -> int:
	return max(lo, min(hi, n))


@dataclass(frozen=True)
class LinuxDoSettings:
	origin: str = "https://linux.do"
	feed: str = "latest"  # latest | unread
	topics_per_run: int = 10
	max_pages_per_run: int = 20
	min_read_seconds: int = 25
	max_read_seconds: int = 90
	max_likes_per_topic: int = 2
	skip_pinned: bool = True
	try_turnstile_solver: bool = True
	headless: bool = False
	storage_state_dir: str = "storage-states"

	@classmethod
	def from_env(cls) -> "LinuxDoSettings":
		origin = _env_str("LINUXDO_ORIGIN", "https://linux.do").rstrip("/")
		feed = _env_str("LINUXDO_FEED", "latest").lower()
		if feed not in {"latest", "unread"}:
			feed = "latest"
		return cls(
			origin=origin,
			feed=feed,
			topics_per_run=_clamp(_env_int("LINUXDO_TOPICS_PER_RUN", 10), 0, 200),
			max_pages_per_run=_clamp(_env_int("LINUXDO_MAX_PAGES_PER_RUN", 20), 1, 200),
			min_read_seconds=_clamp(_env_int("LINUXDO_MIN_READ_SECONDS", 25), 3, 3600),
			max_read_seconds=_clamp(_env_int("LINUXDO_MAX_READ_SECONDS", 90), 3, 7200),
			max_likes_per_topic=_clamp(_env_int("LINUXDO_MAX_LIKES_PER_TOPIC", 2), 0, 20),
			skip_pinned=_env_int("LINUXDO_SKIP_PINNED", 1) != 0,
			try_turnstile_solver=_env_int("LINUXDO_TRY_TURNSTILE_SOLVER", 1) == 1,
			headless=_env_int("HEADLESS", 0) == 1,
			storage_state_dir=_env_str("STORAGE_STATE_DIR", "storage-states"),
		)


@dataclass
class RunStats:
	account_name: str
	username: str
	trust_level: int | None = None
	like_limit: int = 0
	liked_posts_24h_at_start: int = 0
	remaining_likes_at_start: int = 0
	selected_topics: int = 0
	read_topics: int = 0
	likes_clicked: int = 0
	skipped_already_read: int = 0
	skipped_pinned: int = 0
	skipped_too_long: int = 0
	open_failures: int = 0


class LinuxDoAutoReadLike:
	LIKE_LIMITS: dict[int, int] = {0: 50, 1: 50, 2: 75, 3: 100, 4: 150}

	def __init__(self, account_name: str, username: str, password: str, settings: LinuxDoSettings):
		self.account_name = account_name
		self.safe_account_name = _safe_name(account_name)
		self.username = username
		self.password = password
		self.settings = settings
		self._warned_no_cf_solver = False

		Path(self.settings.storage_state_dir).mkdir(parents=True, exist_ok=True)
		# 复用 checkin.py 的 linux.do 登录缓存命名，避免同一账号重复触发 Cloudflare/Turnstile
		# checkin.py: storage-states/linuxdo_{username_hash}_storage_state.json
		username_hash = hashlib.sha256(self.username.encode("utf-8")).hexdigest()[:8]
		primary_storage_state = os.path.join(
			self.settings.storage_state_dir, f"linuxdo_{username_hash}_storage_state.json"
		)
		legacy_storage_state = os.path.join(
			self.settings.storage_state_dir, f"linuxdo_forum_{self.safe_account_name}.json"
		)
		self.storage_state_path = primary_storage_state if os.path.exists(primary_storage_state) else legacy_storage_state
		self.auto_state_path = os.path.join(
			self.settings.storage_state_dir, f"linuxdo_forum_{self.safe_account_name}_autostate.json"
		)

		self.auto_state: dict[str, Any] = self._load_auto_state()
		self._like_rate_limited_until: float = 0.0
		self._like_rate_limited_reason: str = ""

	def _should_use_session_current_api(self) -> bool:
		# linux.do 近期开了/关了 /session/current.json 不稳定：默认不用，必要时可手动开启
		return _env_bool("LINUXDO_USE_SESSION_CURRENT_API", default=False)

	def _load_auto_state(self) -> dict[str, Any]:
		if not os.path.exists(self.auto_state_path):
			return {"read_topics": {}, "liked_posts": {}, "feed_page": 0, "updated_at": _now_ts()}
		try:
			with open(self.auto_state_path, "r", encoding="utf-8") as f:
				data = json.load(f)
			if not isinstance(data, dict):
				return {"read_topics": {}, "liked_posts": {}, "feed_page": 0, "updated_at": _now_ts()}
			data.setdefault("read_topics", {})
			data.setdefault("liked_posts", {})
			data.setdefault("feed_page", 0)
			data["updated_at"] = _now_ts()
			return data
		except Exception:
			return {"read_topics": {}, "liked_posts": {}, "feed_page": 0, "updated_at": _now_ts()}

	def _save_auto_state(self) -> None:
		try:
			self.auto_state["updated_at"] = _now_ts()
			with open(self.auto_state_path, "w", encoding="utf-8") as f:
				json.dump(self.auto_state, f, ensure_ascii=False)
		except Exception as e:
			print(f"⚠️ {self.account_name}: 保存 autostate 失败: {e}")

	def _prune_auto_state(self) -> None:
		# 只保留近 30 天记录，避免缓存无限增大
		cutoff = _now_ts() - 30 * 24 * 60 * 60
		for key in ("read_topics", "liked_posts"):
			m = self.auto_state.get(key)
			if not isinstance(m, dict):
				self.auto_state[key] = {}
				continue
			removed = [k for k, v in m.items() if isinstance(v, int) and v < cutoff]
			for k in removed:
				m.pop(k, None)

	async def _is_cloudflare_interstitial(self, page) -> bool:
		try:
			url = (page.url or "").lower()
		except Exception:
			url = ""
		if any(k in url for k in ("__cf_chl", "challenges.cloudflare.com", "cf_chl")):
			return True
		try:
			title = (await page.title() or "").lower()
		except Exception:
			title = ""
		if any(k in title for k in ("just a moment", "attention required", "please wait", "请稍候", "请稍等")):
			return True
		# 某些情况下标题不包含关键字，但页面已经注入 Turnstile/Challenge DOM
		try:
			seen = await page.evaluate(
				"""() => {
					try {
						const hasIframe = !!document.querySelector('iframe[src*="challenges.cloudflare.com"]');
						const hasTurnstileInput = !!document.querySelector('input[name="cf-turnstile-response"], textarea[name="cf-turnstile-response"]');
						const hasChlForm = !!document.querySelector('form[action*="__cf_chl"], input[name^="cf_chl_"], input[name="cf_challenge_response"]');
						const hasWidget = !!document.querySelector('[id^="cf-chl-widget-"], .cf-chl-widget, #cf-chl-widget');
						const bodyText = (document.body && document.body.innerText) ? document.body.innerText : '';
						const hasText =
							bodyText.includes('Checking your browser') ||
							bodyText.includes('DDoS protection by') ||
							bodyText.includes('Ray ID') ||
							bodyText.includes('正在检查您的浏览器') ||
							bodyText.includes('请稍候') ||
							bodyText.includes('安全检查');
						return hasIframe || hasTurnstileInput || hasChlForm || hasWidget || hasText;
					} catch (e) {
						return false;
					}
				}"""
			)
			return bool(seen)
		except Exception:
			return False

	async def _maybe_pass_cloudflare_interstitial(self, page, *, max_wait_seconds: int = 35) -> None:
		if not await self._is_cloudflare_interstitial(page):
			return
		await self._maybe_solve_cloudflare(page)
		try:
			await page.wait_for_function(
				"""() => {
					const t = (document.title || '').toLowerCase();
					const u = (location.href || '').toLowerCase();
					const stillTitle =
						t.includes('just a moment') || t.includes('attention required') || t.includes('please wait') ||
						t.includes('请稍候') || t.includes('请稍等');
					const stillUrl = u.includes('__cf_chl') || u.includes('challenges.cloudflare.com') || u.includes('cf_chl');
					const hasIframe = !!document.querySelector('iframe[src*="challenges.cloudflare.com"]');
					const hasTurnstileInput = !!document.querySelector('input[name="cf-turnstile-response"], textarea[name="cf-turnstile-response"]');
					const hasChlForm = !!document.querySelector('form[action*="__cf_chl"], input[name^="cf_chl_"], input[name="cf_challenge_response"]');
					const hasWidget = !!document.querySelector('[id^="cf-chl-widget-"], .cf-chl-widget, #cf-chl-widget');
					return !(stillTitle || stillUrl || hasIframe || hasTurnstileInput || hasChlForm || hasWidget);
				}""",
				timeout=max_wait_seconds * 1000,
			)
		except Exception:
			# 保持兼容：不强制抛错，让后续逻辑继续判断
			pass

	async def _dump_debug(self, page, reason: str) -> None:
		try:
			os.makedirs("screenshots", exist_ok=True)
			os.makedirs("logs", exist_ok=True)
			ts = datetime.now().strftime("%Y%m%d_%H%M%S")
			safe_reason = _safe_name(reason)
			png = os.path.join("screenshots", f"{self.safe_account_name}_{ts}_{safe_reason}.png")
			html = os.path.join("logs", f"{self.safe_account_name}_{ts}_{safe_reason}.html")
			try:
				await page.screenshot(path=png, full_page=True)
			except Exception:
				pass
			try:
				content = await page.content()
				with open(html, "w", encoding="utf-8") as f:
					f.write(content)
			except Exception:
				pass
		except Exception:
			pass

	@staticmethod
	def _get_daily_like_limit(trust_level: int | None) -> int:
		if trust_level is None:
			return 50
		return LinuxDoAutoReadLike.LIKE_LIMITS.get(int(trust_level), 50)

	async def _fetch_json_same_origin(self, page, path_or_url: str) -> tuple[int, Any]:
		url = path_or_url
		if path_or_url.startswith("/"):
			url = f"{self.settings.origin}{path_or_url}"
		print(f"🔍 {self.account_name}: [API] 请求 {url}")
		resp = await page.evaluate(
			"""async ({ url }) => {
				try {
					const r = await fetch(url, { credentials: 'include' });
					const t = await r.text();
					return { status: r.status, text: t };
				} catch (e) {
					return { status: 0, text: String(e) };
				}
			}""",
			{"url": url},
		)
		if not isinstance(resp, dict):
			print(f"⚠️ {self.account_name}: [API] 响应异常（非dict）: {str(resp)[:200]}")
			return 0, {"error": str(resp)}
		status = int(resp.get("status") or 0)
		text = resp.get("text") or ""
		text_preview = text[:300] if len(text) > 300 else text
		print(f"🔍 {self.account_name}: [API] 响应 status={status}, body_len={len(text)}, preview={text_preview!r}")
		try:
			return status, json.loads(text)
		except Exception as e:
			print(f"⚠️ {self.account_name}: [API] JSON 解析失败: {e}")
			return status, {"raw": text}

	async def _get_current_user_from_client(self, page) -> dict[str, Any] | None:
		"""从前端运行时对象获取当前用户（比打 /session/current.json 更稳定）。"""
		try:
			res = await page.evaluate(
				"""() => {
					const pick = (u) => {
						if (!u) return null;
						const username = u.username ?? u.name ?? u.userName;
						const trust_level = u.trust_level ?? u.trustLevel;
						return { username: username ?? null, trust_level: trust_level ?? null };
					};
					try {
						const u1 = window.Discourse?.User?.current?.();
						const r1 = pick(u1);
						if (r1 && r1.username) return r1;
					} catch {}
					try {
						const u2 = window.Discourse?.__container__?.lookup?.('current-user:main');
						const r2 = pick(u2);
						if (r2 && r2.username) return r2;
					} catch {}
					try {
						const u3 = window.PreloadStore?.get?.('currentUser')
							|| window.PreloadStore?.data?.currentUser
							|| window.PreloadStore?.data?.['currentUser'];
						const r3 = pick(u3);
						if (r3 && r3.username) return r3;
					} catch {}
					return null;
				}"""
			)
		except Exception:
			return None
		if not isinstance(res, dict):
			return None
		username = res.get("username")
		if not username:
			return None
		try:
			tl_raw = res.get("trust_level")
			tl = int(tl_raw) if tl_raw is not None else None
		except Exception:
			tl = None
		return {"username": str(username), "trust_level": tl, "_from_client": True}

	async def _get_current_user_from_dom(self, page) -> dict[str, Any] | None:
		"""通过 DOM 检测登录状态（备用方案，当 /session/current.json 被限流时使用）"""
		print(f"🔍 {self.account_name}: [DOM检测] 尝试从页面 DOM 获取用户信息")
		try:
			result = await page.evaluate("""() => {
				// 方法1: 检查 sidebar 中的 "我的帖子" 或 "我的消息" 链接（最可靠）
				const sidebarUserLinks = document.querySelectorAll('.sidebar-section-link[href^="/u/"]');
				for (const link of sidebarUserLinks) {
					const href = link.getAttribute('href') || '';
					const match = href.match(/\\/u\\/([^\\/]+)/);
					if (match && match[1]) {
						return { username: match[1], source: 'sidebar_link' };
					}
				}

				// 方法2: 检查用户头像/用户名元素
				const avatarLink = document.querySelector('.current-user a[href^="/u/"]');
				if (avatarLink) {
					const href = avatarLink.getAttribute('href') || '';
					const match = href.match(/\\/u\\/([^\\/]+)/);
					if (match) {
						return { username: match[1], source: 'avatar_link' };
					}
				}

				// 方法3: 检查用户菜单中的用户名
				const userMenu = document.querySelector('.user-menu-links a[href^="/u/"]');
				if (userMenu) {
					const href = userMenu.getAttribute('href') || '';
					const match = href.match(/\\/u\\/([^\\/]+)/);
					if (match) {
						return { username: match[1], source: 'user_menu' };
					}
				}

				// 方法4: 检查 header 中的用户信息
				const headerUser = document.querySelector('.header-dropdown-toggle.current-user');
				if (headerUser) {
					const img = headerUser.querySelector('img');
					if (img) {
						const alt = img.getAttribute('alt') || '';
						if (alt) {
							return { username: alt, source: 'header_img_alt' };
						}
					}
				}

				// 方法5: 检查页面是否有登录按钮（表示未登录）
				const loginBtn = document.querySelector('.login-button, .btn-primary.login-button, a[href="/login"]');
				if (loginBtn && loginBtn.offsetParent !== null) {
					return { not_logged_in: true };
				}

				// 方法6: 检查 body 上的 logged-in class
				if (document.body.classList.contains('logged-in')) {
					// 尝试从其他地方获取用户名
					const anyUserLink = document.querySelector('a[href^="/u/"][data-user-card]');
					if (anyUserLink) {
						const username = anyUserLink.getAttribute('data-user-card');
						if (username) {
							return { username: username, source: 'data_user_card' };
						}
					}
					return { logged_in_but_unknown: true };
				}

				// 方法7: 检查是否存在 header 中的用户按钮（即使没有 logged-in class）
				const headerCurrentUser = document.querySelector('.header-dropdown-toggle.current-user');
				if (headerCurrentUser) {
					return { logged_in_but_unknown: true };
				}

				return null;
			}""")

			if not result:
				print(f"⚠️ {self.account_name}: [DOM检测] 无法从 DOM 确定登录状态")
				return None

			if result.get("not_logged_in"):
				print(f"⚠️ {self.account_name}: [DOM检测] 检测到登录按钮，用户未登录")
				return None

			username = result.get("username")
			if username:
				print(f"✅ {self.account_name}: [DOM检测] 从 {result.get('source')} 检测到用户: {username}")
				# 返回基础用户信息，trust_level 未知时默认为 1
				return {"username": username, "trust_level": None, "_from_dom": True}

			if result.get("logged_in_but_unknown"):
				print(f"⚠️ {self.account_name}: [DOM检测] 页面显示已登录但无法获取用户名，使用配置的用户名")
				return {"username": self.username, "trust_level": None, "_from_dom": True}

			return None
		except Exception as e:
			print(f"⚠️ {self.account_name}: [DOM检测] DOM 检测失败: {e}")
			return None

	async def _get_current_user(self, page, max_retries: int = 3) -> dict[str, Any] | None:
		# 获取当前页面状态用于诊断
		try:
			current_url = page.url
			print(f"🔍 {self.account_name}: [页面状态] 当前 URL: {current_url}")
		except Exception as e:
			print(f"⚠️ {self.account_name}: [页面状态] 获取 URL 失败: {e}")

		for attempt in range(max_retries):
			# 先处理 Cloudflare “Just a moment” 全屏挑战，否则 /session/current.json 常见 429/异常
			try:
				await self._maybe_pass_cloudflare_interstitial(page)
			except Exception:
				pass

			# 1) 先用前端对象判断（最不依赖后端接口变动）
			client_user = await self._get_current_user_from_client(page)
			if client_user:
				return client_user

			# 2) 再用 DOM 判断（当页面脚本尚未完全加载/被拦截时）
			dom_user = await self._get_current_user_from_dom(page)
			if dom_user:
				return dom_user

			# 3) 最后才尝试 /session/current.json（可选；linux.do 可能已关闭/限流）
			if not self._should_use_session_current_api():
				if attempt < max_retries - 1:
					await page.wait_for_timeout(1800)
					continue
				return None

			status, data = await self._fetch_json_same_origin(page, "/session/current.json")

			# 处理 429 限流 - 改用 DOM 检测
			if status == 429:
				# 很多时候 429 是因为仍在 Cloudflare challenge 页，优先再处理一次 challenge
				try:
					if await self._is_cloudflare_interstitial(page):
						print(f"⚠️ {self.account_name}: [用户检查] 仍处于 Cloudflare challenge，处理后重试")
						await self._maybe_pass_cloudflare_interstitial(page)
						await page.wait_for_timeout(1200)
						continue
				except Exception:
					pass
				print(f"⚠️ {self.account_name}: [用户检查] /session/current.json 返回 429 限流")
				# DOM 检测也失败，等待一小段时间后重试
				if attempt < max_retries - 1:
					print(f"⚠️ {self.account_name}: [用户检查] DOM 检测失败，等待 5 秒后重试 ({attempt+1}/{max_retries})")
					await page.wait_for_timeout(5000)
					continue
				return None

			if status != 200 or not isinstance(data, dict):
				print(f"⚠️ {self.account_name}: [用户检查] 获取 session 失败 status={status}")
				return None
			user = data.get("current_user")
			if isinstance(user, dict) and user.get("username"):
				print(f"✅ {self.account_name}: [用户检查] 已登录用户: {user.get('username')}, trust_level={user.get('trust_level')}")
				return user
			print(f"⚠️ {self.account_name}: [用户检查] session 响应中无 current_user 字段")
			return None

		print(f"⚠️ {self.account_name}: [用户检查] 重试 {max_retries} 次后仍失败")
		return None

	async def _get_trust_level_from_client(self, page) -> int | None:
		try:
			res = await page.evaluate(
				"""() => {
					try {
						const u1 = window.Discourse?.User?.current?.();
						const tl1 = u1?.trust_level;
						if (typeof tl1 === 'number') return tl1;
					} catch {}
					try {
						const u2 = window.Discourse?.__container__?.lookup?.('current-user:main');
						const tl2 = u2?.trust_level;
						if (typeof tl2 === 'number') return tl2;
					} catch {}
					try {
						const u3 = window.PreloadStore?.get?.('currentUser')
							|| window.PreloadStore?.data?.currentUser
							|| window.PreloadStore?.data?.['currentUser'];
						const tl3 = u3?.trust_level;
						if (typeof tl3 === 'number') return tl3;
					} catch {}
					return null;
				}"""
			)
		except Exception:
			return None
		try:
			return int(res) if res is not None else None
		except Exception:
			return None

	async def _get_trust_level_from_user_json(self, page, username: str) -> int | None:
		username = str(username or "").strip()
		if not username:
			return None
		candidates = [
			f"/u/{username}.json",
			f"/users/{username}.json",
			f"/u/{username}/summary.json",
			f"/users/{username}/summary.json",
		]
		for path in candidates:
			try:
				status, data = await self._fetch_json_same_origin(page, path)
			except Exception:
				continue
			if status != 200 or not isinstance(data, dict):
				continue
			user = data.get("user")
			if not isinstance(user, dict):
				user = data.get("user_summary") if isinstance(data.get("user_summary"), dict) else None
			if not isinstance(user, dict):
				continue
			tl = user.get("trust_level")
			if tl is None:
				continue
			try:
				return int(tl)
			except Exception:
				continue
		return None

	async def _maybe_solve_cloudflare(self, page) -> None:
		if linuxdo_solve_captcha is None:
			if not self._warned_no_cf_solver:
				self._warned_no_cf_solver = True
				print(
					f"⚠️ {self.account_name}: [CF] 未启用验证码求解（sign_in_with_linuxdo.solve_captcha 不可用），"
					f"遇到 Cloudflare 可能无法自动通过"
				)
			return
		print(f"🔍 {self.account_name}: [CF] 尝试解决 Cloudflare interstitial")
		try:
			solved = await linuxdo_solve_captcha(page, captcha_type="cloudflare", challenge_type="interstitial")
			print(f"✅ {self.account_name}: [CF] interstitial 求解结果: {solved}")
		except Exception as e:
			print(f"⚠️ {self.account_name}: [CF] interstitial 处理失败: {e}")
		if self.settings.try_turnstile_solver:
			print(f"🔍 {self.account_name}: [CF] 尝试解决 Cloudflare turnstile")
			try:
				solved = await linuxdo_solve_captcha(page, captcha_type="cloudflare", challenge_type="turnstile")
				print(f"✅ {self.account_name}: [CF] turnstile 求解结果: {solved}")
			except Exception as e:
				print(f"⚠️ {self.account_name}: [CF] turnstile 处理失败: {e}")

	async def _linuxdo_login(self, page) -> None:
		# 说明：GitHub Hosted Runner 上 Turnstile 经常是不可见/强风控形态，自动点击不稳定。
		# 这里尽量依赖缓存的 storage_state 复用登录态；必要时才走登录表单+interstitial 处理。
		print(f"🔍 {self.account_name}: [登录] 步骤1: 导航到登录页 {self.settings.origin}/login")
		await page.goto(f"{self.settings.origin}/login", wait_until="domcontentloaded")
		await page.wait_for_timeout(1200)

		# 记录登录页加载后状态
		try:
			current_url = page.url
			title = await page.title()
			print(f"🔍 {self.account_name}: [登录] 登录页加载完成 URL={current_url}, title={title!r}")
		except Exception as e:
			print(f"⚠️ {self.account_name}: [登录] 获取登录页信息失败: {e}")

		print(f"🔍 {self.account_name}: [登录] 步骤2: 尝试解决 Cloudflare 验证")
		await self._maybe_pass_cloudflare_interstitial(page, max_wait_seconds=60)

		async def _has_login_inputs() -> bool:
			try:
				return bool(
					await page.evaluate(
						"""() => {
							const sels = [
								'#login-account-name',
								'#signin_username',
								'input[name="login"]',
								'input[name="username"]',
								'input[type="email"]',
								'input[autocomplete="username"]',
								'#login-account-password',
								'#signin_password',
								'input[name="password"]',
								'input[type="password"]',
								'input[autocomplete="current-password"]',
							];
							for (const sel of sels) {
								const el = document.querySelector(sel);
								if (!el) continue;
								if (el.type === 'hidden') continue;
								return true;
							}
							return false;
						}"""
					)
				)
			except Exception:
				return False

		# 若仍停留在 CF 挑战页（页面只剩 cf-turnstile-response 等隐藏 input），不要继续填表单
		if not await _has_login_inputs():
			if await self._is_cloudflare_interstitial(page):
				print(f"⚠️ {self.account_name}: [登录] 仍处于 Cloudflare 验证页，继续等待通过后再尝试登录")
				await self._maybe_pass_cloudflare_interstitial(page, max_wait_seconds=90)
			if not await _has_login_inputs():
				await self._dump_debug(page, "linuxdo_login_no_form_inputs")
				raise RuntimeError("Cloudflare 验证未通过，登录页未出现账号/密码输入框")

		async def _set_value(selectors: list[str], value: str) -> bool:
			for sel in selectors:
				try:
					ok = await page.evaluate(
						"""({ sel, value }) => {
							try {
								const el = document.querySelector(sel);
								if (!el) return false;
								el.focus();
								el.value = value;
								el.dispatchEvent(new Event('input', { bubbles: true }));
								el.dispatchEvent(new Event('change', { bubbles: true }));
								return true;
							} catch (e) {
								return false;
							}
						}""",
						{"sel": sel, "value": value},
					)
					if ok:
						return True
				except Exception:
					continue
			return False

		print(f"🔍 {self.account_name}: [登录] 步骤3: 填写用户名")
		user_ok = await _set_value(
			[
				"#login-account-name",
				"#signin_username",
				'input[name="login"]',
				'input[name="username"]',
				'input[type="email"]',
				'input[autocomplete="username"]',
			],
			self.username,
		)
		print(f"🔍 {self.account_name}: [登录] 用户名填写结果: {'成功' if user_ok else '失败'}")

		print(f"🔍 {self.account_name}: [登录] 步骤4: 填写密码")
		pwd_ok = await _set_value(
			[
				"#login-account-password",
				"#signin_password",
				'input[name="password"]',
				'input[type="password"]',
				'input[autocomplete="current-password"]',
			],
			self.password,
		)
		print(f"🔍 {self.account_name}: [登录] 密码填写结果: {'成功' if pwd_ok else '失败'}")

		if not user_ok or not pwd_ok:
			# 若此时仍是 Cloudflare challenge（页面脚本可能刷新），先尝试通过 challenge 再重试一次
			try:
				if await self._is_cloudflare_interstitial(page):
					print(f"⚠️ {self.account_name}: [登录] 填写失败且检测到 Cloudflare 验证页，尝试通过后重试填写")
					await self._maybe_pass_cloudflare_interstitial(page, max_wait_seconds=90)
					user_ok = await _set_value(
						[
							"#login-account-name",
							"#signin_username",
							'input[name="login"]',
							'input[name="username"]',
							'input[type="email"]',
							'input[autocomplete="username"]',
						],
						self.username,
					)
					pwd_ok = await _set_value(
						[
							"#login-account-password",
							"#signin_password",
							'input[name="password"]',
							'input[type="password"]',
							'input[autocomplete="current-password"]',
						],
						self.password,
					)
			except Exception:
				pass

		if not user_ok or not pwd_ok:
			# 打印页面上可用的输入框以便调试
			try:
				inputs_info = await page.evaluate("""() => {
					const inputs = Array.from(document.querySelectorAll('input'));
					return inputs.map(i => ({
						id: i.id,
						name: i.name,
						type: i.type,
						placeholder: i.placeholder,
						visible: i.offsetParent !== null
					}));
				}""")
				print(f"🔍 {self.account_name}: [登录] 页面上的输入框: {inputs_info}")
			except Exception:
				pass
			raise RuntimeError("linux.do 登录页未找到可输入的账号/密码框")

		print(f"🔍 {self.account_name}: [登录] 步骤5: 点击登录按钮")
		clicked = False
		for sel in [
			"#signin-button",
			"#login-button",
			'button:has-text("登录")',
			'button[type="submit"]',
			'input[type="submit"]',
		]:
			try:
				btn = await page.query_selector(sel)
				if btn:
					print(f"🔍 {self.account_name}: [登录] 找到登录按钮 selector={sel}")
					await btn.click()
					clicked = True
					break
			except Exception:
				continue
		if not clicked:
			print(f"⚠️ {self.account_name}: [登录] 未找到登录按钮，尝试按 Enter 键")
			try:
				await page.keyboard.press("Enter")
			except Exception:
				pass

		# 等待跳出 /login 或 session/current 可获取到 current_user
		print(f"🔍 {self.account_name}: [登录] 步骤6: 等待登录跳转")
		await page.wait_for_timeout(2000)

		# 记录点击登录后的页面状态
		try:
			current_url = page.url
			title = await page.title()
			print(f"🔍 {self.account_name}: [登录] 点击登录后页面状态 URL={current_url}, title={title!r}")
		except Exception as e:
			print(f"⚠️ {self.account_name}: [登录] 获取点击后页面状态失败: {e}")

		# 检测并处理 hCaptcha（登录后可能触发）
		if _handle_hcaptcha is not None:
			print(f"🔍 {self.account_name}: [登录] 步骤6.5: 检测 hCaptcha 验证码")
			try:
				hcaptcha_solved = await _handle_hcaptcha(page, self.account_name)
				if hcaptcha_solved:
					print(f"✅ {self.account_name}: [登录] hCaptcha 已解决，继续登录流程")
					await page.wait_for_timeout(1000)
					# hCaptcha 解完后可能需要再次点击登录/验证按钮
					for sel in [
						'button:has-text("验证")',
						"#signin-button",
						"#login-button",
						'button:has-text("登录")',
						'button[type="submit"]',
					]:
						try:
							btn = await page.query_selector(sel)
							if btn:
								await btn.click()
								print(f"ℹ️ {self.account_name}: [登录] hCaptcha 后点击了 '{sel}'")
								break
						except Exception:
							continue
			except Exception as e_hcaptcha:
				print(f"⚠️ {self.account_name}: [登录] hCaptcha 处理异常(非阻塞): {e_hcaptcha!r}")

		print(f"🔍 {self.account_name}: [登录] 步骤7: 再次尝试解决 Cloudflare 验证")
		await self._maybe_solve_cloudflare(page)

		try:
			await page.wait_for_function(
				"""() => {
					const u = location.href || '';
					if (!u.includes('/login')) return true;
					const t = document.body ? (document.body.innerText || '') : '';
					return t.includes('已登录') || t.includes('logout') || t.includes('退出');
				}""",
				timeout=90000,
			)
			print(f"✅ {self.account_name}: [登录] 页面跳转检测通过")
		except Exception as e:
			print(f"⚠️ {self.account_name}: [登录] 等待跳转超时或失败: {e}")
			# 记录超时时的页面状态
			try:
				current_url = page.url
				title = await page.title()
				print(f"🔍 {self.account_name}: [登录] 超时时页面状态 URL={current_url}, title={title!r}")
			except Exception:
				pass
			# 允许后续用 /session/current.json 再判定
			pass

	async def _ensure_logged_in(self, page) -> dict[str, Any]:
		print(f"🔍 {self.account_name}: [登录检查] 开始访问 {self.settings.origin}/latest")
		await page.goto(f"{self.settings.origin}/latest", wait_until="domcontentloaded")
		await page.wait_for_timeout(1200)

		# 打印页面状态
		try:
			current_url = page.url
			title = await page.title()
			print(f"🔍 {self.account_name}: [登录检查] 页面已加载 URL={current_url}, title={title!r}")
		except Exception as e:
			print(f"⚠️ {self.account_name}: [登录检查] 获取页面信息失败: {e}")

		# 先尝试通过 Cloudflare 全屏挑战，否则后续 /session/current.json 可能一直 429
		try:
			await self._maybe_pass_cloudflare_interstitial(page)
		except Exception:
			pass

		user = await self._get_current_user(page)
		if user:
			print(f"✅ {self.account_name}: [登录检查] 缓存登录有效，跳过登录流程")
			return user

		print(f"ℹ️ {self.account_name}: 未登录，开始登录 linux.do")
		try:
			await self._linuxdo_login(page)
		except Exception as e:
			print(f"❌ {self.account_name}: [登录] 登录过程异常: {e}")
			await self._dump_debug(page, "linuxdo_login_failed")
			raise

		print(f"🔍 {self.account_name}: [登录检查] 登录流程完成，重新检查用户状态")
		user = await self._get_current_user(page)
		if not user:
			print(f"❌ {self.account_name}: [登录检查] 登录后仍无法获取用户信息")
			await self._dump_debug(page, "linuxdo_login_no_current_user")
			raise RuntimeError("linux.do 登录后仍无法获取当前用户信息（可能被 Cloudflare/风控拦截）")
		return user

	async def _sync_likes_24h(self, page, username: str) -> set[int]:
		cutoff = datetime.now(tz=UTC) - timedelta(hours=24)
		offset = 0
		pages = 0
		post_latest_ts: dict[int, int] = {}

		while pages < 5:
			path = f"/user_actions.json?limit=50&username={username}&filter=1&offset={offset}"
			status, data = await self._fetch_json_same_origin(page, path)
			if status != 200 or not isinstance(data, dict):
				break
			items = data.get("user_actions") or []
			if not isinstance(items, list) or not items:
				break

			seen_old = False
			for item in items:
				if not isinstance(item, dict):
					continue
				post_id = item.get("post_id")
				created_at = item.get("created_at")
				if not post_id or not created_at:
					continue
				try:
					# 形如 2025-01-01T12:34:56.789Z
					t = datetime.fromisoformat(str(created_at).replace("Z", "+00:00"))
				except Exception:
					continue
				if t < cutoff:
					seen_old = True
					continue
				try:
					pid = int(post_id)
				except Exception:
					continue
				ts = int(t.timestamp())
				if pid not in post_latest_ts or post_latest_ts[pid] < ts:
					post_latest_ts[pid] = ts

			if seen_old or len(items) < 50:
				break
			offset += 50
			pages += 1

		return set(post_latest_ts.keys())

	async def _fetch_topics(self, page, page_no: int) -> list[dict[str, Any]]:
		endpoint = "unread" if self.settings.feed == "unread" else "latest"
		path = f"/{endpoint}.json?no_definitions=true&page={page_no}"
		print(f"🔍 {self.account_name}: [主题获取] 请求主题列表 endpoint={endpoint}, page={page_no}")
		status, data = await self._fetch_json_same_origin(page, path)
		if status != 200 or not isinstance(data, dict):
			print(f"⚠️ {self.account_name}: [主题获取] 请求失败 status={status}")
			return []
		tl = data.get("topic_list") or {}
		topics = tl.get("topics") or []
		if not isinstance(topics, list):
			print(f"⚠️ {self.account_name}: [主题获取] 响应中无 topics 列表")
			return []
		result = [t for t in topics if isinstance(t, dict)]
		print(f"✅ {self.account_name}: [主题获取] 获取到 {len(result)} 个主题")
		return result

	async def _simulate_reading(self, page, seconds: int) -> None:
		seconds = max(3, seconds)
		start = time.time()
		while time.time() - start < seconds:
			# 小幅滚动为主，偶尔大幅滚动
			if random.random() < 0.08:
				delta = random.randint(200, 520)
			else:
				delta = random.randint(18, 60)
			try:
				await page.evaluate(
					"""({ delta }) => {
						window.scrollBy({ top: delta, behavior: 'smooth' });
					}""",
					{"delta": delta},
				)
			except Exception:
				pass
			await page.wait_for_timeout(random.randint(350, 850))

	async def _click_one_like_candidate(self, page, exclude_post_ids: set[int]) -> int | None:
		"""尽量按 linux.do.js 的方式点一次赞：扫描可点击元素 -> scrollIntoView -> element.click()。

		返回被点赞的 post_id（若无法解析则返回 None）。
		"""
		exclude = list(exclude_post_ids)[:2000]
		res = await page.evaluate(
			"""({ exclude }) => {
				const excluded = new Set(exclude || []);

				const isVisible = (el) => {
					try { return !!(el && el.offsetParent !== null); } catch { return false; }
				};

				const isLiked = (el) => {
					try {
						if (!el) return true;
						if (el.classList && (el.classList.contains('has-like') || el.classList.contains('liked'))) return true;
						if (el.getAttribute && el.getAttribute('aria-pressed') === 'true') return true;
						// 父/子节点可能带 liked 标记
						const sub = el.querySelector?.('.has-like, .liked, [aria-pressed=\"true\"]');
						return !!sub;
					} catch {
						return false;
					}
				};

				const getPostId = (el) => {
					try {
						const article = el.closest?.('article[data-post-id]');
						if (article) {
							const v = article.getAttribute('data-post-id');
							if (v) return Number(v);
						}
						const any = el.closest?.('[data-post-id]');
						if (any) {
							const v = any.getAttribute('data-post-id');
							if (v) return Number(v);
						}
					} catch {}
					return null;
				};

				const pickClickable = (el) => {
					try {
						// discourse-reactions 容器：优先点内部 like button
						if (el.matches?.('.discourse-reactions-reaction-button')) {
							return el.querySelector('button.btn-toggle-reaction-like') || el;
						}
						// like-count / 外层容器：尽量找同一 post 内的核心 like button
						if (el.matches?.('.like-count') || el.matches?.('[data-like-button]') || el.matches?.('.like-button')) {
							const post = el.closest?.('.topic-post') || el.closest?.('article') || el.parentElement;
							return post?.querySelector?.('button.toggle-like') || el;
						}
						return el;
					} catch {
						return el;
					}
				};

				const selectors = [
					// 与 linux.do.js: likeRandomComment 一致
					'.like-button',
					'.like-count',
					'[data-like-button]',
					'.discourse-reactions-reaction-button',
					// 更明确的按钮（便于某些主题只渲染 button，不渲染容器可点）
					'div.discourse-reactions-reaction-button button.btn-toggle-reaction-like',
					'button.toggle-like',
				];

				const nodes = [];
				for (const sel of selectors) {
					for (const el of document.querySelectorAll(sel)) nodes.push(el);
				}

				const candidates = [];
				for (const el of nodes) {
					const clickable = pickClickable(el);
					if (!clickable) continue;
					if (!isVisible(clickable)) continue;
					if (clickable.disabled) continue;
					if (isLiked(clickable)) continue;
					const pid = getPostId(clickable);
					if (pid && excluded.has(pid)) continue;
					candidates.push({ pid, clickable });
				}

				if (!candidates.length) return { clicked: false, pid: null };

				const choice = candidates[Math.floor(Math.random() * candidates.length)];
				try {
					choice.clickable.scrollIntoView({ behavior: 'instant', block: 'center' });
				} catch {}
				try {
					choice.clickable.click();
				} catch (e) {
					return { clicked: false, pid: choice.pid ?? null, error: String(e) };
				}
				return { clicked: true, pid: choice.pid ?? null };
			}""",
			{"exclude": exclude},
		)
		if not isinstance(res, dict):
			return None
		if not res.get("clicked"):
			return None
		pid = res.get("pid")
		try:
			return int(pid) if pid else None
		except Exception:
			return None

	def _install_like_rate_limit_listener(self, page) -> None:
		self._like_rate_limited_until = 0.0
		self._like_rate_limited_reason = ""

		async def _handle_response(resp) -> None:
			try:
				status = resp.status
				url = resp.url or ""
			except Exception:
				return
			if status != 429:
				return
			if ("/discourse-reactions/" not in url) and ("/toggle.json" not in url) and ("/like" not in url):
				return
			try:
				data = await resp.json()
			except Exception:
				data = None
			if not isinstance(data, dict):
				return
			if data.get("error_type") != "rate_limit":
				return
			extras = data.get("extras") or {}
			if not isinstance(extras, dict):
				return
			wait_seconds = extras.get("wait_seconds")
			try:
				ws = int(wait_seconds)
			except Exception:
				return
			if ws <= 0:
				return
			self._like_rate_limited_until = time.time() + ws
			self._like_rate_limited_reason = str(extras.get("time_left") or f"{ws}s")
			print(f"⚠️ {self.account_name}: 点赞触发限流 429，需等待 {self._like_rate_limited_reason}")

		def _on_response(resp) -> None:
			# Playwright 的事件回调不保证 await，这里用 task 承接异步逻辑
			try:
				asyncio.create_task(_handle_response(resp))
			except Exception:
				pass

		page.on("response", _on_response)

	async def _like_some_posts(
		self,
		page,
		remaining_likes: int,
		liked_posts_24h: set[int],
	) -> tuple[int, bool]:
		"""返回 (本主题点赞数量, 是否触发限流)"""
		if remaining_likes <= 0 or self.settings.max_likes_per_topic <= 0:
			print(f"🔍 {self.account_name}: [点赞] 跳过点赞（remaining={remaining_likes}, max_per_topic={self.settings.max_likes_per_topic}）")
			return 0, False
		if self._like_rate_limited_until and time.time() < self._like_rate_limited_until:
			print(f"⚠️ {self.account_name}: [点赞] 仍在限流中，跳过点赞")
			return 0, True

		liked = 0
		target = min(self.settings.max_likes_per_topic, remaining_likes)
		print(f"🔍 {self.account_name}: [点赞] 目标点赞数={target}")
		for i in range(target):
			if self._like_rate_limited_until and time.time() < self._like_rate_limited_until:
				print(f"⚠️ {self.account_name}: [点赞] 点赞过程中触发限流，停止")
				return liked, True
			try:
				pid = await self._click_one_like_candidate(page, liked_posts_24h)
				if pid is None:
					print(f"🔍 {self.account_name}: [点赞] 未找到可点赞的帖子")
					break
				liked += 1
				liked_posts_24h.add(pid)
				self.auto_state.setdefault("liked_posts", {})[str(pid)] = _now_ts()
				self._save_auto_state()
				print(f"✅ {self.account_name}: [点赞] 成功点赞 post_id={pid} ({liked}/{target})")
				await page.wait_for_timeout(random.randint(650, 1400))
			except Exception as e:
				print(f"⚠️ {self.account_name}: [点赞] 点赞失败: {e}")
				continue

		limited = bool(self._like_rate_limited_until and time.time() < self._like_rate_limited_until)
		return liked, limited

	async def run(self, proxy_config: dict | None = None) -> None:
		stats = RunStats(account_name=self.account_name, username=self.username)
		print(f"🔍 {self.account_name}: [运行] 开始执行 Linux.do 自动阅读点赞")
		print(f"🔍 {self.account_name}: [运行] 配置: origin={self.settings.origin}, feed={self.settings.feed}, topics_per_run={self.settings.topics_per_run}")
		self._prune_auto_state()
		self._save_auto_state()

		storage_state = self.storage_state_path if os.path.exists(self.storage_state_path) else None
		print(
			f"ℹ️ {self.account_name}: 启动浏览器 (headless={self.settings.headless}, proxy={'yes' if proxy_config else 'no'}, cache={'yes' if storage_state else 'no'})"
		)
		if storage_state:
			print(f"🔍 {self.account_name}: [运行] 使用缓存文件: {storage_state}")

		async with AsyncCamoufox(
			headless=self.settings.headless,
			humanize=True,
			locale="zh-CN",
			disable_coop=True,
			config={"forceScopeAccess": True},
			i_know_what_im_doing=True,
			window=(1280, 720),
			geoip=True if proxy_config else False,
			proxy=proxy_config,
		) as browser:
			print(f"✅ {self.account_name}: [运行] 浏览器启动成功")
			context = await browser.new_context(storage_state=storage_state)
			page = await context.new_page()
			print(f"✅ {self.account_name}: [运行] 新页面创建成功")
			self._install_like_rate_limit_listener(page)

			user = await self._ensure_logged_in(page)
			trust_level = user.get("trust_level")
			username = str(user.get("username") or self.username)

			# trust_level 决定每日点赞上限；当 /session/current.json 被限流时，DOM 回退可能拿不到 trust_level
			if trust_level is None:
				try:
					await page.wait_for_timeout(900)
				except Exception:
					pass
				tl = await self._get_trust_level_from_client(page)
				if tl is None:
					tl = await self._get_trust_level_from_user_json(page, username)
				if tl is not None:
					trust_level = tl
					print(f"ℹ️ {self.account_name}: [额度] 通过回退方式获取 trust_level={trust_level}")
				else:
					print(f"⚠️ {self.account_name}: [额度] 未能获取 trust_level，将按 50 的保守上限计算")

			limit = self._get_daily_like_limit(int(trust_level) if trust_level is not None else None)

			print(f"🔍 {self.account_name}: [运行] 开始同步近24小时点赞记录")
			liked_posts_24h = await self._sync_likes_24h(page, username)
			used = len(liked_posts_24h)
			remaining = max(0, limit - used)
			if remaining <= 0 and trust_level is None:
				# 若因为 trust_level 缺失导致“误判用完”，最后再尝试一次回退获取
				tl = await self._get_trust_level_from_client(page)
				if tl is None:
					tl = await self._get_trust_level_from_user_json(page, username)
				if tl is not None:
					trust_level = tl
					limit = self._get_daily_like_limit(int(trust_level))
					remaining = max(0, limit - used)
					print(f"ℹ️ {self.account_name}: [额度] 重新计算：trust_level={trust_level}, 上限={limit}, 剩余={remaining}")
			stats.trust_level = int(trust_level) if trust_level is not None else None
			stats.like_limit = int(limit)
			stats.liked_posts_24h_at_start = int(used)
			stats.remaining_likes_at_start = int(remaining)
			print(
				f"ℹ️ {self.account_name}: 用户={username}, trust_level={trust_level}, "
				f"近24h已点赞(去重post)={used}, 上限={limit}, 剩余={remaining}"
			)

			read_topics: dict[str, int] = self.auto_state.get("read_topics") or {}
			if not isinstance(read_topics, dict):
				read_topics = {}
				self.auto_state["read_topics"] = read_topics
			print(f"🔍 {self.account_name}: [运行] 已缓存阅读主题数: {len(read_topics)}")

			start_page = int(self.auto_state.get("feed_page") or 0)
			page_no = max(0, start_page)
			selected: list[dict[str, Any]] = []
			print(f"🔍 {self.account_name}: [运行] 开始获取主题列表，起始页={start_page}")

			while len(selected) < self.settings.topics_per_run and page_no <= start_page + self.settings.max_pages_per_run:
				topics = await self._fetch_topics(page, page_no)
				if not topics:
					print(f"🔍 {self.account_name}: [运行] 第 {page_no} 页无主题，跳到下一页")
					page_no += 1
					continue
				for t in topics:
					tid = t.get("id")
					if tid is None:
						continue
					try:
						tid_s = str(int(tid))
					except Exception:
						continue
					if tid_s in read_topics:
						stats.skipped_already_read += 1
						continue
					# 默认跳过置顶（pinned）主题，避免重复刷常驻帖
					if self.settings.skip_pinned:
						try:
							if bool(t.get("pinned")) or bool(t.get("pinned_globally")):
								stats.skipped_pinned += 1
								continue
						except Exception:
							pass
					posts_count = t.get("posts_count")
					try:
						if int(posts_count or 0) >= 5000:
							stats.skipped_too_long += 1
							continue
					except Exception:
						pass
					selected.append(t)
					if len(selected) >= self.settings.topics_per_run:
						break
				page_no += 1

			self.auto_state["feed_page"] = page_no
			self._save_auto_state()
			stats.selected_topics = len(selected)
			print(f"🔍 {self.account_name}: [运行] 主题筛选完成: 选中={len(selected)}, 已读跳过={stats.skipped_already_read}, 置顶跳过={stats.skipped_pinned}, 过长跳过={stats.skipped_too_long}")

			if not selected:
				print(f"ℹ️ {self.account_name}: 没有可阅读的新主题（可能都已读/接口空）")
			for idx, topic in enumerate(selected):
				tid = topic.get("id")
				title = topic.get("title") or ""
				try:
					tid_i = int(tid)
				except Exception:
					continue

				url = f"{self.settings.origin}/t/topic/{tid_i}"
				print(f"ℹ️ {self.account_name}: [{idx+1}/{len(selected)}] 打开主题 {tid_i} {title!r}")
				try:
					print(f"🔍 {self.account_name}: [主题] 导航到 {url}")
					await page.goto(url, wait_until="domcontentloaded")
					await page.wait_for_timeout(1200)
					# 记录主题页加载后状态
					try:
						current_url = page.url
						page_title = await page.title()
						print(f"🔍 {self.account_name}: [主题] 页面加载完成 URL={current_url}, title={page_title!r}")
					except Exception as e:
						print(f"⚠️ {self.account_name}: [主题] 获取页面信息失败: {e}")
					await self._maybe_solve_cloudflare(page)
				except Exception as e:
					print(f"⚠️ {self.account_name}: 打开主题失败 {tid_i}: {e}")
					stats.open_failures += 1
					continue

				read_s = random.randint(self.settings.min_read_seconds, max(self.settings.min_read_seconds, self.settings.max_read_seconds))
				print(f"🔍 {self.account_name}: [主题] 开始模拟阅读 {read_s} 秒")
				await self._simulate_reading(page, read_s)

				print(f"🔍 {self.account_name}: [主题] 阅读完成，开始点赞（剩余额度={remaining}）")
				liked_in_topic, limited = await self._like_some_posts(page, remaining, liked_posts_24h)
				stats.likes_clicked += liked_in_topic
				remaining = max(0, remaining - liked_in_topic)

				read_topics[str(tid_i)] = _now_ts()
				stats.read_topics += 1
				self._save_auto_state()

				print(
					f"✅ {self.account_name}: [{idx+1}/{len(selected)}] 主题 {tid_i} 阅读 {read_s}s，点赞 {liked_in_topic}，剩余可赞 {remaining}"
				)
				if limited:
					print(f"⚠️ {self.account_name}: 已触发点赞限流，停止本次点赞（阅读仍可继续）")
					# 触发限流后不再点赞，但仍继续读完剩余主题以"纯阅读"为主
					remaining = 0

				await page.wait_for_timeout(random.randint(900, 2200))

			print(f"🔍 {self.account_name}: [运行] 所有主题处理完成，保存登录状态")
			try:
				await context.storage_state(path=self.storage_state_path)
				print(f"✅ {self.account_name}: [运行] 登录状态已保存到 {self.storage_state_path}")
			except Exception as e:
				print(f"⚠️ {self.account_name}: 保存 storage_state 失败: {e}")

		print(f"✅ {self.account_name}: [运行] 执行完成 - 阅读主题={stats.read_topics}/{stats.selected_topics}, 点赞={stats.likes_clicked}, 失败={stats.open_failures}")
		return stats


def _load_linuxdo_accounts_from_env() -> list[tuple[str, str, str]]:
	"""从环境变量加载 Linux.do 账号配置

	优先使用 LINUXDO_ACCOUNTS 变量（专用），如果不存在则回退到 ACCOUNTS 变量（兼容旧配置）

	LINUXDO_ACCOUNTS 格式（推荐）:
	[
		{"name": "账号1", "username": "user1", "password": "pass1"},
		{"username": "user2", "password": "pass2"}
	]

	ACCOUNTS 格式（兼容）:
	[
		{"name": "账号1", "linux.do": {"username": "user1", "password": "pass1"}, ...},
		...
	]

	Returns:
		list[tuple[str, str, str]]: [(账号名, 用户名, 密码), ...]
	"""
	targets: list[tuple[str, str, str]] = []

	# 优先使用 LINUXDO_ACCOUNTS
	linuxdo_accounts_str = os.getenv("LINUXDO_ACCOUNTS")
	if linuxdo_accounts_str:
		try:
			data = json.loads(linuxdo_accounts_str)
		except Exception as e:
			raise RuntimeError(f"LINUXDO_ACCOUNTS 不是合法 JSON: {e}")
		if not isinstance(data, list):
			raise RuntimeError("LINUXDO_ACCOUNTS 必须是 JSON 数组")

		for i, item in enumerate(data):
			if not isinstance(item, dict):
				continue
			username = str(item.get("username") or "").strip()
			password = str(item.get("password") or "").strip()
			if not username or not password:
				continue
			name = str(item.get("name") or f"LinuxDo账号{i + 1}").strip()
			targets.append((name, username, password))

		if targets:
			print(f"ℹ️ 从 LINUXDO_ACCOUNTS 加载了 {len(targets)} 个账号")
			return targets

	# 回退到 ACCOUNTS（兼容旧配置）
	accounts_str = os.getenv("ACCOUNTS")
	if not accounts_str:
		raise RuntimeError(f"缺少环境变量 LINUXDO_ACCOUNTS 或 ACCOUNTS（已尝试加载 {DOTENV_PATH}）")
	try:
		data = json.loads(accounts_str)
	except Exception as e:
		raise RuntimeError(f"ACCOUNTS 不是合法 JSON: {e}")
	if not isinstance(data, list):
		raise RuntimeError("ACCOUNTS 必须是 JSON 数组")

	accounts = [AccountConfig.from_dict(item, i) for i, item in enumerate(data) if isinstance(item, dict)]

	for i, ac in enumerate(accounts):
		name = ac.get_display_name(i)
		ld = ac.linux_do or {}
		if not isinstance(ld, dict):
			continue
		u = str(ld.get("username") or "").strip()
		p = str(ld.get("password") or "").strip()
		if not u or not p:
			continue
		targets.append((name, u, p))

	if targets:
		print(f"ℹ️ 从 ACCOUNTS 加载了 {len(targets)} 个 Linux.do 账号（兼容模式）")

	return targets


async def _run_all() -> None:
	settings = LinuxDoSettings.from_env()
	targets = _load_linuxdo_accounts_from_env()
	global_proxy = _load_proxy()

	if global_proxy:
		print(f"⚙️ 已加载全局代理: {global_proxy.get('server', '(unknown)')}")

	if not targets:
		print("⚠️ 未找到包含 linux.do 用户名密码的账号配置，任务结束")
		return

	# 阅读轮数配置（默认 1 轮）
	read_rounds = _clamp(_env_int("LINUXDO_READ_ROUNDS", 1), 1, 100)
	# 账号间延迟配置（秒），避免多账号连续请求触发 429 限流
	account_delay = _clamp(_env_int("LINUXDO_ACCOUNT_DELAY", 30), 0, 300)
	# 轮次间延迟配置（秒）
	round_delay = _clamp(_env_int("LINUXDO_ROUND_DELAY", 60), 0, 600)

	print(f"ℹ️ 共找到 {len(targets)} 个账号，阅读轮数={read_rounds}，账号间延迟={account_delay}秒，轮次间延迟={round_delay}秒")

	all_stats: list[RunStats] = []
	for round_idx in range(read_rounds):
		if read_rounds > 1:
			print(f"\n{'='*20} 第 {round_idx + 1}/{read_rounds} 轮 {'='*20}")

		for idx, (name, u, p) in enumerate(targets):
			round_info = f"[轮次{round_idx + 1}] " if read_rounds > 1 else ""
			print(f"\n===== {round_info}linux.do 自动阅读点赞：{name} ({idx+1}/{len(targets)}) =====")
			try:
				stats = await LinuxDoAutoReadLike(account_name=name, username=u, password=p, settings=settings).run(proxy_config=global_proxy)
				all_stats.append(stats)
				print(f"✅ {name}: 完成")
			except Exception as e:
				print(f"❌ {name}: 失败: {e}")

			# 账号之间添加延迟，避免触发 429 限流
			if idx < len(targets) - 1 and account_delay > 0:
				print(f"ℹ️ 等待 {account_delay} 秒后处理下一个账号...")
				await asyncio.sleep(account_delay)

		# 轮次之间添加延迟
		if round_idx < read_rounds - 1 and round_delay > 0:
			print(f"\nℹ️ 第 {round_idx + 1} 轮完成，等待 {round_delay} 秒后开始下一轮...")
			await asyncio.sleep(round_delay)

	# 发送通知（若配置了任意通知渠道）
	has_any_channel = any(
		str(os.getenv(k, "") or "").strip()
		for k in [
			"EMAIL_USER",
			"EMAIL_PASS",
			"EMAIL_TO",
			"PUSHPLUS_TOKEN",
			"SERVERPUSHKEY",
			"DINGDING_WEBHOOK",
			"FEISHU_WEBHOOK",
			"WEIXIN_WEBHOOK",
			"TELEGRAM_BOT_TOKEN",
			"TELEGRAM_CHAT_ID",
		]
	)
	if has_any_channel:
		total_read = sum(s.read_topics for s in all_stats)
		total_likes = sum(s.likes_clicked for s in all_stats)
		time_info = f'🕓 执行时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'
		lines: list[str] = [time_info, f"📌 本次总计：阅读主题 {total_read}，点赞 {total_likes}"]
		for s in all_stats:
			lines.append(
				f"👤 {s.account_name}: 阅读主题 {s.read_topics}/{s.selected_topics}，点赞 {s.likes_clicked}，"
				f"信任等级 {s.trust_level}，近24h已赞 {s.liked_posts_24h_at_start}/{s.like_limit}"
			)
		notify.push_message("Linux.do 自动阅读点赞", "\n".join(lines), msg_type="text")
	else:
		print("ℹ️ 未检测到通知渠道配置，跳过消息通知")


def main() -> None:
	asyncio.run(_run_all())


if __name__ == "__main__":
	main()
