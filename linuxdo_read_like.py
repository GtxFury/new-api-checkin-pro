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
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from camoufox.async_api import AsyncCamoufox

from utils.config import AccountConfig

try:  # pragma: no cover - 可选依赖
	from sign_in_with_linuxdo import solve_captcha as linuxdo_solve_captcha  # type: ignore
except Exception:  # pragma: no cover - 可选依赖缺失时静默跳过
	linuxdo_solve_captcha = None


UTC = timezone.utc


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
			headless=_env_int("HEADLESS", 0) == 1,
			storage_state_dir=_env_str("STORAGE_STATE_DIR", "storage-states"),
		)


class LinuxDoAutoReadLike:
	LIKE_LIMITS: dict[int, int] = {0: 50, 1: 50, 2: 75, 3: 100, 4: 150}

	def __init__(self, account_name: str, username: str, password: str, settings: LinuxDoSettings):
		self.account_name = account_name
		self.safe_account_name = _safe_name(account_name)
		self.username = username
		self.password = password
		self.settings = settings

		Path(self.settings.storage_state_dir).mkdir(parents=True, exist_ok=True)
		self.storage_state_path = os.path.join(
			self.settings.storage_state_dir, f"linuxdo_forum_{self.safe_account_name}.json"
		)
		self.auto_state_path = os.path.join(
			self.settings.storage_state_dir, f"linuxdo_forum_{self.safe_account_name}_autostate.json"
		)

		self.auto_state: dict[str, Any] = self._load_auto_state()
		self._like_rate_limited_until: float = 0.0
		self._like_rate_limited_reason: str = ""

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

	@staticmethod
	def _get_daily_like_limit(trust_level: int | None) -> int:
		if trust_level is None:
			return 50
		return LinuxDoAutoReadLike.LIKE_LIMITS.get(int(trust_level), 50)

	async def _fetch_json_same_origin(self, page, path_or_url: str) -> tuple[int, Any]:
		url = path_or_url
		if path_or_url.startswith("/"):
			url = f"{self.settings.origin}{path_or_url}"
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
			return 0, {"error": str(resp)}
		status = int(resp.get("status") or 0)
		text = resp.get("text") or ""
		try:
			return status, json.loads(text)
		except Exception:
			return status, {"raw": text}

	async def _get_current_user(self, page) -> dict[str, Any] | None:
		status, data = await self._fetch_json_same_origin(page, "/session/current.json")
		if status != 200 or not isinstance(data, dict):
			return None
		user = data.get("current_user")
		if isinstance(user, dict) and user.get("username"):
			return user
		return None

	async def _maybe_solve_cloudflare(self, page) -> None:
		if linuxdo_solve_captcha is None:
			return
		try:
			await linuxdo_solve_captcha(page, captcha_type="cloudflare", challenge_type="interstitial")
		except Exception:
			pass
		try:
			await linuxdo_solve_captcha(page, captcha_type="cloudflare", challenge_type="turnstile")
		except Exception:
			pass

	async def _linuxdo_login(self, page) -> None:
		await page.goto(f"{self.settings.origin}/login", wait_until="domcontentloaded")
		await page.wait_for_timeout(1200)
		await self._maybe_solve_cloudflare(page)

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
		if not user_ok or not pwd_ok:
			raise RuntimeError("linux.do 登录页未找到可输入的账号/密码框")

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
					await btn.click()
					clicked = True
					break
			except Exception:
				continue
		if not clicked:
			try:
				await page.keyboard.press("Enter")
			except Exception:
				pass

		# 等待跳出 /login 或 session/current 可获取到 current_user
		await page.wait_for_timeout(1500)
		await self._maybe_solve_cloudflare(page)
		try:
			await page.wait_for_function(
				"""() => {
					const u = location.href || '';
					if (!u.includes('/login')) return true;
					const t = document.body ? (document.body.innerText || '') : '';
					return t.includes('已登录') || t.includes('logout') || t.includes('退出');
				}""",
				timeout=25000,
			)
		except Exception:
			# 允许后续用 /session/current.json 再判定
			pass

	async def _ensure_logged_in(self, page) -> dict[str, Any]:
		await page.goto(f"{self.settings.origin}/latest", wait_until="domcontentloaded")
		await page.wait_for_timeout(1200)

		user = await self._get_current_user(page)
		if user:
			return user

		print(f"ℹ️ {self.account_name}: 未登录，开始登录 linux.do")
		await self._linuxdo_login(page)

		user = await self._get_current_user(page)
		if not user:
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
		status, data = await self._fetch_json_same_origin(page, path)
		if status != 200 or not isinstance(data, dict):
			return []
		tl = data.get("topic_list") or {}
		topics = tl.get("topics") or []
		if not isinstance(topics, list):
			return []
		return [t for t in topics if isinstance(t, dict)]

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

	async def _collect_like_candidate_post_ids(self, page) -> list[int]:
		# 仅针对 discourse-reactions 插件的 “like” 按钮（与 linux.do.js 一致）
		res = await page.evaluate(
			"""() => {
				const posts = Array.from(document.querySelectorAll('article[data-post-id]'));
				const out = [];
				for (const post of posts) {
					const postId = post.getAttribute('data-post-id');
					if (!postId) continue;
					const btn = post.querySelector('div.discourse-reactions-reaction-button button.btn-toggle-reaction-like');
					if (!btn) continue;
					// 可见性简单判断
					const rect = btn.getBoundingClientRect();
					const visible = rect.width > 0 && rect.height > 0;
					if (!visible) continue;
					// 已点赞判断（尽量保守）
					const pressed = btn.getAttribute('aria-pressed') === 'true';
					const liked = pressed || btn.classList.contains('liked') || btn.classList.contains('has-like');
					if (liked) continue;
					out.push(Number(postId));
				}
				return out;
			}""",
		)
		if not isinstance(res, list):
			return []
		out: list[int] = []
		for x in res:
			try:
				out.append(int(x))
			except Exception:
				continue
		return out

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
			return 0, False
		if self._like_rate_limited_until and time.time() < self._like_rate_limited_until:
			return 0, True

		candidates = await self._collect_like_candidate_post_ids(page)
		# 避免点到 24h 内已点赞过的帖子（含本次运行前同步的数据）
		candidates = [pid for pid in candidates if pid not in liked_posts_24h]
		if not candidates:
			return 0, False

		random.shuffle(candidates)
		to_like = candidates[: min(len(candidates), self.settings.max_likes_per_topic, remaining_likes)]

		liked = 0
		for post_id in to_like:
			if self._like_rate_limited_until and time.time() < self._like_rate_limited_until:
				return liked, True
			try:
				sel = (
					f'article[data-post-id="{post_id}"] '
					'div.discourse-reactions-reaction-button button.btn-toggle-reaction-like'
				)
				btn = await page.query_selector(sel)
				if not btn:
					continue
				await btn.scroll_into_view_if_needed()
				await page.wait_for_timeout(random.randint(350, 900))
				await btn.click()
				liked += 1
				liked_posts_24h.add(post_id)
				self.auto_state.setdefault("liked_posts", {})[str(post_id)] = _now_ts()
				self._save_auto_state()
				await page.wait_for_timeout(random.randint(650, 1400))
			except Exception:
				continue

		limited = bool(self._like_rate_limited_until and time.time() < self._like_rate_limited_until)
		return liked, limited

	async def run(self) -> None:
		self._prune_auto_state()
		self._save_auto_state()

		storage_state = self.storage_state_path if os.path.exists(self.storage_state_path) else None
		print(
			f"ℹ️ {self.account_name}: 启动浏览器 (headless={self.settings.headless}, cache={'yes' if storage_state else 'no'})"
		)

		async with AsyncCamoufox(
			headless=self.settings.headless,
			humanize=True,
			locale="zh-CN",
			disable_coop=True,
			config={"forceScopeAccess": True},
			i_know_what_im_doing=True,
			window=(1280, 720),
		) as browser:
			context = await browser.new_context(storage_state=storage_state)
			page = await context.new_page()
			self._install_like_rate_limit_listener(page)

			user = await self._ensure_logged_in(page)
			trust_level = user.get("trust_level")
			username = str(user.get("username") or self.username)
			limit = self._get_daily_like_limit(int(trust_level) if trust_level is not None else None)

			liked_posts_24h = await self._sync_likes_24h(page, username)
			used = len(liked_posts_24h)
			remaining = max(0, limit - used)
			print(
				f"ℹ️ {self.account_name}: 用户={username}, trust_level={trust_level}, "
				f"近24h已点赞(去重post)={used}, 上限={limit}, 剩余={remaining}"
			)

			read_topics: dict[str, int] = self.auto_state.get("read_topics") or {}
			if not isinstance(read_topics, dict):
				read_topics = {}
				self.auto_state["read_topics"] = read_topics

			start_page = int(self.auto_state.get("feed_page") or 0)
			page_no = max(0, start_page)
			selected: list[dict[str, Any]] = []

			while len(selected) < self.settings.topics_per_run and page_no <= start_page + self.settings.max_pages_per_run:
				topics = await self._fetch_topics(page, page_no)
				if not topics:
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
						continue
					posts_count = t.get("posts_count")
					try:
						if int(posts_count or 0) >= 5000:
							continue
					except Exception:
						pass
					selected.append(t)
					if len(selected) >= self.settings.topics_per_run:
						break
				page_no += 1

			self.auto_state["feed_page"] = page_no
			self._save_auto_state()

			if not selected:
				print(f"ℹ️ {self.account_name}: 没有可阅读的新主题（可能都已读/接口空）")
			for topic in selected:
				tid = topic.get("id")
				title = topic.get("title") or ""
				try:
					tid_i = int(tid)
				except Exception:
					continue

				url = f"{self.settings.origin}/t/topic/{tid_i}"
				print(f"ℹ️ {self.account_name}: 打开主题 {tid_i} {title!r}")
				try:
					await page.goto(url, wait_until="domcontentloaded")
					await page.wait_for_timeout(1200)
					await self._maybe_solve_cloudflare(page)
				except Exception as e:
					print(f"⚠️ {self.account_name}: 打开主题失败 {tid_i}: {e}")
					continue

				read_s = random.randint(self.settings.min_read_seconds, max(self.settings.min_read_seconds, self.settings.max_read_seconds))
				await self._simulate_reading(page, read_s)

				liked_in_topic, limited = await self._like_some_posts(page, remaining, liked_posts_24h)
				remaining = max(0, remaining - liked_in_topic)

				read_topics[str(tid_i)] = _now_ts()
				self._save_auto_state()

				print(
					f"ℹ️ {self.account_name}: 主题 {tid_i} 阅读 {read_s}s，点赞 {liked_in_topic}，剩余可赞 {remaining}"
				)
				if limited:
					print(f"⚠️ {self.account_name}: 已触发点赞限流，停止本次点赞（阅读仍可继续）")
					# 触发限流后不再点赞，但仍继续读完剩余主题以“纯阅读”为主
					remaining = 0

				await page.wait_for_timeout(random.randint(900, 2200))

			try:
				await context.storage_state(path=self.storage_state_path)
			except Exception as e:
				print(f"⚠️ {self.account_name}: 保存 storage_state 失败: {e}")


def _load_accounts_from_env() -> list[AccountConfig]:
	accounts_str = os.getenv("ACCOUNTS")
	if not accounts_str:
		raise RuntimeError("缺少环境变量 ACCOUNTS")
	try:
		data = json.loads(accounts_str)
	except Exception as e:
		raise RuntimeError(f"ACCOUNTS 不是合法 JSON: {e}")
	if not isinstance(data, list):
		raise RuntimeError("ACCOUNTS 必须是 JSON 数组")
	return [AccountConfig.from_dict(item, i) for i, item in enumerate(data) if isinstance(item, dict)]


async def _run_all() -> None:
	settings = LinuxDoSettings.from_env()
	accounts = _load_accounts_from_env()

	targets: list[tuple[str, str, str]] = []
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

	if not targets:
		print("⚠️ 未找到包含 linux.do 用户名密码的账号配置，任务结束")
		return

	for name, u, p in targets:
		print(f"\n===== linux.do 自动阅读点赞：{name} =====")
		try:
			await LinuxDoAutoReadLike(account_name=name, username=u, password=p, settings=settings).run()
			print(f"✅ {name}: 完成")
		except Exception as e:
			print(f"❌ {name}: 失败: {e}")


def main() -> None:
	asyncio.run(_run_all())


if __name__ == "__main__":
	main()
