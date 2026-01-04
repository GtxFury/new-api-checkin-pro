#!/usr/bin/env python3
"""
配置管理模块
"""

import json
import os
from dataclasses import dataclass
from typing import Dict, Literal


@dataclass
class ProviderConfig:
    """Provider 配置"""

    name: str
    origin: str
    login_path: str = "/login"
    status_path: str = "/api/status"
    auth_state_path: str = "/api/oauth/state"
    sign_in_path: str | None = "/api/user/sign_in"
    user_info_path: str = "/api/user/self"
    api_user_key: str = "new-api-user"
    github_client_id: str | None = None
    github_auth_path: str = "/api/oauth/github"
    linuxdo_client_id: str | None = None
    linuxdo_auth_path: str = "/api/oauth/linuxdo"
    aliyun_captcha: bool = False
    bypass_method: Literal["waf_cookies"] | None = None
    # 是否启用 Turnstile 校验（需要在浏览器中执行签到）
    turnstile_check: bool = False
    # 可选的签到状态接口路径（如 /api/user/check_in_status）
    check_in_status_path: str | None = None
    # 可选的签到页面路径（如 /console/checkin），用于浏览器签到
    checkin_page_path: str | None = None
    # 可选：newapi 通用控制台签到模式（/console/personal 点击“立即签到”）
    # - newapi_console_personal: 浏览器进入 /console/personal 点击“立即签到”
    # - new_api_post: 通过后端接口 POST 触发签到（适用于部分站点控制台会跳转 /login 的情况）
    # 兼容：历史值 "api_post" 会被自动映射为 "new_api_post"
    checkin_mode: Literal["newapi_console_personal", "new_api_post"] | None = None
    # new_api_post 模式：可选的“是否已签到”查询策略（用于避免重复 POST）
    # - newapi_monthly: GET {path}?month=YYYY-MM，读取 data.stats.checked_in_today
    post_checkin_status_kind: Literal["newapi_monthly"] | None = None
    post_checkin_status_path: str | None = None
    # Linux.do OAuth 回调策略：
    # - auto: 维持默认兼容逻辑（按站点特性/历史行为自动选择）
    # - fast_fetch: 在浏览器内 fetch 调用 /api/oauth/linuxdo
    # - navigation: 浏览器导航到 /api/oauth/linuxdo（更容易通过部分 WAF/CF）
    # - spa: 依赖站点同源前端 /oauth/linuxdo 完成回调并写入 localStorage
    linuxdo_callback_mode: Literal["auto", "fast_fetch", "navigation", "spa"] = "auto"

    @classmethod
    def from_dict(cls, name: str, data: dict) -> "ProviderConfig":
        """从字典创建 ProviderConfig

        配置格式:
        - 基础: {"origin": "https://example.com"}
        - 完整: {"origin": "https://example.com", "login_path": "/login", "api_user_key": "x-api-user", "bypass_method": "waf_cookies", ...}
        """
        raw_checkin_mode = data.get("checkin_mode")
        # 兼容旧值：api_post -> new_api_post
        if raw_checkin_mode == "api_post":
            raw_checkin_mode = "new_api_post"

        return cls(
            name=name,
            origin=data["origin"],
            login_path=data.get("login_path", "/login"),
            status_path=data.get("status_path", "/api/status"),
            auth_state_path=data.get("auth_state_path", "/api/oauth/state"),
            sign_in_path=data.get("sign_in_path", "/api/user/sign_in"),
            user_info_path=data.get("user_info_path", "/api/user/self"),
            api_user_key=data.get("api_user_key", "new-api-user"),
            github_client_id=data.get("github_client_id"),
            github_auth_path=data.get("github_auth_path", "/api/oauth/github"),
            linuxdo_client_id=data.get("linuxdo_client_id"),
            linuxdo_auth_path=data.get("linuxdo_auth_path", "/api/oauth/linuxdo"),
            aliyun_captcha=data.get("aliyun_captcha", False),
            bypass_method=data.get("bypass_method"),
            turnstile_check=data.get("turnstile_check", False),
            check_in_status_path=data.get("check_in_status_path"),
            checkin_page_path=data.get("checkin_page_path"),
            checkin_mode=raw_checkin_mode,
            post_checkin_status_kind=data.get("post_checkin_status_kind"),
            post_checkin_status_path=data.get("post_checkin_status_path"),
            linuxdo_callback_mode=data.get("linuxdo_callback_mode", "auto"),
        )

    def needs_waf_cookies(self) -> bool:
        """判断是否需要获取 WAF cookies"""
        return self.bypass_method == "waf_cookies"

    def needs_manual_check_in(self) -> bool:
        """判断是否需要手动调用签到接口"""
        return self.sign_in_path is not None

    def get_login_url(self) -> str:
        """获取登录 URL"""
        return f"{self.origin}{self.login_path}"

    def get_status_url(self) -> str:
        """获取状态 URL"""
        return f"{self.origin}{self.status_path}"

    def get_auth_state_url(self) -> str:
        """获取认证状态 URL"""
        return f"{self.origin}{self.auth_state_path}"

    def get_sign_in_url(self, user_id: str | int | None = None) -> str | None:
        """获取签到 URL

        Args:
            user_id: 用户 ID（部分站点可能需要在 URL 中携带用户信息）

        Returns:
            str | None: 签到 URL，如果不需要签到则返回 None
        """
        if not self.sign_in_path:
            return None

        # 如果是函数，则调用函数生成 URL（支持动态签名 URL）
        if callable(self.sign_in_path):
            return self.sign_in_path(self.origin, user_id)

        return f"{self.origin}{self.sign_in_path}"

    def get_user_info_url(self) -> str:
        """获取用户信息 URL"""
        return f"{self.origin}{self.user_info_path}"

    def get_github_auth_url(self) -> str:
        """获取 GitHub 认证 URL"""
        return f"{self.origin}{self.github_auth_path}"
    
    def get_linuxdo_auth_url(self) -> str:
        """获取 LinuxDo 认证 URL"""
        return f"{self.origin}{self.linuxdo_auth_path}"

    def get_check_in_status_url(self) -> str | None:
        """获取签到状态 URL"""
        if self.check_in_status_path:
            return f"{self.origin}{self.check_in_status_path}"
        return None


@dataclass
class AppConfig:
    """应用配置"""

    providers: Dict[str, ProviderConfig]

    @classmethod
    def load_from_env(cls) -> "AppConfig":
        """从环境变量加载配置"""
        providers = {
            "anyrouter": ProviderConfig(
                name="anyrouter",
                origin="https://anyrouter.top",
                login_path="/login",
                status_path="/api/status",
                auth_state_path="/api/oauth/state",
                sign_in_path="/api/user/sign_in",
                user_info_path="/api/user/self",
                api_user_key="new-api-user",
                github_client_id="Ov23liOwlnIiYoF3bUqw",
                github_auth_path="/api/oauth/github",
                linuxdo_client_id="8w2uZtoWH9AUXrZr1qeCEEmvXLafea3c",
                linuxdo_auth_path="/api/oauth/linuxdo",
                aliyun_captcha=False,
                bypass_method="waf_cookies",
                turnstile_check=False,
            ),
            "wzw": ProviderConfig(
                name="wzw",
                origin="https://wzw.pp.ua",
                login_path="/login",
                status_path="/api/status",
                auth_state_path="/api/oauth/state",
                # WONG 公益站使用 /api/user/checkin 作为签到接口
                sign_in_path="/api/user/checkin",
                user_info_path="/api/user/self",
                # 该站点使用 new-api-user 作为用户标识头（小写）
                api_user_key="new-api-user",
                github_client_id=None,
                github_auth_path="/api/oauth/github",
                # 从 https://wzw.pp.ua/api/status 中动态获取（该值可能会变动）
                linuxdo_client_id=None,
                linuxdo_auth_path="/api/oauth/linuxdo",
                aliyun_captcha=False,
                # 该站点不需要 WAF cookies
                bypass_method=None,
                turnstile_check=False,
                # 该站点需要 SPA 完成回调建立 session/localStorage
                linuxdo_callback_mode="spa",
            ),
            "agentrouter": ProviderConfig(
                name="agentrouter",
                origin="https://agentrouter.org",
                login_path="/login",
                status_path="/api/status",
                auth_state_path="/api/oauth/state",
                sign_in_path=None,  # 无需签到接口，查询用户信息时自动完成签到
                user_info_path="/api/user/self",
                api_user_key="new-api-user",
                github_client_id="Ov23lidtiR4LeVZvVRNL",
                github_auth_path="/api/oauth/github",
                linuxdo_client_id="KZUecGfhhDZMVnv8UtEdhOhf9sNOhqVX",
                linuxdo_auth_path="/api/oauth/linuxdo",
                aliyun_captcha=True,
                bypass_method=None,
                turnstile_check=False,
            ),
            "runanytime": ProviderConfig(
                name="runanytime",
                origin="https://runanytime.hxi.me",
                login_path="/login",
                status_path="/api/status",
                auth_state_path="/api/oauth/state",
                # runanytime 的签到需要在浏览器中完成（Turnstile），HTTP 客户端不直接调用签到接口
                sign_in_path=None,
                user_info_path="/api/user/self",
                # 站点实现可能在 Veloera/New-API 间切换，这里默认按 new-api-user 配置，
                # 实际请求侧会同时兼容注入 Veloera-User 等常见变体。
                api_user_key="new-api-user",
                github_client_id=None,
                github_auth_path="/api/oauth/github",
                # 从 https://runanytime.hxi.me/api/status 中获取
                linuxdo_client_id="AHjK9O3FfbCXKpF6VXGBC60K21yJ2fYk",
                linuxdo_auth_path="/api/oauth/linuxdo",
                aliyun_captcha=False,
                bypass_method=None,
                turnstile_check=True,
                check_in_status_path="/api/user/check_in_status",
            ),
            "hotaru": ProviderConfig(
                name="hotaru",
                origin="https://api.hotaruapi.top",
                login_path="/login",
                status_path="/api/status",
                auth_state_path="/api/oauth/state",
                sign_in_path=None,  # 签到在前端 /console/personal 完成
                user_info_path="/api/user/self",
                api_user_key="new-api-user",
                github_client_id=None,
                github_auth_path="/api/oauth/github",
                linuxdo_client_id=None,  # 从 /api/status 获取，避免写死导致配置过期
                linuxdo_auth_path="/api/oauth/linuxdo",
                aliyun_captcha=False,
                bypass_method=None,
                turnstile_check=False,
                check_in_status_path="/api/user/check_in_status",
                checkin_page_path="/console/personal",
                checkin_mode="newapi_console_personal",
            ),
            "kfc": ProviderConfig(
                name="kfc",
                origin="https://kfc-api.sxxe.net",
                login_path="/login",
                status_path="/api/status",
                auth_state_path="/api/oauth/state",
                sign_in_path=None,  # 签到在前端 /console/personal 完成
                user_info_path="/api/user/self",
                api_user_key="new-api-user",
                github_client_id=None,
                github_auth_path="/api/oauth/github",
                linuxdo_client_id=None,  # 从 /api/status 获取，避免写死导致配置过期
                linuxdo_auth_path="/api/oauth/linuxdo",
                aliyun_captcha=False,
                bypass_method=None,
                turnstile_check=False,
                check_in_status_path="/api/user/check_in_status",
                checkin_page_path="/console/personal",
                checkin_mode="newapi_console_personal",
            ),
            "neb": ProviderConfig(
                name="neb",
                origin="https://ai.zzhdsgsss.xyz",
                login_path="/login",
                status_path="/api/status",
                auth_state_path="/api/oauth/state",
                sign_in_path=None,  # 签到在前端 /console/personal 完成
                user_info_path="/api/user/self",
                api_user_key="new-api-user",
                github_client_id=None,
                github_auth_path="/api/oauth/github",
                # 从 /api/status 获取，避免写死导致配置过期
                linuxdo_client_id=None,
                linuxdo_auth_path="/api/oauth/linuxdo",
                aliyun_captcha=False,
                bypass_method=None,
                turnstile_check=False,
                check_in_status_path="/api/user/check_in_status",
                checkin_page_path="/console/personal",
                checkin_mode="newapi_console_personal",
            ),
            "huan": ProviderConfig(
                name="huan",
                origin="https://ai.huan666.de",
                login_path="/login",
                status_path="/api/status",
                auth_state_path="/api/oauth/state",
                # huan：控制台易跳回 /login，这里改用后端接口 POST 触发签到
                sign_in_path="/api/user/checkin",
                user_info_path="/api/user/self",
                api_user_key="new-api-user",
                github_client_id=None,
                github_auth_path="/api/oauth/github",
                # 从 /api/status 获取，避免写死导致配置过期
                linuxdo_client_id=None,
                linuxdo_auth_path="/api/oauth/linuxdo",
                aliyun_captcha=False,
                bypass_method=None,
                turnstile_check=False,
                checkin_mode="new_api_post",
                # newapi 月度状态接口：/api/user/checkin?month=YYYY-MM
                post_checkin_status_kind="newapi_monthly",
                post_checkin_status_path="/api/user/checkin",
                # 该站点更依赖同源 SPA /oauth/linuxdo 完成回调并写入 localStorage
                linuxdo_callback_mode="spa",
            ),
            "dik3": ProviderConfig(
                name="dik3",
                origin="https://ai.dik3.cn",
                login_path="/login",
                status_path="/api/status",
                auth_state_path="/api/oauth/state",
                # 曼波api：使用 SPA 回调完成登录，再用后端接口 POST 触发签到
                sign_in_path="/api/user/checkin",
                user_info_path="/api/user/self",
                api_user_key="new-api-user",
                github_client_id=None,
                github_auth_path="/api/oauth/github",
                # 从 /api/status 获取，避免写死导致配置过期
                linuxdo_client_id=None,
                linuxdo_auth_path="/api/oauth/linuxdo",
                aliyun_captcha=False,
                bypass_method=None,
                turnstile_check=False,
                checkin_mode="new_api_post",
                # newapi 月度状态接口：/api/user/checkin?month=YYYY-MM
                post_checkin_status_kind="newapi_monthly",
                post_checkin_status_path="/api/user/checkin",
                # 该站点依赖同源 SPA /oauth/linuxdo 完成回调并写入 localStorage
                linuxdo_callback_mode="spa",
            ),
            "daiju": ProviderConfig(
                name="daiju",
                origin="https://api.daiju.live",
                login_path="/login",
                status_path="/api/status",
                auth_state_path="/api/oauth/state",
                sign_in_path=None,  # 签到在前端 /console/personal 完成
                user_info_path="/api/user/self",
                api_user_key="new-api-user",
                github_client_id=None,
                github_auth_path="/api/oauth/github",
                # 从 /api/status 获取，避免写死导致配置过期
                linuxdo_client_id=None,
                linuxdo_auth_path="/api/oauth/linuxdo",
                aliyun_captcha=False,
                bypass_method=None,
                turnstile_check=False,
                check_in_status_path="/api/user/check_in_status",
                checkin_page_path="/console/personal",
                checkin_mode="newapi_console_personal",
            ),
            # 兼容旧名称：ccode（有间公益）当前已迁移为 hotaru
            "ccode": ProviderConfig(
                name="ccode",
                origin="https://api.hotaruapi.top",
                login_path="/login",
                status_path="/api/status",
                auth_state_path="/api/oauth/state",
                sign_in_path=None,  # 签到在前端 /console/personal 完成
                user_info_path="/api/user/self",
                api_user_key="new-api-user",
                github_client_id=None,
                github_auth_path="/api/oauth/github",
                linuxdo_client_id=None,  # 从 /api/status 获取，避免写死导致配置过期
                linuxdo_auth_path="/api/oauth/linuxdo",
                aliyun_captcha=False,
                bypass_method=None,
                turnstile_check=False,
                check_in_status_path="/api/user/check_in_status",
                checkin_page_path="/console/personal",
                checkin_mode="newapi_console_personal",
            ),
            "elysiver": ProviderConfig(
                name="elysiver",
                origin="https://elysiver.h-e.top",
                login_path="/login",
                status_path="/api/status",
                auth_state_path="/api/oauth/state",
                # 与 runanytime 一样：签到在前端完成，后端通过 check_in_status 确认
                sign_in_path=None,
                user_info_path="/api/user/self",
                # Veloera 站点约定使用 Veloera-User 作为用户标识头
                api_user_key="Veloera-User",
                github_client_id=None,
                github_auth_path="/api/oauth/github",
                # 从 https://elysiver.h-e.top/api/status 中获取
                linuxdo_client_id="E2eaCQVl9iecd4aJBeTKedXfeKiJpSPF",
                linuxdo_auth_path="/api/oauth/linuxdo",
                aliyun_captcha=False,
                bypass_method=None,
                # 在浏览器中执行每日签到，并通过 /api/user/check_in_status 校验
                turnstile_check=True,
                check_in_status_path="/api/user/check_in_status",
                # newapi 通用签到入口：/console/personal 右侧“立即签到”
                checkin_page_path="/console/personal",
                checkin_mode="newapi_console_personal",
                # 该站点必须依赖 SPA 完成回调（避免回调接口触发 CF/WAF 或 session 未建立）
                linuxdo_callback_mode="spa",
            ),
        }

        # 尝试从环境变量加载自定义 providers
        providers_str = os.getenv("PROVIDERS")
        if providers_str:
            try:
                providers_data = json.loads(providers_str)

                if not isinstance(providers_data, dict):
                    print("⚠️ PROVIDERS must be a JSON object, ignoring custom providers")
                    return cls(providers=providers)

                # 解析自定义 providers,会覆盖默认配置
                for name, provider_data in providers_data.items():
                    try:
                        providers[name] = ProviderConfig.from_dict(name, provider_data)
                    except Exception as e:
                        print(f'⚠️ Failed to parse provider "{name}": {e}, skipping')
                        continue

                print(f"ℹ️ Loaded {len(providers_data)} custom provider(s) from PROVIDERS environment variable")
            except json.JSONDecodeError as e:
                print(f"⚠️ Failed to parse PROVIDERS environment variable: {e}, using default configuration only")
            except Exception as e:
                print(f"⚠️ Error loading PROVIDERS: {e}, using default configuration only")

        return cls(providers=providers)

    def get_provider(self, name: str) -> ProviderConfig | None:
        """获取指定 provider 配置"""
        return self.providers.get(name)


@dataclass
class AccountConfig:
    """账号配置"""

    provider: str = "anyrouter"
    cookies: dict | str = ""
    api_user: str = ""
    name: str | None = None
    linux_do: dict | None = None
    github: dict | None = None
    proxy: dict | None = None

    @classmethod
    def from_dict(cls, data: dict, index: int) -> "AccountConfig":
        """从字典创建 AccountConfig"""
        provider = data.get("provider", "anyrouter")
        name = data.get("name", f"Account {index + 1}")

        # Handle different authentication types
        cookies = data.get("cookies", "")
        linux_do = data.get("linux.do")
        github = data.get("github")
        proxy = data.get("proxy")

        return cls(
            provider=provider,
            name=name if name else None,
            cookies=cookies,
            api_user=data.get("api_user", ""),
            linux_do=linux_do,
            github=github,
            proxy=proxy,
        )

    def get_display_name(self, index: int = 0) -> str:
        """获取显示名称"""
        return self.name if self.name else f"Account {index + 1}"
