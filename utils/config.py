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

    @classmethod
    def from_dict(cls, name: str, data: dict) -> "ProviderConfig":
        """从字典创建 ProviderConfig

        配置格式:
        - 基础: {"origin": "https://example.com"}
        - 完整: {"origin": "https://example.com", "login_path": "/login", "api_user_key": "x-api-user", "bypass_method": "waf_cookies", ...}
        """
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

    def get_sign_in_url(self) -> str | None:
        """获取签到 URL"""
        if self.sign_in_path:
            return f"{self.origin}{self.sign_in_path}"
        return None

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
                # 该站点使用 Veloera-User 作为用户标识头
                api_user_key="Veloera-User",
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
