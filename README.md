# newapi.ai 多账号自动签到

> Fork from [anyrouter-check-in](https://github.com/millylee/anyrouter-check-in)，添加 linux.do/github 登录时签到，支持更多场景

用于 Claude Code 中转站 newapi.ai 多账号每日签到。  
[AnyRouter 限时注册](https://anyrouter.top/register?aff=wJrb)即送 200 美金（推荐额外赠送 100 美金），每日签到赠送 $25。业界良心，支持 `claude-sonnet-4.5`、`gpt-5-codex`，Claude Code 百万上下文（使用 `/model sonnet[1m]` 开启），`gemini-2.5-pro` 模型。  
[AgentRouter 限时注册](https://agentrouter.org/register?aff=wDU2)即送 200 美金（推荐额外赠送 100 美金），每日签到赠送 $25。支持 `claude-sonnet-4.5`、`gpt-5`、`deepseek-v3.2`、`glm4.6`。  
其它使用 `newapi.ai` 功能相似

## 功能特性

- ✅ 单个/多账号自动签到
- ✅ 多种机器人通知（可选）
- ✅ linux.do 登录认证
- ✅ github 登录认证 (with OTP)
- ✅ Cloudflare bypass
- ✅ linux.do 自动阅读/点赞（可选工作流：`.github/workflows/linuxdo_read_like.yml`）

## 使用方法

### 1. Fork 本仓库

点击右上角的 "Fork" 按钮，将本仓库 fork 到你的账户。

### 2. 设置 GitHub Environment Secret

1. 在你 fork 的仓库中，点击 "Settings" 选项卡
2. 在左侧菜单中找到 "Environments" -> "New environment"
3. 新建一个名为 `production` 的环境
4. 点击新建的 `production` 环境进入环境配置页
5. 点击 "Add environment secret" 创建 secret：
   - Name: `ACCOUNTS`
   - Value: 你的多账号配置数据

### 3. 多账号配置格式
> 如果未提供 `name` 字段，会使用 `Account 1`、`Account 2` 等默认名称。  
> 配置中 `cookies`、`github`、`linux.do` 必须至少配置 1 个。   
> 使用 `cookies` 设置时，`api_user` 字段必填。

示例：

```json
[
    {
      "name": "我的账号",
      "cookies": {
        "session": "account1_session_value"
      },
      "api_user": "account1_api_user_id"
      "github": {
        "username": "myuser",
        "password": "mypass",
      },
      "linux.do": {
        "username": "myuser",
        "password": "mypass",
      }
    },
    {
      "name": "另一个账号",
      "provider": "agentrouter",
      "proxy": {
        "server": "http://username:password@proxy.example.com:8080"
      }
      "linux.do": {
        "username": "user2",
        "password": "pass2",
      }
    }
  ]
```

#### 字段说明：

- `name` (可选)：自定义账号显示名称，用于通知和日志中标识账号
- `provider` (可选)：供应商，内置 `anyrouter`、`agentrouter`、`runanytime`、`hotaru`（兼容旧名 `ccode`）、`kfc`、`neb`、`huan`、`dik3`、`mu`、`daiju`，默认使用 `anyrouter`
- `proxy` (可选)：单个账号代理配置，支持 `http`、`socks5` 代理
- `cookies`(可选)：用于身份验证的 cookies 数据  
  - 对于 `anyrouter`、`agentrouter`：从浏览器获取 `session` 即可  
  - 对于 `runanytime`：newapi 通用签到入口已迁移至控制台 `/console/personal` 的“立即签到”，并保留福利站转盘获取兑换码后自动兑换；需使用 `linux.do` 登录（不再支持仅 cookies）
  - 对于 `hotaru`：newapi 通用签到入口为控制台 `/console/personal` 的“立即签到”（不走福利站转盘）；需使用 `linux.do` 登录（不再支持仅 cookies）
- `api_user`(cookies 设置时必需)：
  - `anyrouter` / `agentrouter`：对应请求头 `new-api-user` 的值  
  - `runanytime`：对应请求头 `new-api-user`（或旧实现的 `Veloera-User`）的值（内部登录流程会自动获取，通常无需手动填写）
- `linux.do`(可选)：用于登录身份验证
  - `username`: 用户名
  - `password`: 密码
- `github`(可选)：用于登录身份验证
  - `username`: 用户名
  - `password`: 密码

#### 供应商配置：

在仓库的 Settings -> Environments -> production -> Environment secrets 中添加：
   - Name: `PROVIDERS`
   - Value: 供应商

常用可选字段（写在 `PROVIDERS` 的单个 provider 配置里）：
- `checkin_mode`：
  - `"newapi_console_personal"`：使用 newapi 通用控制台签到（浏览器进入 `/console/personal` 点击“立即签到”）
  - `"new_api_post"`：使用后端接口 POST 触发签到（适用于控制台会跳转 `/login` 的站点）
- `post_checkin_status_kind` / `post_checkin_status_path`（仅 `checkin_mode="new_api_post"` 时使用）：
  - `"newapi_monthly"` + `"/api/user/checkin"`：GET `{path}?month=YYYY-MM`，读取 `data.stats.checked_in_today` 判断是否已签到
- `checkin_page_path`: 自定义签到页面路径（默认会按站点内置值/候选路径探测）
- `linuxdo_callback_mode`: Linux.do OAuth 回调策略（默认 `"auto"`）
  - `"fast_fetch"`：在浏览器内 `fetch` 调用 `/api/oauth/linuxdo`（更快，但部分站点会因 SameSite/会话校验失败）
  - `"navigation"`：浏览器导航到 `/api/oauth/linuxdo`（更容易通过部分 WAF/CF）
  - `"spa"`：依赖同源前端 `/oauth/linuxdo` 完成回调并写入 localStorage（适用于回调 API 不稳定/容易回登录页的站点）

#### hotaru 站点地址

- 默认固定为 `https://api.hotaruapi.top`（如需自定义可通过 `PROVIDERS` 覆盖）

#### kfc 站点地址

- 默认固定为 `https://kfc-api.sxxe.net`（如需自定义可通过 `PROVIDERS` 覆盖）

#### neb 站点地址

- 默认固定为 `https://ai.zzhdsgsss.xyz`（如需自定义可通过 `PROVIDERS` 覆盖）

#### huan 站点地址

- 默认固定为 `https://ai.huan666.de`（如需自定义可通过 `PROVIDERS` 覆盖）

#### dik3（曼波api）站点地址

- 默认固定为 `https://ai.dik3.cn`（如需自定义可通过 `PROVIDERS` 覆盖）

#### mu（Mu.API）站点地址

- 默认固定为 `https://demo.awa1.fun`（如需自定义可通过 `PROVIDERS` 覆盖）

#### daiju（小呆公益站）站点地址

- 默认固定为 `https://api.daiju.live`（如需自定义可通过 `PROVIDERS` 覆盖）


#### 代理配置
> 应用到所有的账号，如果单个账号需要使用代理，请在单个账号配置中添加 `proxy` 字段。  
> 打开 [webshare](https://dashboard.webshare.io/) 注册账号，获取免费代理

在仓库的 Settings -> Environments -> production -> Environment secrets 中添加：
   - Name: `PROXY`
   - Value: 代理服务器地址


```bash
{
  "server": "http://username:password@proxy.example.com:8080"
}

或者

{
  "server": "http://proxy.example.com:8080",
  "username": "username",
  "password": "password"
}
```


#### 如何获取 cookies 与 api_user 的值。

通过 F12 工具，切到 Application 面板，Cookies -> session 的值，最好重新登录下，但有可能提前失效，失效后报 401 错误，到时请再重新获取。

![获取 cookies](./assets/request-cookie-session.png)

通过 F12 工具，切到 Application 面板，面板，Local storage -> user 对象中的 id 字段。

![获取 api_user](./assets/request-api-user.png)

#### `GitHub` 在新设备上登录会有两次验证

通过打印日志中链接打开并输入验证码。

![输入 OTP](./assets/github-otp.png)

### 4. 启用 GitHub Actions

1. 在你的仓库中，点击 "Actions" 选项卡
2. 如果提示启用 Actions，请点击启用
3. 找到 "newapi.ai 自动签到" workflow
4. 点击 "Enable workflow"

### 5. 测试运行

你可以手动触发一次签到来测试：

1. 在 "Actions" 选项卡中，点击 "newapi.ai 自动签到"
2. 点击 "Run workflow" 按钮
3. 确认运行

![运行结果](./assets/check-in.png)

## 执行时间

- 脚本每 8 小时执行一次（1. action 无法准确触发，基本延时 1~1.5h；2. 目前观测到 newapi.ai 的签到是每 24h 而不是零点就可签到）
- 你也可以随时手动触发签到

## 注意事项

## x666.me（独立签到）

本仓库额外提供了 `x666.me` 的独立签到入口与独立 Action：
- 入口脚本：`main_x666.py`
- Workflow：`.github/workflows/x666.yml`

配置方式：在 `production` 的 Environment secrets 中新增 `ACCOUNTS_X666`，格式如下：

```json
[
  {
    "name": "x666 账号1",
    "linux.do": {
      "username": "linux.do 用户名",
      "password": "linux.do 密码"
    }
  }
]
```

说明：
- 目前 x666 签到已改为：访问 `https://qd.x666.me/` -> 右上角用 `linux.do` 登录 -> 点击“签到” -> 再登录 `https://x666.me/` 获取余额。
- 旧版 `access_token/cookies/api_user` 仍保留兼容，但站点改版后可能无法使用。

- 可以在 Actions 页面查看详细的运行日志
- 支持部分账号失败，只要有账号成功签到，整个任务就不会失败
- `GitHub` 新设备 OTP 验证，注意日志中的链接或配置了通知注意接收的链接，访问链接进行输入验证码

## kfc（独立签到）

本仓库额外提供了 `kfc` 的独立签到入口与独立 Action：
- 入口脚本：`main_kfc.py`
- Workflow：`.github/workflows/kfc.yml`

配置方式：在 `production` 的 Environment secrets 中新增 `ACCOUNTS_KFC`，格式参考 `ACCOUNTS`（需提供 `linux.do` 账号密码），并在账号配置中使用 `provider: "kfc"`（未填写时 `main_kfc.py` 会自动补全）。

## neb（独立签到）

本仓库额外提供了 `neb` 的独立签到入口与独立 Action：
- 入口脚本：`main_neb.py`
- Workflow：`.github/workflows/neb.yml`

配置方式：在 `production` 的 Environment secrets 中新增 `ACCOUNTS_NEB`，格式参考 `ACCOUNTS`（需提供 `linux.do` 账号密码），并在账号配置中使用 `provider: "neb"`（未填写时 `main_neb.py` 会自动补全）。

## huan（独立签到）

本仓库额外提供了 `huan` 的独立签到入口与独立 Action：
- 入口脚本：`main_huan.py`
- Workflow：`.github/workflows/huan.yml`

配置方式：在 `production` 的 Environment secrets 中新增 `ACCOUNTS_HUAN`，格式参考 `ACCOUNTS`（需提供 `linux.do` 账号密码），并在账号配置中使用 `provider: "huan"`（未填写时 `main_huan.py` 会自动补全）。

## dik3（曼波api）（独立签到）

本仓库额外提供了 `dik3`（曼波api）的独立签到入口与独立 Action：
- 入口脚本：`main_dik3.py`
- Workflow：`.github/workflows/dik3.yml`

配置方式：在 `production` 的 Environment secrets 中新增 `ACCOUNTS_DIK3`，格式参考 `ACCOUNTS`（需提供 `linux.do` 账号密码），并在账号配置中使用 `provider: "dik3"`（未填写时 `main_dik3.py` 会自动补全）。

## mu（Mu.API）（独立签到）

本仓库额外提供了 `mu`（Mu.API）的独立签到入口与独立 Action：
- 入口脚本：`main_mu.py`
- Workflow：`.github/workflows/mu.yml`

配置方式：在 `production` 的 Environment secrets 中新增 `ACCOUNTS_MU`，格式参考 `ACCOUNTS`（需提供 `linux.do` 账号密码），并在账号配置中使用 `provider: "mu"`（未填写时 `main_mu.py` 会自动补全）。

## daiju（小呆公益站）（独立签到）

本仓库额外提供了 `daiju` 的独立签到入口与独立 Action：
- 入口脚本：`main_daiju.py`
- Workflow：`.github/workflows/daiju.yml`

配置方式：在 `production` 的 Environment secrets 中新增 `ACCOUNTS_DAIJU`，格式参考 `ACCOUNTS`（需提供 `linux.do` 账号密码），并在账号配置中使用 `provider: "daiju"`（未填写时 `main_daiju.py` 会自动补全）。

## 开启通知

脚本支持多种通知方式，可以通过配置以下环境变量开启，如果 `webhook` 有要求安全设置，例如钉钉，可以在新建机器人时选择自定义关键词，填写 `newapi.ai`。

### 邮箱通知

- `EMAIL_USER`: 发件人邮箱地址
- `EMAIL_PASS`: 发件人邮箱密码/授权码
- `CUSTOM_SMTP_SERVER`: 自定义发件人 SMTP 服务器(可选)
- `EMAIL_TO`: 收件人邮箱地址

### 钉钉机器人

- `DINGDING_WEBHOOK`: 钉钉机器人的 Webhook 地址

### 飞书机器人

- `FEISHU_WEBHOOK`: 飞书机器人的 Webhook 地址

### 企业微信机器人

- `WEIXIN_WEBHOOK`: 企业微信机器人的 Webhook 地址

### Telegram Bot

- `TELEGRAM_BOT_TOKEN`: Telegram 机器人 Token（例如 `123456789:XXXXXX`）
- `TELEGRAM_CHAT_ID`: 接收通知的聊天 ID（个人/群组均可，常见为整数 ID）

### PushPlus 推送

- `PUSHPLUS_TOKEN`: PushPlus 的 Token

### Server 酱

- `SERVERPUSHKEY`: Server 酱的 SendKey

配置步骤：

1. 在仓库的 Settings -> Environments -> production -> Environment secrets 中添加上述环境变量
2. 每个通知方式都是独立的，可以只配置你需要的推送方式
3. 如果某个通知方式配置不正确或未配置，脚本会自动跳过该通知方式

## 故障排除

如果签到失败，请检查：

1. 账号配置格式是否正确
2. 网站是否更改了签到接口
3. 查看 Actions 运行日志获取详细错误信息

## 本地开发环境设置

如果你需要在本地测试或开发，请按照以下步骤设置：

```bash
# 安装所有依赖
uv sync --dev

# 安装 Camoufox 浏览器
python3 -m camoufox fetch

# 按 .env.example 创建 .env
uv run main.py
```

## 测试

```bash
uv sync --dev

# 安装 Camoufox 浏览器
python3 -m camoufox fetch

# 运行测试
uv run pytest tests/
```

## 免责声明

本脚本仅用于学习和研究目的，使用前请确保遵守相关网站的使用条款.
