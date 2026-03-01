#!/usr/bin/env python3
"""
交互式生成 LINUXDOT Secret 值

使用方法:
  1. 运行: python gen_linuxdot.py
  2. 输入你有几个 linux.do 账号
  3. 浏览器依次打开 linux.do 登录页，手动登录
  4. 每个账号登录完成后回到终端按 Enter
  5. 全部完成后自动生成 LINUXDOT 值并复制到剪贴板
"""

import asyncio
import gzip
import base64
import hashlib
import json
import os
import sys


async def login_account(username: str, index: int, total: int) -> dict | None:
    """打开浏览器让用户手动登录一个 linux.do 账号，返回 cookies"""
    from camoufox.async_api import AsyncCamoufox

    username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:8]
    print(f"\n{'='*60}")
    print(f"  账号 {index}/{total}: {username} (hash: {username_hash})")
    print(f"{'='*60}")

    async with AsyncCamoufox(
        headless=False,
        humanize=True,
        locale="zh-CN",
        window=(1280, 720),
    ) as browser:
        context = await browser.new_context()
        page = await context.new_page()

        await page.goto("https://linux.do/login", wait_until="domcontentloaded")
        print(f"  🌐 浏览器已打开 linux.do 登录页")
        print(f"  👆 请在浏览器中手动登录账号: {username}")
        print(f"  ⏳ 登录完成后回到这里按 Enter...")

        await asyncio.get_event_loop().run_in_executor(None, input)

        # 检查登录状态
        try:
            user_check = await page.evaluate("""() => {
                try {
                    return !!document.querySelector('.current-user, .header-dropdown-toggle.current-user');
                } catch(e) { return false; }
            }""")
            print(f"  👤 登录状态: {'✅ 已登录' if user_check else '⚠️ 未检测到，仍保存'}")
        except Exception:
            pass

        # 保存 storage state
        state_dir = "storage-states"
        os.makedirs(state_dir, exist_ok=True)
        state_path = os.path.join(state_dir, f"linuxdo_{username_hash}_storage_state.json")
        state = await context.storage_state()
        with open(state_path, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False)

        cookies = state.get("cookies", [])
        print(f"  💾 已保存: {state_path} ({len(cookies)} cookies)")

        return {
            "hash": username_hash,
            "username": username,
            "state": state,
            "file": f"linuxdo_{username_hash}_storage_state.json",
        }


def generate_secret(results: list[dict]) -> str:
    """将所有账号的完整 storage state 压缩为 GitHub Secret 值 (gzip+base64)"""
    data = {r["file"]: r["state"] for r in results}
    raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    compressed = gzip.compress(raw)
    return base64.b64encode(compressed).decode("utf-8")


async def main():
    print("🔧 LINUXDOT Secret 生成工具")
    print("=" * 60)

    # 输入账号（必须和 ACCOUNTS 里 linux.do.username 完全一致，通常是邮箱）
    while True:
        try:
            count = int(input("\n📋 你有几个 linux.do 账号？ ").strip())
            if count > 0:
                break
            print("  请输入大于 0 的数字")
        except ValueError:
            print("  请输入数字")

    usernames = []
    for i in range(1, count + 1):
        u = input(f"  输入第 {i} 个账号的 linux.do 登录名（和 ACCOUNTS 里 linux.do.username 一致，通常是邮箱）: ").strip()
        if u:
            usernames.append(u)

    if not usernames:
        print("\n❌ 没有输入任何用户名")
        return

    print(f"\n📋 将依次登录 {len(usernames)} 个账号:")
    for i, u in enumerate(usernames, 1):
        h = hashlib.sha256(u.encode("utf-8")).hexdigest()[:8]
        print(f"  {i}. {u} (hash: {h})")

    results = []
    for i, username in enumerate(usernames, 1):
        result = await login_account(username, i, len(usernames))
        if result:
            results.append(result)
            print(f"  ✅ 账号 {username} 完成!")

    if not results:
        print("\n❌ 没有成功登录任何账号")
        return

    # 生成压缩后的 secret 值
    secret_value = generate_secret(results)

    print(f"\n{'='*60}")
    print(f"✅ 所有账号登录完成! ({len(results)}/{len(usernames)})")
    print(f"{'='*60}")
    print(f"\n📊 统计:")
    for r in results:
        nc = len(r['state'].get('cookies', []))
        no = len(r['state'].get('origins', []))
        print(f"  {r['username']}: {nc} cookies, {no} origins")
    print(f"\n📦 压缩后大小: {len(secret_value)} 字符 (限制 48,000)")

    # 保存到文件
    out_file = "linuxdot_secret.txt"
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(secret_value)
    print(f"💾 已保存到: {out_file}")

    # 复制到剪贴板
    try:
        import subprocess
        subprocess.run(
            ["powershell", "-Command", f"Get-Content {out_file} | Set-Clipboard"],
            check=True, capture_output=True,
        )
        print(f"📋 已自动复制到剪贴板!")
    except Exception:
        print(f"📋 请手动复制 {out_file} 的内容")

    print(f"\n🚀 下一步: GitHub → Settings → Secrets → 新建/更新 LINUXDOT → 粘贴")


if __name__ == "__main__":
    asyncio.run(main())
