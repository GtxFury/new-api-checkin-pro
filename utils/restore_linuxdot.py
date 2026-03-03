"""Restore linux.do storage states from LINUXDOT env var (gzip+base64)."""

import base64
import gzip
import json
import os
import time


def _is_truthy(value: str) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _cookie_expires_at(state: dict, cookie_name: str) -> float | None:
    cookies = state.get("cookies", [])
    if not isinstance(cookies, list):
        return None
    for c in cookies:
        if not isinstance(c, dict):
            continue
        if c.get("name") != cookie_name:
            continue
        exp = c.get("expires")
        try:
            exp_num = float(exp)
        except Exception:
            return None
        if exp_num <= 0:
            return None
        return exp_num
    return None


def _should_restore_file(fpath: str, force_overwrite: bool) -> tuple[bool, str]:
    """返回 (是否写入, 原因)。"""
    if not os.path.exists(fpath):
        return True, "missing"
    if force_overwrite:
        return True, "force_overwrite"

    base = os.path.basename(fpath)
    # 仅对 linuxdo storage-state 做“过期自动覆盖”判断；其他文件保持“存在即不覆盖”。
    if not (base.startswith("linuxdo_") and base.endswith("_storage_state.json")):
        return False, "exists_keep"

    try:
        with open(fpath, "r", encoding="utf-8") as f:
            existing = json.load(f)
        if not isinstance(existing, dict):
            return True, "invalid_json"

        now = time.time()
        # linux.do 登录态核心 cookie，若缺失或即将过期，则优先用 LINUXDOT 刷新
        t_exp = _cookie_expires_at(existing, "_t")
        if t_exp is None or t_exp <= now + 6 * 3600:
            return True, "linuxdo_t_expired_or_missing"

        # CF 清除票据过期很快，过期后常导致页面卡挑战；提前刷新
        cf_exp = _cookie_expires_at(existing, "cf_clearance")
        if cf_exp is not None and cf_exp <= now + 30 * 60:
            return True, "cf_clearance_expiring"
    except Exception:
        return True, "read_error"

    return False, "exists_fresh"


def restore_linuxdot():
    """Decode LINUXDOT env var and write storage-state files."""
    raw = os.getenv("LINUXDOT", "").strip()
    if not raw:
        return
    try:
        force_overwrite = _is_truthy(os.getenv("LINUXDOT_OVERWRITE", ""))
        decoded = json.loads(gzip.decompress(base64.b64decode(raw)).decode("utf-8"))
        os.makedirs("storage-states", exist_ok=True)
        for fname, state in decoded.items():
            fpath = os.path.join("storage-states", os.path.basename(fname))
            existed_before = os.path.exists(fpath)
            should_restore, reason = _should_restore_file(fpath, force_overwrite)
            if should_restore:
                with open(fpath, "w", encoding="utf-8") as f:
                    json.dump(state, f, ensure_ascii=False)
                nc = len(state.get("cookies", []))
                action = "Overwrote" if existed_before else "Restored"
                print(f"ℹ️ {action}: {fpath} ({nc} cookies, reason={reason})")
            elif reason != "exists_keep":
                print(f"ℹ️ Skip restore: {fpath} (reason={reason})")
    except Exception as e:
        print(f"⚠️ LINUXDOT decode failed: {e}")
