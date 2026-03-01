"""Restore linux.do storage states from LINUXDOT env var (gzip+base64)."""

import base64
import gzip
import json
import os


def restore_linuxdot():
    """Decode LINUXDOT env var and write storage-state files if not exist."""
    raw = os.getenv("LINUXDOT", "").strip()
    if not raw:
        return
    try:
        decoded = json.loads(gzip.decompress(base64.b64decode(raw)).decode("utf-8"))
        os.makedirs("storage-states", exist_ok=True)
        for fname, state in decoded.items():
            fpath = os.path.join("storage-states", os.path.basename(fname))
            if not os.path.exists(fpath):
                with open(fpath, "w", encoding="utf-8") as f:
                    json.dump(state, f, ensure_ascii=False)
                nc = len(state.get("cookies", []))
                print(f"ℹ️ Restored: {fpath} ({nc} cookies)")
    except Exception as e:
        print(f"⚠️ LINUXDOT decode failed: {e}")
