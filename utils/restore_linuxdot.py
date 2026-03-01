"""Restore linux.do storage states from LINUXDOT env var (gzip+base64)."""

import base64
import gzip
import json
import os
import shutil

# All provider subdirectories that use storage-states/
PROVIDER_SUBDIRS = [
    "", "taizi", "neb", "mu", "kfc", "hybgzs", "huan",
    "hotaru", "gemai", "freestyle", "daiju", "anthorpic", "x666",
]


def restore_linuxdot():
    """Decode LINUXDOT env var and write storage-state files to all provider dirs."""
    raw = os.getenv("LINUXDOT", "").strip()
    if not raw:
        return
    try:
        decoded = json.loads(gzip.decompress(base64.b64decode(raw)).decode("utf-8"))
        for subdir in PROVIDER_SUBDIRS:
            target_dir = os.path.join("storage-states", subdir) if subdir else "storage-states"
            os.makedirs(target_dir, exist_ok=True)
            for fname, state in decoded.items():
                fpath = os.path.join(target_dir, os.path.basename(fname))
                if not os.path.exists(fpath):
                    with open(fpath, "w", encoding="utf-8") as f:
                        json.dump(state, f, ensure_ascii=False)
        # Print summary (only once)
        for fname, state in decoded.items():
            nc = len(state.get("cookies", []))
            print(f"ℹ️ Restored: {fname} ({nc} cookies) → {len(PROVIDER_SUBDIRS)} dirs")
    except Exception as e:
        print(f"⚠️ LINUXDOT decode failed: {e}")
