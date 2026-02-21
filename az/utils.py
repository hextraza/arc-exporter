import json
import re
from pathlib import Path

def log(msg, lvl="*"):
    print(f"[{lvl}] {msg}")

def ensure(p: Path):
    p.mkdir(parents=True, exist_ok=True)
    return p

def safe_dir_name(name: str) -> str:
    s = name.strip() if isinstance(name, str) else "profile"
    s = re.sub(r"[\\/:*?\"<>|]+", "-", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s or "profile"

def read_json(path: Path):
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


