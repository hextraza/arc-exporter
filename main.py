import argparse
import base64
import csv
import datetime as dt
import os
import shutil
import sqlite3
from pathlib import Path

from az.utils import ensure, log, read_json, safe_dir_name

NOW = dt.datetime.now().strftime("%Y%m%d-%H%M%S")

BASE_DIR = Path(__file__).resolve().parent
OUT_ROOT = BASE_DIR / "arc-export" / "profiles"


def arc_user_data_root() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise RuntimeError("LOCALAPPDATA not set; cannot locate Arc user data")
    return Path(local_app_data) / "Packages" / "TheBrowserCompany.Arc_ttt1ap7aakyb4" / "LocalCache" / "Local" / "Arc" / "User Data"


def arc_local_state_path() -> Path:
    return arc_user_data_root() / "Local State"


def arc_profiles() -> list[Path]:
    user_data = arc_user_data_root()
    if not user_data.exists():
        raise RuntimeError(f"Arc user data not found at: {user_data}")
    profiles = []
    for entry in sorted(user_data.iterdir()):
        if entry.is_dir() and (entry / "Login Data").exists():
            profiles.append(entry)
    if not profiles:
        raise RuntimeError("No Arc profiles with Login Data found.")
    return profiles


def arc_display_names() -> dict[str, str]:
    ls = read_json(arc_local_state_path())
    info_cache = (ls.get("profile") or {}).get("info_cache") or {}
    out: dict[str, str] = {}
    for key, meta in info_cache.items():
        name = meta.get("name") if isinstance(meta, dict) else None
        out[key] = name or key
    return out


def dpapi_decrypt(ciphertext: bytes) -> bytes:
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

    def _blob_from_bytes(data: bytes) -> DATA_BLOB:
        blob = DATA_BLOB()
        blob.cbData = len(data)
        blob.pbData = ctypes.cast(ctypes.create_string_buffer(data, len(data)), ctypes.POINTER(ctypes.c_byte))
        return blob

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    in_blob = _blob_from_bytes(ciphertext)
    out_blob = DATA_BLOB()

    if not crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        return ctypes.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        kernel32.LocalFree(out_blob.pbData)


def get_master_key(local_state_path: Path) -> bytes:
    data = read_json(local_state_path)
    encrypted_key_b64 = (data.get("os_crypt") or {}).get("encrypted_key")
    if not encrypted_key_b64:
        raise RuntimeError("No encrypted_key found in Local State")
    encrypted_key = base64.b64decode(encrypted_key_b64)
    if encrypted_key.startswith(b"DPAPI"):
        encrypted_key = encrypted_key[5:]
    return dpapi_decrypt(encrypted_key)


def decrypt_password_value(encrypted_value: bytes, master_key: bytes) -> str:
    if not encrypted_value:
        return ""
    if encrypted_value.startswith(b"v10"):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except Exception as exc:
            raise RuntimeError("cryptography package required for AES-GCM decryption. Install with: pip install cryptography") from exc
        nonce = encrypted_value[3:15]
        ciphertext = encrypted_value[15:]
        aesgcm = AESGCM(master_key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8", errors="ignore")
        except Exception:
            return ""
    try:
        return dpapi_decrypt(encrypted_value).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def export_passwords_csv(profile_dir: Path, out_csv: Path, master_key: bytes) -> bool:
    db = profile_dir / "Login Data"
    if not db.exists():
        log(f"No Login Data in {profile_dir.name}; skipping passwords.", "!")
        return False
    ensure(out_csv.parent)
    tmp_db = out_csv.parent / f"{profile_dir.name}-LoginData.sqlite"
    shutil.copy2(db, tmp_db)

    conn = sqlite3.connect(str(tmp_db))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    try:
        cur.execute("SELECT origin_url, username_value, password_value FROM logins")
        rows = cur.fetchall()
    finally:
        conn.close()
        try:
            tmp_db.unlink()
        except Exception:
            pass

    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "username", "password"])
        for row in rows:
            url = row["origin_url"] or ""
            user = row["username_value"] or ""
            encrypted_value = row["password_value"]
            if isinstance(encrypted_value, memoryview):
                encrypted_value = encrypted_value.tobytes()
            if not isinstance(encrypted_value, (bytes, bytearray)):
                encrypted_value = b""
            pwd = decrypt_password_value(encrypted_value, master_key)
            w.writerow([url, user, pwd])

    log(f"Passwords CSV → {out_csv}", "OK")
    return True


def parse_args(argv = None):
    p = argparse.ArgumentParser(description="Export Arc passwords on Windows.")
    p.add_argument("--profiles-root", help="Override Arc user data root")
    return p.parse_args(argv)


def main():
    args = parse_args()
    if args.profiles_root:
        root = Path(args.profiles_root)
        if not root.exists():
            raise RuntimeError(f"Provided profiles root does not exist: {root}")
        global arc_user_data_root
        arc_user_data_root = lambda: root

    profiles = arc_profiles()
    display_names = arc_display_names()
    master_key = get_master_key(arc_local_state_path())

    for profile in profiles:
        display = display_names.get(profile.name, profile.name)
        out_dir = OUT_ROOT / safe_dir_name(display)
        out_csv = out_dir / f"passwords_{NOW}.csv"
        export_passwords_csv(profile, out_csv, master_key)

    log("All done.", "OK")


if __name__ == "__main__":
    main()