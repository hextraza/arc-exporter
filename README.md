## Arc Exporter (Windows)

Export Arc Browser passwords from Arc for Windows into a CSV file.

Derived from [arc-exporter](https://github.com/mhadifilms/arc-exporter) by [mhadifilms](https://github.com/mhadifilms). It only exports passwords, not your entire profile.

### Features
- Exports per‑profile passwords to `arc-export/profiles/<ArcProfileName>/passwords_<ts>.csv`
- Windows DPAPI + Chromium AES‑GCM decryption

### Requirements
- Windows 11
- Python 3.9+
- Arc for Windows installed
- `cryptography` package (`pip install cryptography`)

### Quick start
1) Fully quit Arc.
2) Run:
```bash
python main.py
```

### Custom Arc profile root (optional)
If your Arc user data lives somewhere else, pass a custom path:
```bash
python main.py --profiles-root "C:\\Users\\<you>\\AppData\\Local\\Packages\\TheBrowserCompany.Arc_ttt1ap7aakyb4\\LocalCache\\Local\\Arc\\User Data"
```

### Outputs
- `arc-export/profiles/<ArcProfileName>/passwords_<ts>.csv`
  - Columns: `url`, `username`, `password`