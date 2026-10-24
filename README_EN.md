# LinkBridge — Secure Local Clipboard & File Bridge for Android 9+ and Windows

**Created by Mohammed Al-Bukair (عمل محمد البكير)**

LinkBridge is a complete, offline-first system consisting of a native **Android 9+ (API 28+) Kotlin application** and a **Windows 10/11 desktop application (Python + PySide6 + SQLite)**. It enables fast, authenticated, end-to-end encrypted clipboard synchronization and chunked file/folder transfers over **Local Wi-Fi LAN**, **Phone Wi-Fi Hotspot**, or **Bluetooth Classic (RFCOMM)** without cloud servers, accounts, or internet access.

---

## Key Features

1. **Three Unified Transport Routes (`TransportAdapter`)**:
   - **Local Wi-Fi LAN**: Preferred high-speed route for large files (64 KiB chunks over TLS 1.3/1.2).
   - **Phone Wi-Fi Hotspot**: Direct offline transfer when the laptop connects to the phone's hotspot.
   - **Bluetooth Classic (RFCOMM)**: Offline fallback route using 16 KiB chunks and application-layer forward-secret **ECDH P-256 + HKDF-SHA256 + AES-256-GCM** encryption.
2. **Zero-Trust Local Security**:
   - Unique per-device ECDSA P-256 X.509 certificates generated on first run (zero hardcoded shared keys).
   - 6-digit PIN / QR pairing challenge (5-minute TTL) with HMAC-SHA256 proof of possession and SHA-256 certificate fingerprint pinning.
   - Short-lived session tokens (`SESSION_TTL_SECONDS = 3600`) with instant device revocation and certificate renewal.
3. **Bidirectional Smart Clipboard Bridge**:
   - Per-direction auto-sync toggles alongside explicit manual send buttons.
   - Content SHA-256 hashing and origin device tracking to prevent infinite sync loops and duplicate sends.
   - Optional exclusion list for sensitive Windows password managers (`KeePass.exe`, `1Password.exe`, `Bitwarden.exe`).
4. **Resumable Streaming File Transfer**:
   - Streams arbitrary files and folders in chunks without loading entire files into RAM.
   - Saves in-progress transfers as `.lbpart` checkpoints, supporting automatic byte-offset resume after connection drops.
   - Verifies full-file SHA-256 and exact byte size before atomically moving into the destination folder.
   - Protects against path traversal (`..`, drive letters, absolute paths) and resolves filename collisions safely (`file (1).ext`).

---

## Running Tests & Verification

```bash
bash scripts/run_tests.sh
```

See `docs/TEST_REPORT.md`, `docs/PROTOCOL.md`, `docs/SECURITY_AND_PERMISSIONS.md`, and `docs/TROUBLESHOOTING.md` for full architectural details and actual execution reports.
