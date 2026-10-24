"""
Windows Startup & System Tray Integration (`startup_and_tray.py`).
- Manages user-level Windows startup entry (`HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`)
  without requiring Administrator privileges, strictly controlled by user opt-in.
- Provides system tray icon integration via PySide6 `QSystemTrayIcon` when running on Windows desktop.
"""
import os
import sys
from pathlib import Path
from typing import Optional

from .storage import LocalStorage

RUN_REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
APP_REG_KEY = "LinkBridge"


class WindowsStartupManager:
    """Manages optional Windows login auto-start under HKCU (no Administrator rights required)."""

    @staticmethod
    def get_launch_command(app_entry_path: Optional[Path] = None) -> str:
        if getattr(sys, "frozen", False):
            return f'"{sys.executable}" --minimized'
        entry = app_entry_path or (Path(__file__).resolve().parent / "app.py")
        return f'"{sys.executable}" "{entry}" --minimized'

    @classmethod
    def is_startup_enabled(cls, storage: Optional[LocalStorage] = None) -> bool:
        if sys.platform == "win32":
            try:
                import winreg

                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_REG_PATH, 0, winreg.KEY_READ) as key:
                    val, _ = winreg.QueryValueEx(key, APP_REG_KEY)
                    return bool(val)
            except OSError:
                return False
        if storage is not None:
            return bool(storage.get_setting("run_on_windows_startup", False))
        return False

    @classmethod
    def set_startup_enabled(
        cls,
        enabled: bool,
        storage: Optional[LocalStorage] = None,
        app_entry_path: Optional[Path] = None,
    ) -> bool:
        if storage is not None:
            storage.set_setting("run_on_windows_startup", enabled)

        if sys.platform != "win32":
            return True

        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                RUN_REG_PATH,
                0,
                winreg.KEY_SET_VALUE,
            ) as key:
                if enabled:
                    cmd = cls.get_launch_command(app_entry_path)
                    winreg.SetValueEx(key, APP_REG_KEY, 0, winreg.REG_SZ, cmd)
                else:
                    try:
                        winreg.DeleteValue(key, APP_REG_KEY)
                    except FileNotFoundError:
                        pass
            return True
        except OSError:
            return False
