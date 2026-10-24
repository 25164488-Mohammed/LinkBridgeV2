"""
Bilingual Localization & Theme Palettes for LinkBridge Windows (`i18n.py`).
Supports Arabic (RTL) and English (LTR), plus Dark and Light themes.
Includes the required attribution «عمل محمد البكير» in the About section.
"""
from typing import Dict

STRINGS: Dict[str, Dict[str, str]] = {
    "ar": {
        "app_title": "LinkBridge — جسر محلي آمن بين Android وWindows",
        "status_connected": "متصل بـ: {peer} ({transport})",
        "status_disconnected": "غير متصل — في انتظار الربط المحلي",
        "status_listening": "الخدمة المحلية تستمع على {ip}:{port}",
        "route_wifi_lan": "شبكة Wi-Fi المحلية (مفضّل للملفات الكبيرة)",
        "route_wifi_hotspot": "نقطة اتصال الهاتف (Hotspot دون إنترنت)",
        "route_bluetooth": "بلوتوث كلاسيكي (Bluetooth RFCOMM)",
        "tab_dashboard": "الاتصال والإرسال السريع",
        "tab_clipboard": "سجل الحافظة والمزامنة",
        "tab_files": "نقل الملفات والمجلدات",
        "tab_settings": "الإعدادات والخصوصية",
        "tab_about": "حول التطبيق",
        "btn_start_listener": "تشغيل الاستماع المحلي",
        "btn_stop_listener": "إيقاف الاستماع",
        "btn_generate_pin": "توليد رمز اقتران جديد (PIN / QR)",
        "btn_connect_peer": "اتصال بالجهاز المقابل",
        "btn_disconnect": "قطع الاتصال",
        "btn_send_text": "إرسال النص الآن",
        "btn_send_clipboard": "إرسال محتوى الحافظة الحالي",
        "btn_send_files": "إرسال ملفات...",
        "btn_send_folder": "إرسال مجلد...",
        "btn_cancel_transfer": "إلغاء النقل وحذف المؤقت",
        "btn_copy": "نسخ",
        "btn_resend": "إعادة إرسال",
        "btn_delete": "حذف",
        "btn_clear_history": "مسح السجل بالكامل",
        "btn_clean_temp": "تنظيف الملفات المؤقتة (.lbpart)",
        "btn_renew_cert": "تجديد شهادة الأمان ومفاتيح الجهاز",
        "btn_revoke_peer": "إبطال الثقة بالجهاز المقترن",
        "lbl_paired_device": "الجهاز المقترن:",
        "lbl_fingerprint": "بصمة الشهادة (SHA-256):",
        "lbl_search_clip": "بحث في سجل الحافظة...",
        "lbl_receive_dir": "مجلد الاستقبال على Windows:",
        "chk_monitor_clip": "تفعيل مراقبة الحافظة على Windows",
        "chk_auto_win_to_and": "مزامنة تلقائية من Windows إلى Android",
        "chk_auto_and_to_win": "مزامنة تلقائية من Android إلى Windows",
        "chk_auto_copy_recv": "نسخ النص المستلم إلى الحافظة المحلية تلقائيًا",
        "chk_auto_accept_files": "قبول الملفات الواردة تلقائيًا دون سؤال لكل ملف",
        "chk_hide_notif": "إخفاء محتوى النصوص داخل الإشعارات لحماية الخصوصية",
        "chk_save_history": "حفظ سجل الحافظة محليًا في قاعدة بيانات SQLite",
        "chk_run_startup": "تشغيل LinkBridge تلقائيًا مع بدء Windows (بموافقة المستخدم ودون صلاحيات مسؤول)",
        "about_heading": "LinkBridge v1.0 — جسر محلي آمن لنقل النصوص والملفات",
        "about_credit": "عمل محمد البكير",
        "about_description": (
            "نظام متكامل لنقل النصوص ومحتويات الحافظة والملفات بين هاتف Android 9+ ولابتوب Windows 10/11 "
            "عبر الشبكة المحلية Wi-Fi أو نقطة اتصال الهاتف أو Bluetooth RFCOMM، بتشفير ومصادقة كاملة "
            "ودون أي اعتماد على الإنترنت أو الخدمات السحابية."
        ),
    },
    "en": {
        "app_title": "LinkBridge — Secure Local Bridge for Android & Windows",
        "status_connected": "Connected to: {peer} ({transport})",
        "status_disconnected": "Disconnected — Waiting for local link",
        "status_listening": "Local service listening on {ip}:{port}",
        "route_wifi_lan": "Local Wi-Fi LAN (Preferred for large files)",
        "route_wifi_hotspot": "Phone Wi-Fi Hotspot (Offline)",
        "route_bluetooth": "Bluetooth Classic (RFCOMM)",
        "tab_dashboard": "Connection & Quick Send",
        "tab_clipboard": "Clipboard History & Sync",
        "tab_files": "File & Folder Transfers",
        "tab_settings": "Settings & Privacy",
        "tab_about": "About",
        "btn_start_listener": "Start Local Listener",
        "btn_stop_listener": "Stop Listener",
        "btn_generate_pin": "Generate Pairing Token (PIN / QR)",
        "btn_connect_peer": "Connect to Peer",
        "btn_disconnect": "Disconnect",
        "btn_send_text": "Send Text Now",
        "btn_send_clipboard": "Send Current Clipboard",
        "btn_send_files": "Send Files...",
        "btn_send_folder": "Send Folder...",
        "btn_cancel_transfer": "Cancel Transfer & Clean Temp",
        "btn_copy": "Copy",
        "btn_resend": "Resend",
        "btn_delete": "Delete",
        "btn_clear_history": "Clear All History",
        "btn_clean_temp": "Clean Temporary Files (.lbpart)",
        "btn_renew_cert": "Renew Device Security Certificate",
        "btn_revoke_peer": "Revoke Paired Device Trust",
        "lbl_paired_device": "Paired Device:",
        "lbl_fingerprint": "Certificate Fingerprint (SHA-256):",
        "lbl_search_clip": "Search clipboard history...",
        "lbl_receive_dir": "Windows Receive Folder:",
        "chk_monitor_clip": "Enable Windows Clipboard Monitoring",
        "chk_auto_win_to_and": "Auto-Sync from Windows to Android",
        "chk_auto_and_to_win": "Auto-Sync from Android to Windows",
        "chk_auto_copy_recv": "Automatically copy received text to local clipboard",
        "chk_auto_accept_files": "Auto-accept incoming files without prompting per file",
        "chk_hide_notif": "Hide text content in notifications for privacy",
        "chk_save_history": "Save clipboard history locally in SQLite",
        "chk_run_startup": "Run LinkBridge on Windows startup (User opt-in, no Admin required)",
        "about_heading": "LinkBridge v1.0 — Secure Local Text & File Bridge",
        "about_credit": "عمل محمد البكير",
        "about_description": (
            "Integrated local bridge for transferring clipboard text and files between Android 9+ and Windows 10/11 "
            "over Local Wi-Fi, Phone Hotspot, or Bluetooth RFCOMM with end-to-end authentication and zero cloud dependencies."
        ),
    },
}


def get_stylesheet(theme: str = "dark") -> str:
    if theme == "light":
        return """
        QMainWindow, QWidget {
            background-color: #F8FAFC;
            color: #0F172A;
            font-family: "Segoe UI", "Noto Sans Arabic", Tahoma, sans-serif;
            font-size: 13px;
        }
        QTabWidget::pane {
            border: 1px solid #CBD5E1;
            border-radius: 8px;
            background: #FFFFFF;
        }
        QTabBar::tab {
            background: #E2E8F0;
            color: #334155;
            padding: 9px 18px;
            border-top-left-radius: 6px;
            border-top-right-radius: 6px;
            margin-right: 4px;
            font-weight: 600;
        }
        QTabBar::tab:selected {
            background: #0284C7;
            color: #FFFFFF;
        }
        QPushButton {
            background-color: #0284C7;
            color: #FFFFFF;
            border: none;
            border-radius: 6px;
            padding: 8px 14px;
            font-weight: 600;
        }
        QPushButton:hover {
            background-color: #0369A1;
        }
        QPushButton#dangerBtn {
            background-color: #DC2626;
        }
        QLineEdit, QTextEdit, QComboBox, QSpinBox, QListWidget, QTableWidget {
            background-color: #FFFFFF;
            color: #0F172A;
            border: 1px solid #CBD5E1;
            border-radius: 6px;
            padding: 6px;
        }
        QProgressBar {
            border: 1px solid #CBD5E1;
            border-radius: 6px;
            text-align: center;
            background: #E2E8F0;
        }
        QProgressBar::chunk {
            background-color: #0284C7;
            border-radius: 5px;
        }
        """
    return """
    QMainWindow, QWidget {
        background-color: #0F172A;
        color: #F1F5F9;
        font-family: "Segoe UI", "Noto Sans Arabic", Tahoma, sans-serif;
        font-size: 13px;
    }
    QTabWidget::pane {
        border: 1px solid #334155;
        border-radius: 8px;
        background: #1E293B;
    }
    QTabBar::tab {
        background: #1E293B;
        color: #94A3B8;
        padding: 9px 18px;
        border-top-left-radius: 6px;
        border-top-right-radius: 6px;
        margin-right: 4px;
        font-weight: 600;
    }
    QTabBar::tab:selected {
        background: #0EA5E9;
        color: #0F172A;
    }
    QPushButton {
        background-color: #0EA5E9;
        color: #0F172A;
        border: none;
        border-radius: 6px;
        padding: 8px 14px;
        font-weight: 600;
    }
    QPushButton:hover {
        background-color: #38BDF8;
    }
    QPushButton#dangerBtn {
        background-color: #EF4444;
        color: #FFFFFF;
    }
    QLineEdit, QTextEdit, QComboBox, QSpinBox, QListWidget, QTableWidget {
        background-color: #0F172A;
        color: #F1F5F9;
        border: 1px solid #334155;
        border-radius: 6px;
        padding: 6px;
    }
    QProgressBar {
        border: 1px solid #334155;
        border-radius: 6px;
        text-align: center;
        background: #0F172A;
        color: #F1F5F9;
    }
    QProgressBar::chunk {
        background-color: #10B981;
        border-radius: 5px;
    }
    """
