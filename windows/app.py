"""
LinkBridge Windows Desktop Application (`app.py`).
Supports:
- Native PySide6 Desktop UI with Arabic RTL & English LTR support, Dark & Light themes, System Tray icon,
  Connection wizard (Wi-Fi LAN, Phone Hotspot, Bluetooth RFCOMM), QR/PIN pairing generator,
  Clipboard Bridge with history/search/copy/resend/delete, File & Folder transfer table with progress & speed,
  Privacy & Security settings, and About dialog containing «عمل محمد البكير».
- Headless CLI & Self-Verification mode (`--self-check`) when invoked from terminal or automated scripts.
"""
import argparse
import json
import os
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

# Ensure project root is on sys.path so `protocol` and `windows` resolve cleanly
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from protocol.constants import DEFAULT_WIFI_PORT, TransportType
from protocol.transport import (
    BluetoothRfcommTransport,
    LocalDiscoveryService,
    RouteSelector,
    WifiTlsTransport,
)
from windows.bridge_node import LinkBridgeNode
from windows.i18n import STRINGS, get_stylesheet
from windows.startup_and_tray import WindowsStartupManager


def get_default_appdata_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
        return base / "LinkBridge"
    return Path.home() / ".local" / "share" / "LinkBridge"


def run_self_check(data_dir: Path) -> int:
    """Run a quick diagnostic check of identity, SQLite storage, discovery, and Bluetooth RFCOMM capabilities."""
    node = LinkBridgeNode(data_dir=data_dir, device_name="LinkBridge-Windows-Check")
    pin, secret_hex, exp = node.generate_pairing_code()
    ips = LocalDiscoveryService.get_local_private_ips()
    bt_caps = BluetoothRfcommTransport.check_system_capabilities()
    qr_payload = LocalDiscoveryService.build_qr_pairing_payload(
        node.identity,
        ip=ips[0]["ip"],
        port=DEFAULT_WIFI_PORT,
        pairing_secret_hex=secret_hex,
        pin_code=pin,
        expires_at=exp,
    )
    summary = {
        "device_id": node.identity.device_id,
        "fingerprint_sha256": node.identity.fingerprint_sha256,
        "local_ips": ips,
        "bluetooth_capabilities": bt_caps,
        "sample_qr_pairing_payload": json.loads(qr_payload),
        "about_credit": STRINGS["ar"]["about_credit"],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    node.shutdown()
    return 0


def launch_pyside6_gui(data_dir: Path, start_minimized: bool = False) -> int:
    try:
        from PySide6.QtCore import Qt, QTimer, Signal, QObject
        from PySide6.QtGui import QAction, QGuiApplication, QIcon, QPixmap, QColor
        from PySide6.QtWidgets import (
            QApplication,
            QCheckBox,
            QComboBox,
            QFileDialog,
            QFormLayout,
            QGroupBox,
            QHBoxLayout,
            QHeaderView,
            QLabel,
            QLineEdit,
            QMainWindow,
            QMenu,
            QMessageBox,
            QProgressBar,
            QPushButton,
            QSpinBox,
            QSystemTrayIcon,
            QTabWidget,
            QTableWidget,
            QTableWidgetItem,
            QTextEdit,
            QVBoxLayout,
            QWidget,
        )
    except ImportError as e:
        print(
            "PySide6 غير مثبت في بيئة Python الحالية. لتشغيل الواجهة الرسومية على Windows، ثبّت المتطلبات عبر:\n"
            "  pip install -r windows/requirements.txt\n"
            f"تفاصيل الخطأ: {e}",
            file=sys.stderr,
        )
        return 1

    class UiBridgeSignals(QObject):
        event_signal = Signal(str, dict)

    class LinkBridgeMainWindow(QMainWindow):
        def __init__(self) -> None:
            super().__init__()
            self.signals = UiBridgeSignals()
            self.signals.event_signal.connect(self._on_node_event)

            self.node = LinkBridgeNode(
                data_dir=data_dir,
                device_name="LinkBridge-Windows-PC",
                on_event_callback=lambda et, d: self.signals.event_signal.emit(et, d),
                approval_prompt_callback=self._prompt_file_approval,
            )
            self.node.clipboard_backend.set_qt_clipboard(QGuiApplication.clipboard())

            self.lang = self.node.storage.get_setting("language", "ar")
            self.theme = self.node.storage.get_setting("theme", "dark")

            self._build_ui()
            self._apply_language_and_theme()
            self._setup_tray_icon()

            # Periodic timer for Windows clipboard monitoring (every 800ms when enabled)
            self._clip_timer = QTimer(self)
            self._clip_timer.timeout.connect(self._poll_clipboard)
            self._clip_timer.start(800)

        def tr_key(self, key: str) -> str:
            return STRINGS.get(self.lang, STRINGS["ar"]).get(key, key)

        def _build_ui(self) -> None:
            self.setMinimumSize(980, 680)
            central = QWidget()
            self.setCentralWidget(central)
            main_layout = QVBoxLayout(central)

            # Top Connection Status Header Bar
            header_box = QHBoxLayout()
            self.lbl_conn_status = QLabel()
            self.lbl_conn_status.setStyleSheet("font-size: 15px; font-weight: bold;")
            self.lbl_local_addr = QLabel()
            self.combo_route = QComboBox()
            self.combo_route.addItem("Wi-Fi LAN", TransportType.WIFI_LAN.value)
            self.combo_route.addItem("Phone Hotspot", TransportType.WIFI_HOTSPOT.value)
            self.combo_route.addItem("Bluetooth RFCOMM", TransportType.BLUETOOTH_RFCOMM.value)
            header_box.addWidget(self.lbl_conn_status, stretch=2)
            header_box.addWidget(self.lbl_local_addr, stretch=2)
            header_box.addWidget(self.combo_route, stretch=1)
            main_layout.addLayout(header_box)

            # Tabs
            self.tabs = QTabWidget()
            main_layout.addWidget(self.tabs)

            # 1. Dashboard & Quick Send Tab
            self.tab_dash = QWidget()
            dash_layout = QVBoxLayout(self.tab_dash)

            conn_group = QGroupBox()
            conn_form = QHBoxLayout(conn_group)
            self.input_peer_addr = QLineEdit()
            self.input_peer_addr.setPlaceholderText("IP:Port (192.168.1.15:48520) / BT MAC (AA:BB:CC:DD:EE:FF)")
            self.input_pin = QLineEdit()
            self.input_pin.setPlaceholderText("PIN (6 digits)")
            self.btn_listen = QPushButton()
            self.btn_listen.clicked.connect(self._toggle_listener)
            self.btn_gen_pin = QPushButton()
            self.btn_gen_pin.clicked.connect(self._on_generate_pin)
            self.btn_connect = QPushButton()
            self.btn_connect.clicked.connect(self._on_connect_clicked)
            conn_form.addWidget(self.btn_listen)
            conn_form.addWidget(self.btn_gen_pin)
            conn_form.addWidget(self.input_peer_addr, stretch=2)
            conn_form.addWidget(self.input_pin, stretch=1)
            conn_form.addWidget(self.btn_connect)
            dash_layout.addWidget(conn_group)

            self.lbl_pairing_info = QLabel()
            self.lbl_pairing_info.setWordWrap(True)
            dash_layout.addWidget(self.lbl_pairing_info)

            # Quick Text Send Box
            self.txt_quick_send = QTextEdit()
            self.txt_quick_send.setPlaceholderText("اكتب أو الصق نصًا لإرساله فورًا إلى الهاتف...")
            dash_layout.addWidget(self.txt_quick_send)

            quick_btns = QHBoxLayout()
            self.btn_send_text = QPushButton()
            self.btn_send_text.clicked.connect(self._on_send_custom_text)
            self.btn_send_clip = QPushButton()
            self.btn_send_clip.clicked.connect(self._on_send_current_clipboard)
            self.btn_quick_files = QPushButton()
            self.btn_quick_files.clicked.connect(self._on_pick_and_send_files)
            quick_btns.addWidget(self.btn_send_text)
            quick_btns.addWidget(self.btn_send_clip)
            quick_btns.addWidget(self.btn_quick_files)
            dash_layout.addLayout(quick_btns)

            self.tabs.addTab(self.tab_dash, "")

            # 2. Clipboard History Tab
            self.tab_clip = QWidget()
            clip_layout = QVBoxLayout(self.tab_clip)
            clip_top = QHBoxLayout()
            self.input_clip_search = QLineEdit()
            self.input_clip_search.textChanged.connect(self._refresh_clipboard_table)
            self.btn_clear_clip = QPushButton()
            self.btn_clear_clip.setObjectName("dangerBtn")
            self.btn_clear_clip.clicked.connect(self._on_clear_clipboard_history)
            clip_top.addWidget(self.input_clip_search, stretch=3)
            clip_top.addWidget(self.btn_clear_clip)
            clip_layout.addLayout(clip_top)

            self.tbl_clip = QTableWidget(0, 5)
            self.tbl_clip.setHorizontalHeaderLabels(["ID", "Direction", "Transport", "Text Preview", "Hash"])
            self.tbl_clip.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
            clip_layout.addWidget(self.tbl_clip)
            self.tabs.addTab(self.tab_clip, "")

            # 3. File Transfers Tab
            self.tab_files = QWidget()
            files_layout = QVBoxLayout(self.tab_files)
            files_btns = QHBoxLayout()
            self.btn_send_files_tab = QPushButton()
            self.btn_send_files_tab.clicked.connect(self._on_pick_and_send_files)
            self.btn_send_folder_tab = QPushButton()
            self.btn_send_folder_tab.clicked.connect(self._on_pick_and_send_folder)
            self.btn_clean_temp = QPushButton()
            self.btn_clean_temp.clicked.connect(self._on_clean_temp_files)
            files_btns.addWidget(self.btn_send_files_tab)
            files_btns.addWidget(self.btn_send_folder_tab)
            files_btns.addWidget(self.btn_clean_temp)
            files_layout.addLayout(files_btns)

            self.progress_bar = QProgressBar()
            self.progress_bar.setValue(0)
            files_layout.addWidget(self.progress_bar)

            self.tbl_files = QTableWidget(0, 6)
            self.tbl_files.setHorizontalHeaderLabels(
                ["ID", "File Name", "Direction", "Progress", "Status", "SHA-256"]
            )
            self.tbl_files.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            files_layout.addWidget(self.tbl_files)
            self.tabs.addTab(self.tab_files, "")

            # 4. Settings & Privacy Tab
            self.tab_settings = QWidget()
            set_layout = QVBoxLayout(self.tab_settings)
            form = QFormLayout()

            self.chk_monitor_clip = QCheckBox()
            self.chk_auto_win_to_and = QCheckBox()
            self.chk_auto_and_to_win = QCheckBox()
            self.chk_auto_copy_recv = QCheckBox()
            self.chk_auto_accept_files = QCheckBox()
            self.chk_hide_notif = QCheckBox()
            self.chk_save_history = QCheckBox()
            self.chk_run_startup = QCheckBox()

            for chk, key in [
                (self.chk_monitor_clip, "monitor_windows_clipboard"),
                (self.chk_auto_win_to_and, "auto_sync_win_to_android"),
                (self.chk_auto_and_to_win, "auto_sync_android_to_win"),
                (self.chk_auto_copy_recv, "auto_copy_received_to_clipboard"),
                (self.chk_auto_accept_files, "auto_accept_files"),
                (self.chk_hide_notif, "hide_text_in_notifications"),
                (self.chk_save_history, "save_clipboard_history"),
                (self.chk_run_startup, "run_on_windows_startup"),
            ]:
                chk.setChecked(bool(self.node.storage.get_setting(key, False)))
                chk.toggled.connect(lambda val, k=key: self._on_setting_toggled(k, val))
                form.addRow(chk)

            # Language & Theme selectors
            lang_theme_row = QHBoxLayout()
            self.btn_toggle_lang = QPushButton("العربية (RTL) / English (LTR)")
            self.btn_toggle_lang.clicked.connect(self._toggle_language)
            self.btn_toggle_theme = QPushButton("الوضع الداكن / الفاتح (Dark / Light)")
            self.btn_toggle_theme.clicked.connect(self._toggle_theme)
            self.btn_renew_cert = QPushButton()
            self.btn_renew_cert.clicked.connect(self._on_renew_cert)
            lang_theme_row.addWidget(self.btn_toggle_lang)
            lang_theme_row.addWidget(self.btn_toggle_theme)
            lang_theme_row.addWidget(self.btn_renew_cert)

            set_layout.addLayout(form)
            set_layout.addLayout(lang_theme_row)
            self.tabs.addTab(self.tab_settings, "")

            # 5. About Tab (includes «عمل محمد البكير»)
            self.tab_about = QWidget()
            about_layout = QVBoxLayout(self.tab_about)
            self.lbl_about_heading = QLabel()
            self.lbl_about_heading.setStyleSheet("font-size: 18px; font-weight: bold;")
            self.lbl_about_desc = QLabel()
            self.lbl_about_desc.setWordWrap(True)
            self.lbl_about_credit = QLabel()
            self.lbl_about_credit.setStyleSheet(
                "font-size: 15px; font-weight: 600; color: #38BDF8; margin-top: 16px; padding: 10px; "
                "border: 1px solid #334155; border-radius: 8px;"
            )
            self.lbl_about_fp = QLabel()
            self.lbl_about_fp.setWordWrap(True)
            about_layout.addWidget(self.lbl_about_heading)
            about_layout.addWidget(self.lbl_about_desc)
            about_layout.addWidget(self.lbl_about_fp)
            about_layout.addWidget(self.lbl_about_credit)
            about_layout.addStretch()
            self.tabs.addTab(self.tab_about, "")

            self._refresh_clipboard_table()
            self._refresh_files_table()

        def _apply_language_and_theme(self) -> None:
            self.setLayoutDirection(Qt.LayoutDirection.RightToLeft if self.lang == "ar" else Qt.LayoutDirection.LeftToRight)
            self.setStyleSheet(get_stylesheet(self.theme))
            self.setWindowTitle(self.tr_key("app_title"))

            if self.node.active_transport and self.node.active_transport.is_connected:
                self.lbl_conn_status.setText(
                    self.tr_key("status_connected").format(
                        peer=self.node.active_transport.peer_device_name or "Android",
                        transport=self.node.active_transport.transport_type.value,
                    )
                )
            else:
                self.lbl_conn_status.setText(self.tr_key("status_disconnected"))

            ips = LocalDiscoveryService.get_local_private_ips()
            self.lbl_local_addr.setText(f"IP: {ips[0]['ip']} | ID: {self.node.identity.device_id}")

            self.tabs.setTabText(0, self.tr_key("tab_dashboard"))
            self.tabs.setTabText(1, self.tr_key("tab_clipboard"))
            self.tabs.setTabText(2, self.tr_key("tab_files"))
            self.tabs.setTabText(3, self.tr_key("tab_settings"))
            self.tabs.setTabText(4, self.tr_key("tab_about"))

            self.btn_listen.setText(
                self.tr_key("btn_stop_listener") if self.node._listening else self.tr_key("btn_start_listener")
            )
            self.btn_gen_pin.setText(self.tr_key("btn_generate_pin"))
            self.btn_connect.setText(self.tr_key("btn_connect_peer"))
            self.btn_send_text.setText(self.tr_key("btn_send_text"))
            self.btn_send_clip.setText(self.tr_key("btn_send_clipboard"))
            self.btn_quick_files.setText(self.tr_key("btn_send_files"))
            self.btn_send_files_tab.setText(self.tr_key("btn_send_files"))
            self.btn_send_folder_tab.setText(self.tr_key("btn_send_folder"))
            self.btn_clean_temp.setText(self.tr_key("btn_clean_temp"))
            self.btn_clear_clip.setText(self.tr_key("btn_clear_history"))
            self.btn_renew_cert.setText(self.tr_key("btn_renew_cert"))
            self.input_clip_search.setPlaceholderText(self.tr_key("lbl_search_clip"))

            self.chk_monitor_clip.setText(self.tr_key("chk_monitor_clip"))
            self.chk_auto_win_to_and.setText(self.tr_key("chk_auto_win_to_and"))
            self.chk_auto_and_to_win.setText(self.tr_key("chk_auto_and_to_win"))
            self.chk_auto_copy_recv.setText(self.tr_key("chk_auto_copy_recv"))
            self.chk_auto_accept_files.setText(self.tr_key("chk_auto_accept_files"))
            self.chk_hide_notif.setText(self.tr_key("chk_hide_notif"))
            self.chk_save_history.setText(self.tr_key("chk_save_history"))
            self.chk_run_startup.setText(self.tr_key("chk_run_startup"))

            self.lbl_about_heading.setText(self.tr_key("about_heading"))
            self.lbl_about_desc.setText(self.tr_key("about_description"))
            self.lbl_about_fp.setText(
                f"{self.tr_key('lbl_fingerprint')} {self.node.identity.fingerprint_sha256}"
            )
            self.lbl_about_credit.setText(f"✦ {self.tr_key('about_credit')} ✦")

        def _setup_tray_icon(self) -> None:
            if not QSystemTrayIcon.isSystemTrayAvailable():
                return
            pix = QPixmap(32, 32)
            pix.fill(QColor("#0EA5E9"))
            self.tray = QSystemTrayIcon(QIcon(pix), self)
            menu = QMenu()
            act_show = QAction("إظهار LinkBridge / Show", self)
            act_show.triggered.connect(self.showNormal)
            act_send_clip = QAction(self.tr_key("btn_send_clipboard"), self)
            act_send_clip.triggered.connect(self._on_send_current_clipboard)
            act_quit = QAction("خروج / Exit", self)
            act_quit.triggered.connect(QApplication.instance().quit)
            menu.addAction(act_show)
            menu.addAction(act_send_clip)
            menu.addSeparator()
            menu.addAction(act_quit)
            self.tray.setContextMenu(menu)
            self.tray.show()

        def _toggle_language(self) -> None:
            self.lang = "en" if self.lang == "ar" else "ar"
            self.node.storage.set_setting("language", self.lang)
            self._apply_language_and_theme()

        def _toggle_theme(self) -> None:
            self.theme = "light" if self.theme == "dark" else "dark"
            self.node.storage.set_setting("theme", self.theme)
            self._apply_language_and_theme()

        def _on_setting_toggled(self, key: str, value: bool) -> None:
            if key == "run_on_windows_startup":
                WindowsStartupManager.set_startup_enabled(value, storage=self.node.storage)
            else:
                self.node.storage.set_setting(key, value)

        def _toggle_listener(self) -> None:
            if self.node._listening:
                self.node.stop_wifi_listener()
                self.lbl_pairing_info.setText("تم إيقاف خدمة الاستماع المحلية.")
            else:
                if not self.node.active_pin:
                    self.node.generate_pairing_code()
                ips = LocalDiscoveryService.get_local_private_ips()
                display_ip = ips[0]["ip"]
                _, port = self.node.start_wifi_listener(bind_ip="0.0.0.0", port=DEFAULT_WIFI_PORT)
                self.lbl_pairing_info.setText(
                    f"{self.tr_key('status_listening').format(ip=display_ip, port=port)} | رمز الاقتران (PIN): {self.node.active_pin}"
                )
            self._apply_language_and_theme()

        def _on_generate_pin(self) -> None:
            pin, secret_hex, exp = self.node.generate_pairing_code()
            ips = LocalDiscoveryService.get_local_private_ips()
            qr_json = LocalDiscoveryService.build_qr_pairing_payload(
                self.node.identity, ips[0]["ip"], DEFAULT_WIFI_PORT, secret_hex, pin, exp
            )
            self.lbl_pairing_info.setText(
                f"رمز الاقتران المؤقت (صالح لـ 5 دقائق): {pin}\nبيانات QR للاقتران السريع: {qr_json}"
            )

        def _on_connect_clicked(self) -> None:
            target = self.input_peer_addr.text().strip()
            pin = self.input_pin.text().strip() or None
            route = self.combo_route.currentData()
            if not target:
                QMessageBox.warning(self, "LinkBridge", "يرجى إدخال عنوان IP:Port أو عنوان Bluetooth MAC.")
                return
            try:
                if route == TransportType.BLUETOOTH_RFCOMM.value:
                    t = BluetoothRfcommTransport.connect(self.node.identity, bt_mac_address=target)
                else:
                    host, port_s = (target.split(":", 1) + [str(DEFAULT_WIFI_PORT)])[:2]
                    t = WifiTlsTransport.connect(
                        self.node.identity,
                        host=host,
                        port=int(port_s),
                        is_hotspot=(route == TransportType.WIFI_HOTSPOT.value),
                    )
                self.node.authenticate_as_client(t, pin_or_secret=pin)
                self.node.enable_live_dispatcher(t)
                self._apply_language_and_theme()
            except Exception as e:
                QMessageBox.critical(self, "خطأ في الاتصال", str(e))

        def _on_send_custom_text(self) -> None:
            text = self.txt_quick_send.toPlainText()
            if not self.node.active_transport or not self.node.active_transport.is_connected:
                QMessageBox.warning(self, "LinkBridge", "يرجى الاتصال بالجهاز المقترن أولًا.")
                return
            ok, info = self.node.clipboard_manager.send_text_manual(self.node.active_transport, text)
            if not ok:
                QMessageBox.warning(self, "LinkBridge", info.get("error", "Error"))
            else:
                self.txt_quick_send.clear()
                self._refresh_clipboard_table()

        def _on_send_current_clipboard(self) -> None:
            text = self.node.clipboard_backend.get_text()
            if not self.node.active_transport or not self.node.active_transport.is_connected:
                QMessageBox.warning(self, "LinkBridge", "يرجى الاتصال بالجهاز المقترن أولًا.")
                return
            ok, info = self.node.clipboard_manager.send_text_manual(self.node.active_transport, text)
            if not ok:
                QMessageBox.warning(self, "LinkBridge", info.get("error", "Error"))
            else:
                self._refresh_clipboard_table()

        def _on_pick_and_send_files(self) -> None:
            if not self.node.active_transport or not self.node.active_transport.is_connected:
                QMessageBox.warning(self, "LinkBridge", "يرجى الاتصال بالجهاز المقترن أولًا.")
                return
            files, _ = QFileDialog.getOpenFileNames(self, self.tr_key("btn_send_files"))
            for fpath in files:
                try:
                    self.node.file_manager.send_file(self.node.active_transport, Path(fpath))
                except Exception as e:
                    QMessageBox.critical(self, "خطأ في نقل الملف", str(e))
            self._refresh_files_table()

        def _on_pick_and_send_folder(self) -> None:
            if not self.node.active_transport or not self.node.active_transport.is_connected:
                QMessageBox.warning(self, "LinkBridge", "يرجى الاتصال بالجهاز المقترن أولًا.")
                return
            folder = QFileDialog.getExistingDirectory(self, self.tr_key("btn_send_folder"))
            if folder:
                try:
                    self.node.file_manager.send_directory(self.node.active_transport, Path(folder))
                except Exception as e:
                    QMessageBox.critical(self, "خطأ في نقل المجلد", str(e))
                self._refresh_files_table()

        def _on_clear_clipboard_history(self) -> None:
            self.node.storage.clear_clipboard_history()
            self._refresh_clipboard_table()

        def _on_clean_temp_files(self) -> None:
            count = self.node.storage.cleanup_temporary_files()
            QMessageBox.information(self, "LinkBridge", f"تم تنظيف {count} من الملفات المؤقتة غير المكتملة.")
            self._refresh_files_table()

        def _on_renew_cert(self) -> None:
            self.node.renew_device_certificate()
            self._apply_language_and_theme()
            QMessageBox.information(self, "LinkBridge", "تم تجديد شهادة الأمان ومفاتيح الجهاز بنجاح.")

        def _poll_clipboard(self) -> None:
            if self.node.active_transport and self.node.active_transport.is_connected:
                sent, _ = self.node.clipboard_manager.poll_local_clipboard_for_auto_sync(self.node.active_transport)
                if sent:
                    self._refresh_clipboard_table()

        def _prompt_file_approval(self, info: Dict[str, Any]) -> bool:
            ans = QMessageBox.question(
                self,
                "طلب استلام ملف",
                f"يرغب الجهاز المقترن بإرسال الملف:\n{info['file_name']} ({info['total_bytes']} بايت)\nهل توافق على الاستلام؟",
            )
            return ans == QMessageBox.StandardButton.Yes

        def _on_node_event(self, event_type: str, data: Dict[str, Any]) -> None:
            if event_type == "CONNECTED":
                self._apply_language_and_theme()
            elif event_type == "CLIPBOARD_RECEIVED":
                self._refresh_clipboard_table()
                if hasattr(self, "tray"):
                    self.tray.showMessage("LinkBridge", data.get("notification_preview", ""))
            elif event_type == "FILE_PROGRESS":
                total = max(int(data.get("total_bytes", 1)), 1)
                done = int(data.get("transferred_bytes", 0))
                self.progress_bar.setValue(int((done * 100) / total))
                self._refresh_files_table()

        def _refresh_clipboard_table(self) -> None:
            items = self.node.storage.list_clipboard_history(self.input_clip_search.text())
            self.tbl_clip.setRowCount(len(items))
            for idx, it in enumerate(items):
                self.tbl_clip.setItem(idx, 0, QTableWidgetItem(it["item_id"]))
                self.tbl_clip.setItem(idx, 1, QTableWidgetItem(it["direction"]))
                self.tbl_clip.setItem(idx, 2, QTableWidgetItem(it["transport"]))
                preview = it["text_content"].replace("\n", " ")[:80]
                self.tbl_clip.setItem(idx, 3, QTableWidgetItem(preview))
                self.tbl_clip.setItem(idx, 4, QTableWidgetItem(it["content_hash"][:16]))

        def _refresh_files_table(self) -> None:
            items = self.node.storage.list_file_transfers()
            self.tbl_files.setRowCount(len(items))
            for idx, it in enumerate(items):
                self.tbl_files.setItem(idx, 0, QTableWidgetItem(str(it["transfer_id"])))
                self.tbl_files.setItem(idx, 1, QTableWidgetItem(it["file_name"]))
                self.tbl_files.setItem(idx, 2, QTableWidgetItem(it["direction"]))
                prog = f"{it['transferred_bytes']}/{it['total_bytes']} B"
                self.tbl_files.setItem(idx, 3, QTableWidgetItem(prog))
                self.tbl_files.setItem(idx, 4, QTableWidgetItem(it["status"]))
                self.tbl_files.setItem(idx, 5, QTableWidgetItem(it["expected_sha256"][:16]))

    app = QApplication(sys.argv)
    win = LinkBridgeMainWindow()
    if not start_minimized:
        win.show()
    return app.exec()


def main() -> int:
    parser = argparse.ArgumentParser(description="LinkBridge Windows Desktop Application")
    parser.add_argument("--data-dir", type=str, default=str(get_default_appdata_dir()))
    parser.add_argument("--minimized", action="store_true", help="Start minimized in system tray")
    parser.add_argument("--self-check", action="store_true", help="Run non-interactive self-check and print JSON status")
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    if args.self_check:
        return run_self_check(data_dir)
    return launch_pyside6_gui(data_dir, start_minimized=args.minimized)


if __name__ == "__main__":
    sys.exit(main())
