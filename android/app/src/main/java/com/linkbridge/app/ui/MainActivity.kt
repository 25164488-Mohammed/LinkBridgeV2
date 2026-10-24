package com.linkbridge.app.ui

import android.app.Activity
import android.bluetooth.BluetoothAdapter
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.Gravity
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.documentfile.provider.DocumentFile
import com.linkbridge.app.R
import com.linkbridge.app.clipboard.AndroidClipboardController
import com.linkbridge.app.data.LinkBridgeDatabase
import com.linkbridge.app.files.SafFileTransferController
import com.linkbridge.app.protocol.AndroidDeviceIdentity
import com.linkbridge.app.protocol.BluetoothRfcommTransportAdapter
import com.linkbridge.app.protocol.ProtocolConstants
import com.linkbridge.app.protocol.ProtocolFrame
import com.linkbridge.app.protocol.TransportAdapter
import com.linkbridge.app.protocol.WifiTlsTransportAdapter
import com.linkbridge.app.service.LinkBridgeForegroundService
import org.json.JSONObject
import java.io.File
import kotlin.concurrent.thread

class MainActivity : AppCompatActivity() {

    companion object {
        private const val REQ_PICK_FILES = 1001
        private const val REQ_PICK_SAVE_FOLDER = 1002
        @Volatile
        var activeTransport: TransportAdapter? = null
    }

    private lateinit var db: LinkBridgeDatabase
    private lateinit var identity: AndroidDeviceIdentity
    private lateinit var clipboardController: AndroidClipboardController
    private lateinit var fileController: SafFileTransferController
    private var selectedSaveTreeUri: Uri? = null

    private lateinit var tvStatus: TextView
    private lateinit var etPeerHost: EditText
    private lateinit var etPin: EditText
    private lateinit var spinnerRoute: Spinner
    private lateinit var etTextToSend: EditText
    private lateinit var progressBar: ProgressBar
    private lateinit var tvHistoryLog: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        db = LinkBridgeDatabase(this)
        identity = AndroidDeviceIdentity.loadOrCreate(db)
        clipboardController = AndroidClipboardController(this, identity.deviceId, db)
        fileController = SafFileTransferController(this, db)

        val savedUriStr = db.getSetting("saf_receive_tree_uri", "")
        if (savedUriStr.isNotEmpty()) {
            selectedSaveTreeUri = Uri.parse(savedUriStr)
        }

        val rootScroll = ScrollView(this)
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(40, 40, 40, 40)
        }
        rootScroll.addView(container)

        val tvTitle = TextView(this).apply {
            text = getString(R.string.app_name)
            textSize = 20f
        }
        tvStatus = TextView(this).apply {
            text = getString(R.string.status_disconnected)
            textSize = 14f
            setPadding(0, 12, 0, 20)
        }
        container.addView(tvTitle)
        container.addView(tvStatus)

        spinnerRoute = Spinner(this)
        val routes = listOf(
            getString(R.string.route_wifi_lan),
            getString(R.string.route_wifi_hotspot),
            getString(R.string.route_bluetooth)
        )
        spinnerRoute.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, routes)
        container.addView(spinnerRoute)

        etPeerHost = EditText(this).apply {
            hint = "IP:Port (192.168.1.10:48520) / BT MAC (AA:BB:CC:DD:EE:FF)"
            setText(db.getSetting("last_peer_host", ""))
        }
        etPin = EditText(this).apply {
            hint = getString(R.string.hint_pairing_pin)
        }
        container.addView(etPeerHost)
        container.addView(etPin)

        val btnConnect = Button(this).apply {
            text = getString(R.string.btn_connect)
            setOnClickListener { connectToPeer() }
        }
        container.addView(btnConnect)

        etTextToSend = EditText(this).apply {
            hint = getString(R.string.hint_enter_text)
            minLines = 3
        }
        container.addView(etTextToSend)

        val btnSendCurrentClip = Button(this).apply {
            text = getString(R.string.btn_send_clipboard_now)
            setOnClickListener { sendCurrentClipboard() }
        }
        val btnSendTypedText = Button(this).apply {
            text = getString(R.string.btn_send_text)
            setOnClickListener { sendCustomText() }
        }
        container.addView(btnSendCurrentClip)
        container.addView(btnSendTypedText)

        progressBar = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal).apply {
            max = 100
            progress = 0
        }
        val btnSendFiles = Button(this).apply {
            text = getString(R.string.btn_pick_and_send_files)
            setOnClickListener { openSafFilePicker() }
        }
        val btnPickSaveDir = Button(this).apply {
            text = getString(R.string.btn_select_receive_folder)
            setOnClickListener { openSafFolderPicker() }
        }
        container.addView(progressBar)
        container.addView(btnSendFiles)
        container.addView(btnPickSaveDir)

        val chkAutoCopy = CheckBox(this).apply {
            text = getString(R.string.chk_auto_copy_clipboard)
            isChecked = db.getSetting("auto_copy_received_to_clipboard", "false") == "true"
            setOnCheckedChangeListener { _, isChecked ->
                db.setSetting("auto_copy_received_to_clipboard", isChecked.toString())
            }
        }
        val chkFgService = CheckBox(this).apply {
            text = getString(R.string.chk_enable_quick_notification)
            setOnCheckedChangeListener { _, isChecked ->
                val svcIntent = Intent(this@MainActivity, LinkBridgeForegroundService::class.java)
                if (isChecked) startForegroundService(svcIntent) else stopService(svcIntent)
            }
        }
        val btnToggleTheme = Button(this).apply {
            text = getString(R.string.btn_toggle_theme)
            setOnClickListener {
                val mode = AppCompatDelegate.getDefaultNightMode()
                if (mode == AppCompatDelegate.MODE_NIGHT_YES) {
                    AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_NO)
                } else {
                    AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES)
                }
            }
        }
        container.addView(chkAutoCopy)
        container.addView(chkFgService)
        container.addView(btnToggleTheme)

        tvHistoryLog = TextView(this).apply {
            setPadding(0, 20, 0, 12)
        }
        container.addView(tvHistoryLog)

        val tvPlatformNote = TextView(this).apply {
            text = clipboardController.getAndroidClipboardPlatformNote()
            setPadding(0, 16, 0, 12)
        }
        val tvAbout = TextView(this).apply {
            text = "${getString(R.string.about_title)}\nID: ${identity.deviceId}\n✦ ${getString(R.string.about_credit)} ✦"
            gravity = Gravity.CENTER
            textSize = 15f
            setPadding(16, 28, 16, 16)
        }
        container.addView(tvPlatformNote)
        container.addView(tvAbout)

        setContentView(rootScroll)
        refreshHistoryView()
    }

    private fun refreshHistoryView() {
        val items = db.listRecentClipboardItems(15)
        tvHistoryLog.text = if (items.isEmpty()) {
            "سجل الحافظة فارغ حاليًا"
        } else {
            "آخر عناصر الحافظة:\n" + items.joinToString("\n")
        }
    }

    private fun connectToPeer() {
        val target = etPeerHost.text.toString().trim()
        val pin = etPin.text.toString().trim().ifEmpty { null }
        if (target.isEmpty()) {
            Toast.makeText(this, "يرجى إدخال عنوان الجهاز المقابل (IP:Port أو BT MAC)", Toast.LENGTH_SHORT).show()
            return
        }
        db.setSetting("last_peer_host", target)
        val routeIdx = spinnerRoute.selectedItemPosition
        thread {
            try {
                val adapter: TransportAdapter = when (routeIdx) {
                    2 -> {
                        val btAdapter = BluetoothAdapter.getDefaultAdapter()
                        val bonded = BluetoothRfcommTransportAdapter.getPairedDevices(btAdapter)
                            .firstOrNull { it.address.equals(target, ignoreCase = true) || it.name == target }
                            ?: throw IllegalStateException("الجهاز غير مقترن عبر Bluetooth؛ يرجى الاقتران أولًا")
                        BluetoothRfcommTransportAdapter.connectToPairedDevice(bonded)
                    }
                    else -> {
                        val parts = target.split(":")
                        val host = parts[0]
                        val port = parts.getOrNull(1)?.toIntOrNull() ?: ProtocolConstants.DEFAULT_WIFI_PORT
                        WifiTlsTransportAdapter.connect(host, port, isHotspot = (routeIdx == 1))
                    }
                }
                adapter.clientHandshakeAndAuth(identity, db, pin)
                adapter.startBackgroundDispatcher { frame -> handleIncomingFrameFromWindows(adapter, frame) }
                activeTransport = adapter
                runOnUiThread {
                    tvStatus.text = "متصل بـ ${adapter.peerDeviceName ?: "Windows"} (${adapter.route.name})"
                    Toast.makeText(this, "تم الاتصال والمصادقة بنجاح!", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                runOnUiThread {
                    tvStatus.text = "فشل الاتصال أو المصادقة: ${e.message}"
                    Toast.makeText(this, "خطأ: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun handleIncomingFrameFromWindows(transport: TransportAdapter, frame: ProtocolFrame) {
        when (frame.header.msgType) {
            ProtocolConstants.MSG_CLIPBOARD_PUSH -> {
                val ok = clipboardController.handleIncomingClipboardPush(transport, frame.jsonBody())
                if (ok) {
                    runOnUiThread {
                        refreshHistoryView()
                        Toast.makeText(this, "تم استلام نص جديد من الكمبيوتر", Toast.LENGTH_SHORT).show()
                    }
                }
            }
            ProtocolConstants.MSG_FILE_OFFER -> {
                val offerBody = frame.jsonBody()
                val transferId = frame.header.transferId
                val treeUri = selectedSaveTreeUri
                val targetDocDir = if (treeUri != null) {
                    DocumentFile.fromTreeUri(this, treeUri)
                } else {
                    val fallbackDir = getExternalFilesDir(null) ?: filesDir
                    DocumentFile.fromFile(fallbackDir)
                }
                if (targetDocDir != null) {
                    val saved = fileController.receiveFileToSafDirectory(transport, offerBody, transferId, targetDocDir)
                    runOnUiThread {
                        if (saved) {
                            Toast.makeText(this, "تم استلام الملف والتحقق من SHA-256 بنجاح", Toast.LENGTH_LONG).show()
                        } else {
                            Toast.makeText(this, "تعذر حفظ الملف الوارد", Toast.LENGTH_LONG).show()
                        }
                    }
                }
            }
            ProtocolConstants.MSG_PING -> {
                transport.sendControl(ProtocolConstants.MSG_PONG, JSONObject().put("ts", System.currentTimeMillis()))
            }
        }
    }

    private fun sendCurrentClipboard() {
        val transport = activeTransport ?: run {
            Toast.makeText(this, "يرجى الاتصال بالكمبيوتر أولًا", Toast.LENGTH_SHORT).show()
            return
        }
        val clipText = clipboardController.readCurrentClipboardText()
        if (clipText.isNullOrBlank()) {
            Toast.makeText(this, "الحافظة فارغة حاليًا", Toast.LENGTH_SHORT).show()
            return
        }
        thread {
            try {
                clipboardController.sendTextNow(transport, clipText, mode = "MANUAL")
                runOnUiThread {
                    refreshHistoryView()
                    Toast.makeText(this, "تم إرسال الحافظة إلى Windows بنجاح", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                runOnUiThread {
                    Toast.makeText(this, "خطأ: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun sendCustomText() {
        val transport = activeTransport ?: run {
            Toast.makeText(this, "يرجى الاتصال بالكمبيوتر أولًا", Toast.LENGTH_SHORT).show()
            return
        }
        val txt = etTextToSend.text.toString()
        thread {
            try {
                if (clipboardController.sendTextNow(transport, txt, mode = "MANUAL")) {
                    runOnUiThread {
                        etTextToSend.text.clear()
                        refreshHistoryView()
                        Toast.makeText(this, "تم إرسال النص إلى Windows بنجاح", Toast.LENGTH_SHORT).show()
                    }
                }
            } catch (e: Exception) {
                runOnUiThread {
                    Toast.makeText(this, "خطأ: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun openSafFilePicker() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true)
        }
        @Suppress("DEPRECATION")
        startActivityForResult(intent, REQ_PICK_FILES)
    }

    private fun openSafFolderPicker() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE)
        @Suppress("DEPRECATION")
        startActivityForResult(intent, REQ_PICK_SAVE_FOLDER)
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != Activity.RESULT_OK || data == null) return
        when (requestCode) {
            REQ_PICK_SAVE_FOLDER -> {
                data.data?.let { treeUri ->
                    contentResolver.takePersistableUriPermission(
                        treeUri,
                        Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                    )
                    selectedSaveTreeUri = treeUri
                    db.setSetting("saf_receive_tree_uri", treeUri.toString())
                    Toast.makeText(this, "تم حفظ مجلد الاستقبال بنجاح", Toast.LENGTH_SHORT).show()
                }
            }
            REQ_PICK_FILES -> {
                val transport = activeTransport ?: return
                val uris = mutableListOf<Uri>()
                data.clipData?.let { clip ->
                    for (i in 0 until clip.itemCount) {
                        uris.add(clip.getItemAt(i).uri)
                    }
                } ?: data.data?.let { uris.add(it) }

                thread {
                    try {
                        for (uri in uris) {
                            fileController.sendUriFile(transport, uri) { sent, total ->
                                val pct = if (total > 0) ((sent * 100) / total).toInt() else 0
                                runOnUiThread { progressBar.progress = pct }
                            }
                        }
                        runOnUiThread {
                            Toast.makeText(this, "اكتمل إرسال الملفات والتحقق من SHA-256", Toast.LENGTH_SHORT).show()
                        }
                    } catch (e: Exception) {
                        runOnUiThread {
                            Toast.makeText(this, "خطأ في نقل الملف: ${e.message}", Toast.LENGTH_LONG).show()
                        }
                    }
                }
            }
        }
    }
}
