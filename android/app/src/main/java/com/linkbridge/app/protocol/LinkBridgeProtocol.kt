package com.linkbridge.app.protocol

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothSocket
import android.util.Base64
import com.linkbridge.app.data.LinkBridgeDatabase
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.UUID
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.concurrent.thread

object ProtocolConstants {
    val MAGIC = byteArrayOf('L'.code.toByte(), 'B'.code.toByte(), '0'.code.toByte(), '1'.code.toByte())
    const val VERSION: Byte = 1
    const val HEADER_SIZE = 64
    const val DEFAULT_WIFI_PORT = 48520
    const val WIFI_CHUNK_SIZE = 65536
    const val BT_CHUNK_SIZE = 16384
    val BT_SERVICE_UUID: UUID = UUID.fromString("8c9b4f10-5d32-4e8a-b129-7f4e90c31a2b")

    const val FLAG_NONE: Int = 0x00
    const val FLAG_ENCRYPTED_AEAD: Int = 0x01
    const val FLAG_REQUIRE_ACK: Int = 0x02
    const val FLAG_IS_BINARY_CHUNK: Int = 0x04

    const val MSG_HELLO: Int = 0x01
    const val MSG_HELLO_ACK: Int = 0x02
    const val MSG_PAIR_REQUEST: Int = 0x03
    const val MSG_PAIR_RESPONSE: Int = 0x04
    const val MSG_AUTH_SESSION: Int = 0x05
    const val MSG_AUTH_RESULT: Int = 0x06
    const val MSG_PING: Int = 0x07
    const val MSG_PONG: Int = 0x08
    const val MSG_DISCONNECT: Int = 0x09
    const val MSG_REVOKE_PAIRING: Int = 0x0A

    const val MSG_CLIPBOARD_PUSH: Int = 0x10
    const val MSG_CLIPBOARD_ACK: Int = 0x11

    const val MSG_FILE_OFFER: Int = 0x20
    const val MSG_FILE_ACCEPT: Int = 0x21
    const val MSG_FILE_REJECT: Int = 0x22
    const val MSG_FILE_CHUNK: Int = 0x23
    const val MSG_FILE_CHUNK_ACK: Int = 0x24
    const val MSG_FILE_COMPLETE: Int = 0x25
    const val MSG_FILE_VERIFY_RESULT: Int = 0x26
    const val MSG_FILE_CANCEL: Int = 0x27

    const val MSG_ERROR: Int = 0xF0
}

enum class TransportRoute {
    WIFI_LAN,
    WIFI_HOTSPOT,
    BLUETOOTH_RFCOMM
}

data class FrameHeader(
    val version: Byte,
    val flags: Int,
    val msgType: Int,
    val msgId: Long,
    val transferId: Long,
    val payloadLength: Long,
    val sha256Digest: ByteArray
)

data class ProtocolFrame(
    val header: FrameHeader,
    val payload: ByteArray
) {
    fun jsonBody(): JSONObject {
        if ((header.flags and ProtocolConstants.FLAG_IS_BINARY_CHUNK) != 0) {
            throw IllegalStateException("Binary chunk frame cannot be parsed as JSON")
        }
        return JSONObject(String(payload, StandardCharsets.UTF_8))
    }
}

object CryptoUtils {
    private val secureRandom = SecureRandom()

    fun randomHex(numBytes: Int = 16): String {
        val b = ByteArray(numBytes)
        secureRandom.nextBytes(b)
        return b.joinToString("") { "%02x".format(it) }
    }

    fun sha256Bytes(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    fun sha256Hex(data: ByteArray): String =
        sha256Bytes(data).joinToString("") { "%02x".format(it) }

    fun hmacSha256Hex(key: ByteArray, message: ByteArray): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(message).joinToString("") { "%02x".format(it) }
    }

    fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int = 32): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)

        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        val okm = ByteBuffer.allocate(length)
        var t = ByteArray(0)
        var counter: Byte = 1
        while (okm.remaining() > 0) {
            mac.reset()
            mac.update(t)
            mac.update(info)
            mac.update(counter)
            t = mac.doFinal()
            val toCopy = minOf(t.size, okm.remaining())
            okm.put(t, 0, toCopy)
            counter++
        }
        return okm.array()
    }

    fun deriveSharedLinkKey(pinOrSecret: String, initiatorFp: String, responderFp: String): ByteArray {
        val salt = sha256Bytes("$initiatorFp:$responderFp".toByteArray(StandardCharsets.UTF_8))
        return hkdfSha256(
            ikm = pinOrSecret.toByteArray(StandardCharsets.UTF_8),
            salt = salt,
            info = "LinkBridge-Paired-LinkKey-v1".toByteArray(StandardCharsets.UTF_8),
            length = 32
        )
    }

    fun hexToBytes(hex: String): ByteArray {
        val clean = hex.trim()
        val out = ByteArray(clean.length / 2)
        for (i in out.indices) {
            val idx = i * 2
            out[i] = clean.substring(idx, idx + 2).toInt(16).toByte()
        }
        return out
    }

    fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }
}

/**
 * Persistent Device Cryptographic Identity for Android (`AndroidDeviceIdentity`).
 * Generates a unique EC P-256 keypair, stores its SubjectPublicKeyInfo PEM & SHA-256 fingerprint in SQLite,
 * and matches `DeviceIdentity.fingerprint_from_pem` on Windows.
 */
data class AndroidDeviceIdentity(
    val deviceId: String,
    val deviceName: String,
    val publicPem: String,
    val fingerprintSha256: String
) {
    companion object {
        fun loadOrCreate(db: LinkBridgeDatabase, deviceName: String = android.os.Build.MODEL ?: "Android-9"): AndroidDeviceIdentity {
            val existingId = db.getSetting("device_id", "")
            val existingPem = db.getSetting("device_pub_pem", "")
            val existingFp = db.getSetting("device_fp_sha256", "")
            if (existingId.isNotEmpty() && existingPem.isNotEmpty() && existingFp.isNotEmpty()) {
                return AndroidDeviceIdentity(existingId, deviceName, existingPem, existingFp)
            }
            return generateNew(db, deviceName)
        }

        fun generateNew(db: LinkBridgeDatabase, deviceName: String = android.os.Build.MODEL ?: "Android-9"): AndroidDeviceIdentity {
            val deviceId = "lb-android-" + CryptoUtils.randomHex(8)
            val kpg = KeyPairGenerator.getInstance("EC")
            kpg.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
            val kp = kpg.generateKeyPair()
            val derBytes = kp.public.encoded
            val b64 = Base64.encodeToString(derBytes, Base64.NO_WRAP)
            val pubPem = "-----BEGIN PUBLIC KEY-----\n$b64\n-----END PUBLIC KEY-----\n"
            val fp = CryptoUtils.sha256Hex(derBytes)

            db.setSetting("device_id", deviceId)
            db.setSetting("device_pub_pem", pubPem)
            db.setSetting("device_fp_sha256", fp)
            return AndroidDeviceIdentity(deviceId, deviceName, pubPem, fp)
        }
    }
}

class AeadChannelCipher(private val sessionKey: ByteArray) {
    private var sendSeq: Long = 0
    private var recvSeq: Long = 0

    companion object {
        fun generateEphemeralEcdh(): Pair<KeyPair, String> {
            val kpg = KeyPairGenerator.getInstance("EC")
            kpg.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
            val kp = kpg.generateKeyPair()
            val b64 = Base64.encodeToString(kp.public.encoded, Base64.NO_WRAP)
            val pem = "-----BEGIN PUBLIC KEY-----\n$b64\n-----END PUBLIC KEY-----\n"
            return Pair(kp, pem)
        }

        fun fromEcdhAndLinkKey(
            localKeyPair: KeyPair,
            peerPubPem: String,
            pairedLinkKey: ByteArray,
            contextTranscript: ByteArray
        ): AeadChannelCipher {
            val cleanB64 = peerPubPem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("\\s".toRegex(), "")
            val pubBytes = Base64.decode(cleanB64, Base64.DEFAULT)
            val kf = KeyFactory.getInstance("EC")
            val peerPub = kf.generatePublic(X509EncodedKeySpec(pubBytes))

            val ka = KeyAgreement.getInstance("ECDH")
            ka.init(localKeyPair.private)
            ka.doPhase(peerPub, true)
            val sharedSecret = ka.generateSecret()

            val combinedSaltInput = ByteBuffer.allocate(pairedLinkKey.size + contextTranscript.size)
                .put(pairedLinkKey)
                .put(contextTranscript)
                .array()
            val salt = CryptoUtils.sha256Bytes(combinedSaltInput)
            val sessionKey = CryptoUtils.hkdfSha256(
                ikm = sharedSecret,
                salt = salt,
                info = "LinkBridge-RFCOMM-AES256GCM-v1".toByteArray(StandardCharsets.UTF_8),
                length = 32
            )
            return AeadChannelCipher(sessionKey)
        }
    }

    @Synchronized
    fun encrypt(plaintext: ByteArray, aad: ByteArray): ByteArray {
        val nonce = ByteBuffer.allocate(12).putInt(0).putLong(sendSeq).array()
        sendSeq++
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(sessionKey, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        val ct = cipher.doFinal(plaintext)
        return ByteBuffer.allocate(12 + ct.size).put(nonce).put(ct).array()
    }

    @Synchronized
    fun decrypt(wirePayload: ByteArray, aad: ByteArray): ByteArray {
        if (wirePayload.size < 28) {
            throw SecurityException("Truncated AEAD payload on RFCOMM channel")
        }
        val nonce = wirePayload.copyOfRange(0, 12)
        val seq = ByteBuffer.wrap(nonce, 4, 8).long
        if (seq < recvSeq) {
            throw SecurityException("Replay attack detected on RFCOMM channel: seq=$seq < expected=$recvSeq")
        }
        recvSeq = seq + 1
        val ct = wirePayload.copyOfRange(12, wirePayload.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(sessionKey, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(ct)
    }
}

abstract class TransportAdapter(
    val route: TransportRoute,
    val chunkSize: Int
) {
    private val msgCounter = AtomicLong(0)
    private val writeLock = Any()
    var sessionToken: String? = null
    var peerDeviceId: String? = null
    var peerDeviceName: String? = null
    var peerFingerprint: String? = null
    protected var aeadCipher: AeadChannelCipher? = null
    protected open val requireAead: Boolean = false

    private val dispatcherActive = AtomicBoolean(false)
    private val replyQueue = LinkedBlockingQueue<ProtocolFrame>()
    private val incomingQueue = LinkedBlockingQueue<ProtocolFrame>()

    abstract val isConnected: Boolean
    protected abstract val inputStream: InputStream
    protected abstract val outputStream: OutputStream
    abstract fun close()

    private fun buildAad(version: Byte, flags: Int, msgType: Int, msgId: Long, transferId: Long, digest: ByteArray): ByteArray {
        return ByteBuffer.allocate(52)
            .put(version)
            .put(flags.toByte())
            .putShort(msgType.toShort())
            .putLong(msgId)
            .putLong(transferId)
            .put(digest)
            .array()
    }

    fun sendControl(msgType: Int, body: JSONObject, transferId: Long = 0L): Long {
        if (!isConnected) throw IllegalStateException("Transport not connected")
        if (sessionToken != null && !body.has("session_token")) {
            body.put("session_token", sessionToken)
        }
        val bytes = body.toString().toByteArray(StandardCharsets.UTF_8)
        return sendRawFrame(msgType, bytes, transferId, ProtocolConstants.FLAG_NONE)
    }

    fun sendChunk(chunkBytes: ByteArray, transferId: Long): Long {
        if (!isConnected) throw IllegalStateException("Disconnected during chunk transfer")
        return sendRawFrame(
            ProtocolConstants.MSG_FILE_CHUNK,
            chunkBytes,
            transferId,
            ProtocolConstants.FLAG_IS_BINARY_CHUNK
        )
    }

    private fun sendRawFrame(msgType: Int, payload: ByteArray, transferId: Long, baseFlags: Int): Long {
        val msgId = msgCounter.incrementAndGet()
        val digest = CryptoUtils.sha256Bytes(payload)
        var flags = baseFlags
        val cipher = aeadCipher
        val wirePayload = if (cipher != null) {
            flags = flags or ProtocolConstants.FLAG_ENCRYPTED_AEAD
            val aad = buildAad(ProtocolConstants.VERSION, flags, msgType, msgId, transferId, digest)
            cipher.encrypt(payload, aad)
        } else {
            payload
        }

        val headerBuf = ByteBuffer.allocate(ProtocolConstants.HEADER_SIZE)
        headerBuf.put(ProtocolConstants.MAGIC)
        headerBuf.put(ProtocolConstants.VERSION)
        headerBuf.put(flags.toByte())
        headerBuf.putShort(msgType.toShort())
        headerBuf.putLong(msgId)
        headerBuf.putLong(transferId)
        headerBuf.putLong(wirePayload.size.toLong())
        headerBuf.put(digest)

        synchronized(writeLock) {
            outputStream.write(headerBuf.array())
            outputStream.write(wirePayload)
            outputStream.flush()
        }
        return msgId
    }

    private fun readStreamFrame(maxPayloadBytes: Int = 2 * 1024 * 1024): ProtocolFrame {
        val dis = DataInputStream(inputStream)
        val rawHeader = ByteArray(ProtocolConstants.HEADER_SIZE)
        dis.readFully(rawHeader)
        val buf = ByteBuffer.wrap(rawHeader)

        val magic = ByteArray(4)
        buf.get(magic)
        if (!magic.contentEquals(ProtocolConstants.MAGIC)) {
            throw SecurityException("Invalid protocol magic header")
        }
        val version = buf.get()
        if (version != ProtocolConstants.VERSION) {
            throw SecurityException("Unsupported protocol version: $version")
        }
        val flags = buf.get().toInt() and 0xFF
        val msgType = buf.short.toInt() and 0xFFFF
        val msgId = buf.long
        val transferId = buf.long
        val payloadLen = buf.long
        val digest = ByteArray(32)
        buf.get(digest)

        if (payloadLen < 0 || payloadLen > maxPayloadBytes) {
            throw SecurityException("Frame payload length $payloadLen exceeds limit $maxPayloadBytes")
        }

        val wirePayload = ByteArray(payloadLen.toInt())
        if (payloadLen > 0) {
            dis.readFully(wirePayload)
        }

        if (requireAead && aeadCipher != null && (flags and ProtocolConstants.FLAG_ENCRYPTED_AEAD) == 0) {
            throw SecurityException("Unencrypted frame rejected on channel requiring AEAD")
        }

        val cleartext = if ((flags and ProtocolConstants.FLAG_ENCRYPTED_AEAD) != 0) {
            val cipher = aeadCipher ?: throw SecurityException("Received AEAD frame without configured cipher")
            val aad = buildAad(version, flags, msgType, msgId, transferId, digest)
            cipher.decrypt(wirePayload, aad)
        } else {
            wirePayload
        }

        val actualDigest = CryptoUtils.sha256Bytes(cleartext)
        if (!actualDigest.contentEquals(digest)) {
            throw SecurityException("SHA-256 frame integrity verification failed")
        }

        val header = FrameHeader(version, flags, msgType, msgId, transferId, payloadLen, digest)
        return ProtocolFrame(header, cleartext)
    }

    fun receiveFrame(maxPayloadBytes: Int = 2 * 1024 * 1024): ProtocolFrame {
        if (dispatcherActive.get()) {
            return incomingQueue.poll(30, TimeUnit.SECONDS)
                ?: throw IllegalStateException("Timed out waiting for incoming frame")
        }
        return readStreamFrame(maxPayloadBytes)
    }

    fun receiveReplyFrame(maxPayloadBytes: Int = 2 * 1024 * 1024): ProtocolFrame {
        if (dispatcherActive.get()) {
            return replyQueue.poll(30, TimeUnit.SECONDS)
                ?: throw IllegalStateException("Timed out waiting for reply frame")
        }
        return readStreamFrame(maxPayloadBytes)
    }

    /**
     * Executes the complete LinkBridge v1.0 cryptographic handshake as Client (Initiator):
     * 1. Exchanges HELLO / HELLO_ACK with X.509/PublicKey fingerprint & ephemeral ECDH P-256 public keys.
     * 2. Sends PAIR_REQUEST / receives PAIR_RESPONSE if `pinOrSecret` is provided or device is not yet paired.
     * 3. Authenticates session (`AUTH_SESSION` / `AUTH_RESULT`) using derived 256-bit `linkKey`.
     * 4. Activates `AeadChannelCipher` (`AES-256-GCM`) if on Bluetooth RFCOMM.
     */
    fun clientHandshakeAndAuth(
        identity: AndroidDeviceIdentity,
        db: LinkBridgeDatabase,
        pinOrSecret: String?
    ) {
        val (ephKp, ephPubPem) = AeadChannelCipher.generateEphemeralEcdh()
        val clientNonce = CryptoUtils.randomHex(16)
        val hello = JSONObject().apply {
            put("device_id", identity.deviceId)
            put("device_name", identity.deviceName)
            put("platform", "Android")
            put("cert_pem", identity.publicPem)
            put("fingerprint", identity.fingerprintSha256)
            put("transport", route.name)
            put("client_nonce", clientNonce)
            put("ecdh_pub", ephPubPem)
        }
        sendControl(ProtocolConstants.MSG_HELLO, hello)
        val ackFrame = readStreamFrame()
        if (ackFrame.header.msgType == ProtocolConstants.MSG_ERROR) {
            throw SecurityException(ackFrame.jsonBody().optString("reason", "Handshake rejected"))
        }
        if (ackFrame.header.msgType != ProtocolConstants.MSG_HELLO_ACK) {
            throw SecurityException("Expected HELLO_ACK from Windows PC")
        }
        val ack = ackFrame.jsonBody()
        val peerId = ack.getString("device_id")
        val peerName = ack.optString("device_name", "Windows-PC")
        val peerFp = ack.getString("fingerprint")
        val serverNonce = ack.getString("server_nonce")
        val peerEcdhPub = ack.getString("ecdh_pub")

        var storedLinkKeyHex = db.getPairedDeviceLinkKeyHex(peerId, peerFp)
        if (storedLinkKeyHex == null || !pinOrSecret.isNullOrBlank()) {
            val secret = pinOrSecret?.trim()
                ?: throw SecurityException("الجهاز غير مقترن؛ يرجى إدخال رمز الاقتران المكون من 6 أرقام أولًا")
            val msgToMac = "${identity.deviceId}|${identity.fingerprintSha256}|$peerId|$peerFp|$clientNonce:$serverNonce"
            val proofHmac = CryptoUtils.hmacSha256Hex(
                secret.toByteArray(StandardCharsets.UTF_8),
                msgToMac.toByteArray(StandardCharsets.UTF_8)
            )
            val pairReq = JSONObject().apply {
                put("device_id", identity.deviceId)
                put("proof_hmac", proofHmac)
            }
            sendControl(ProtocolConstants.MSG_PAIR_REQUEST, pairReq)
            val pairRespFrame = readStreamFrame()
            if (pairRespFrame.header.msgType != ProtocolConstants.MSG_PAIR_RESPONSE) {
                throw SecurityException("استجابة اقتران غير صالحة")
            }
            val pairResp = pairRespFrame.jsonBody()
            if (!pairResp.optBoolean("paired", false)) {
                throw SecurityException(pairResp.optString("reason", "تم رفض رمز الاقتران"))
            }
            val linkKeyBytes = CryptoUtils.deriveSharedLinkKey(secret, identity.fingerprintSha256, peerFp)
            storedLinkKeyHex = CryptoUtils.bytesToHex(linkKeyBytes)
            db.savePairedDevice(peerId, peerName, peerFp, storedLinkKeyHex)
        }

        val linkKey = CryptoUtils.hexToBytes(storedLinkKeyHex)
        val authMsg = "AUTH:${identity.deviceId}:$peerId:$clientNonce:$serverNonce"
        val authMac = CryptoUtils.hmacSha256Hex(linkKey, authMsg.toByteArray(StandardCharsets.UTF_8))
        val authReq = JSONObject().apply {
            put("device_id", identity.deviceId)
            put("auth_mac", authMac)
        }
        sendControl(ProtocolConstants.MSG_AUTH_SESSION, authReq)
        val authResFrame = readStreamFrame()
        if (authResFrame.header.msgType != ProtocolConstants.MSG_AUTH_RESULT) {
            throw SecurityException("استجابة مصادقة الجلسة غير صالحة")
        }
        val authRes = authResFrame.jsonBody()
        if (!authRes.optBoolean("authenticated", false)) {
            throw SecurityException(authRes.optString("reason", "تم رفض مصادقة الجلسة"))
        }

        this.peerDeviceId = peerId
        this.peerDeviceName = peerName
        this.peerFingerprint = peerFp
        this.sessionToken = authRes.getString("session_token")

        if (requireAead) {
            val transcript = "$clientNonce:$serverNonce:${identity.fingerprintSha256}:$peerFp"
                .toByteArray(StandardCharsets.UTF_8)
            this.aeadCipher = AeadChannelCipher.fromEcdhAndLinkKey(
                localKeyPair = ephKp,
                peerPubPem = peerEcdhPub,
                pairedLinkKey = linkKey,
                contextTranscript = transcript
            )
        }
    }

    fun startBackgroundDispatcher(onIncomingOperation: (ProtocolFrame) -> Unit) {
        if (dispatcherActive.getAndSet(true)) return
        val replyTypes = setOf(
            ProtocolConstants.MSG_CLIPBOARD_ACK,
            ProtocolConstants.MSG_FILE_ACCEPT,
            ProtocolConstants.MSG_FILE_REJECT,
            ProtocolConstants.MSG_FILE_VERIFY_RESULT,
            ProtocolConstants.MSG_PONG
        )
        thread(isDaemon = true) {
            while (isConnected && dispatcherActive.get()) {
                try {
                    val frame = readStreamFrame(maxPayloadBytes = maxOf(chunkSize * 2, 2 * 1024 * 1024))
                    if (replyTypes.contains(frame.header.msgType)) {
                        replyQueue.put(frame)
                    } else {
                        incomingQueue.put(frame)
                        if (frame.header.msgType == ProtocolConstants.MSG_CLIPBOARD_PUSH ||
                            frame.header.msgType == ProtocolConstants.MSG_FILE_OFFER ||
                            frame.header.msgType == ProtocolConstants.MSG_PING ||
                            frame.header.msgType == ProtocolConstants.MSG_REVOKE_PAIRING
                        ) {
                            thread(isDaemon = true) {
                                try {
                                    val nextOp = incomingQueue.poll(5, TimeUnit.SECONDS)
                                    if (nextOp != null) onIncomingOperation(nextOp)
                                } catch (_: Exception) {
                                }
                            }
                        }
                    }
                } catch (_: Exception) {
                    dispatcherActive.set(false)
                    break
                }
            }
        }
    }
}

class WifiTlsTransportAdapter(
    private val sslSocket: SSLSocket,
    isHotspot: Boolean = false
) : TransportAdapter(
    route = if (isHotspot) TransportRoute.WIFI_HOTSPOT else TransportRoute.WIFI_LAN,
    chunkSize = ProtocolConstants.WIFI_CHUNK_SIZE
) {
    override val isConnected: Boolean
        get() = sslSocket.isConnected && !sslSocket.isClosed

    override val inputStream: InputStream = BufferedInputStream(sslSocket.inputStream)
    override val outputStream: OutputStream = BufferedOutputStream(sslSocket.outputStream)

    override fun close() {
        try {
            sslSocket.close()
        } catch (_: Exception) {
        }
    }

    companion object {
        fun connect(host: String, port: Int, isHotspot: Boolean = false, timeoutMs: Int = 10000): WifiTlsTransportAdapter {
            val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
                override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            })
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(null, trustAll, SecureRandom())
            val sock = ctx.socketFactory.createSocket() as SSLSocket
            sock.connect(InetSocketAddress(host, port), timeoutMs)
            sock.startHandshake()
            return WifiTlsTransportAdapter(sock, isHotspot = isHotspot)
        }
    }
}

class BluetoothRfcommTransportAdapter(
    private val btSocket: BluetoothSocket
) : TransportAdapter(
    route = TransportRoute.BLUETOOTH_RFCOMM,
    chunkSize = ProtocolConstants.BT_CHUNK_SIZE
) {
    override val requireAead: Boolean = true

    override val isConnected: Boolean
        get() = btSocket.isConnected

    override val inputStream: InputStream = BufferedInputStream(btSocket.inputStream)
    override val outputStream: OutputStream = BufferedOutputStream(btSocket.outputStream)

    override fun close() {
        try {
            btSocket.close()
        } catch (_: Exception) {
        }
    }

    companion object {
        fun getPairedDevices(adapter: BluetoothAdapter?): List<BluetoothDevice> {
            if (adapter == null || !adapter.isEnabled) return emptyList()
            return try {
                adapter.bondedDevices?.toList() ?: emptyList()
            } catch (_: SecurityException) {
                emptyList()
            }
        }

        fun connectToPairedDevice(device: BluetoothDevice): BluetoothRfcommTransportAdapter {
            val sock = device.createRfcommSocketToServiceRecord(ProtocolConstants.BT_SERVICE_UUID)
            sock.connect()
            return BluetoothRfcommTransportAdapter(sock)
        }
    }
}
