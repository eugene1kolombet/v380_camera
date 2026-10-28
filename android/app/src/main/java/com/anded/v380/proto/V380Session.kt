package com.anded.v380.proto

import com.anded.v380.I18n
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.Closeable
import java.io.DataInputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.util.TimeZone

class CameraException(msg: String) : IOException(msg)

/**
 * Управляющая сессия с камерой V380 по TCP 8089 (протокол — client/PROTOCOL_NOTES.md,
 * эталон — gui/v380gui.cpp). Одна сессия = одно соединение после входа LANPASS.
 */
class V380Session private constructor(private val sock: Socket) : Closeable {
    private val inp = DataInputStream(BufferedInputStream(sock.getInputStream(), 1 shl 16))
    private val out = sock.getOutputStream()

    /** X25519-секрет сессии: AES-ключ = key[0:16], IV = key[16:32]. */
    var key: ByteArray = HK
        private set
    var sid = 0
        private set

    class Packet(val cmd: Int, val body: ByteArray, val json: JSONObject?)

    companion object {
        const val DEFAULT_PORT = 8089

        /** Управляющий порт камеры; задаётся в приложении (поле «Port»). */
        @Volatile var port = DEFAULT_PORT
        const val CMD_IOT = 939722776
        const val CMD_MEDIA = 939722784
        const val CMD_NOTIFY = 939722786

        const val M_LANPASS = 196870
        const val M_RECLIST = 197152
        const val M_REPLAY = 197154
        const val M_GETPROP = 197376
        const val M_SETPROP = 197378
        const val M_ACTION = 197384

        const val DAID_NET = (4L shl 16) or 512
        const val DPID_NET_MODE = (4L shl 16) or 256 or 1
        const val DPID_NET_SSID = (4L shl 16) or 256 or 4
        const val DPID_RECMODE = (2L shl 16) or 256 or 3
        const val DPID_ALARM_MAIN = (10L shl 16) or 256 or 0
        const val DPID_ALARM_MT = (10L shl 16) or 256 or 4
        const val DPID_ALARM_TIMER = (10L shl 16) or 256 or 5
        const val DPID_ONVIF = (15L shl 16) or 256 or 0
        const val DPID_RTSP_AUDIO = (15L shl 16) or 256 or 1

        private val HK = byteArrayOf(
            54, 58, 229.toByte(), 40, 22, 56, 207.toByte(), 132.toByte(), 150.toByte(), 154.toByte(), 99, 78,
            159.toByte(), 150.toByte(), 106, 152.toByte(), 181.toByte(), 115, 209.toByte(), 255.toByte(),
            233.toByte(), 55, 178.toByte(), 119, 209.toByte(), 241.toByte(), 214.toByte(), 43, 56, 116,
            138.toByte(), 229.toByte(),
        )

        fun open(ip: String, password: String, connectTimeoutMs: Int = 5000): V380Session {
            val s = Socket()
            try {
                s.connect(InetSocketAddress(ip, port), connectTimeoutMs)
                s.soTimeout = 8000
                s.tcpNoDelay = true
            } catch (e: IOException) {
                s.close()
                throw CameraException(I18n.s.noConnection("$ip:$port"))
            }
            val ss = V380Session(s)
            try {
                ss.login(password)
            } catch (e: Exception) {
                ss.close()
                throw if (e is CameraException) e else CameraException(I18n.s.loginFailed(e.message))
            }
            return ss
        }

        private fun tz(): String {
            val off = TimeZone.getDefault().getOffset(System.currentTimeMillis()) / 60000
            return String.format("%+03d:%02d", off / 60, Math.abs(off) % 60)
        }

        /** org.json экранирует «/» как «\/» — камере это не нужно, а base64 содержит «/». */
        fun js(o: Any): String = o.toString().replace("\\/", "/")
    }

    override fun close() {
        try { sock.close() } catch (_: IOException) {}
    }

    // ---------- пакеты ----------

    fun send(method: Int, params: String, k: ByteArray = key, b2: Int = sid, b3: Int = 0) {
        val id = Crypto.rnd.nextInt() and 0x7fffffff
        val js = "{\"id\":$id,\"method_id\":$method,\"chn\":1,\"ts\":${System.currentTimeMillis() / 1000},\"params\":$params}"
        val enc = Crypto.cbc(true, k, k.copyOfRange(16, 32), Crypto.pkcs7pad(js.toByteArray()))
        val pkt = ByteArray(16 + enc.size)
        le32(pkt, 0, CMD_IOT)
        pkt[4] = 1; pkt[5] = 2; pkt[6] = b2.toByte(); pkt[7] = b3.toByte()
        le32(pkt, 12, enc.size)
        System.arraycopy(enc, 0, pkt, 16, enc.size)
        synchronized(out) { out.write(pkt); out.flush() }
    }

    fun read(k: ByteArray = key): Packet {
        val h = ByteArray(16)
        inp.readFully(h)
        val cmd = rd32(h, 0)
        val len = rd32(h, 12)
        if (len < 0 || len > (8 shl 20)) throw CameraException(I18n.s.badPacketLength(len))
        val body = ByteArray(len)
        inp.readFully(body)
        var json: JSONObject? = null
        if ((cmd == CMD_IOT || cmd == CMD_NOTIFY) && len > 0 && len % 16 == 0) {
            val d = Crypto.pkcs7unpad(Crypto.cbc(false, k, k.copyOfRange(16, 32), body))
            json = try { JSONObject(String(d)) } catch (_: Exception) { null }
        }
        return Packet(cmd, body, json)
    }

    /** Запрос и первый IoT-ответ на него (NOTIFY/MEDIA по пути пропускаются). */
    fun request(method: Int, params: String): JSONObject {
        send(method, params)
        while (true) {
            val p = read()
            if (p.cmd == CMD_IOT && p.json != null) return p.json
        }
    }

    // ---------- вход ----------

    private fun login(password: String) {
        val al = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        val seed = ByteArray(32) { al[Crypto.rnd.nextInt(62)].code.toByte() }
        val pub = Crypto.x25519Base(seed)
        val magic = Crypto.rnd.nextInt(256)
        val px = ByteArray(32) { (pub[it].toInt() xor magic).toByte() }
        val cS = Crypto.b64(Crypto.sha256(px + password.toByteArray()))
        val params = "{\"act\":1,\"verify\":{\"cKM\":\"${Crypto.b64(px)}\",\"cS\":\"$cS\",\"tz\":\"${tz()}\",\"ts\":${System.currentTimeMillis() / 1000}}}"
        send(M_LANPASS, params, HK, 0, magic)
        val rp = read(HK)
        val ver = rp.json?.optJSONObject("data")?.optJSONObject("verify")
        val dK = ver?.optString("dK", "")?.takeIf { it.isNotEmpty() }
            ?: throw CameraException(I18n.s.loginRejected)
        val dk = Crypto.unb64(dK)
        if (dk.size < 32) throw CameraException(I18n.s.badLoginResponse)
        key = Crypto.x25519(seed, dk)
        sid = ver.optInt("sid", 0)
    }

    // ---------- свойства ----------

    /** Значения свойств: Boolean / Number / String / JSONObject; свойства с ошибкой не попадают. */
    fun getProps(vararg dpids: Long): Map<Long, Any> {
        val r = request(M_GETPROP, "{\"dplist\":${JSONArray(dpids.toList())}}")
        val res = mutableMapOf<Long, Any>()
        val dl = r.optJSONObject("data")?.optJSONArray("dplist_result") ?: return res
        for (i in 0 until dl.length()) {
            val it = dl.optJSONObject(i) ?: continue
            if (it.optInt("code", 1000) != 1000 || !it.has("value")) continue
            res[it.optLong("dpid")] = it.get("value")
        }
        return res
    }

    fun getInt(dpid: Long): Int = when (val v = getProps(dpid)[dpid]) {
        is Boolean -> if (v) 1 else 0
        is Number -> v.toInt()
        else -> -1
    }

    fun setProps(values: List<Pair<Long, Any>>) {
        val arr = JSONArray()
        for ((dpid, v) in values) arr.put(JSONObject().put("dpid", dpid).put("value", v))
        val r = request(M_SETPROP, "{\"dplist\":${js(arr)}}")
        val code = r.optJSONObject("result")?.optInt("code", 0) ?: 0
        if (code != 1000) throw CameraException(I18n.s.cameraRefused(code))
        val dl = r.optJSONObject("data")?.optJSONArray("dplist_result") ?: return
        for (i in 0 until dl.length()) {
            val c = dl.optJSONObject(i)?.optInt("code", 1000) ?: 1000
            if (c != 1000) throw CameraException(I18n.s.propertyRejected(dl.optJSONObject(i)?.optLong("dpid"), c))
        }
    }

    // ---------- режим записи ----------

    /** mode 1 — постоянно, 2 — по движению (с тревогой, детектором движения и круглосуточным расписанием). */
    fun setRecordMode(mode: Int) {
        if (mode == 2) {
            val day = JSONObject("{\"cnt\":1,\"sche\":[{\"enable\":true,\"mode\":1,\"s_time\":\"0:0:0\",\"e_time\":\"23:59:59\"}]}")
            val timer = JSONObject()
            for (d in listOf("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")) timer.put(d, day)
            setProps(listOf(DPID_ALARM_TIMER to timer, DPID_ALARM_MT to true, DPID_ALARM_MAIN to true, DPID_RECMODE to 2))
        } else {
            setProps(listOf(DPID_ALARM_MAIN to false, DPID_RECMODE to 1))
        }
    }

    // ---------- записи ----------

    data class Segment(val startMs: Long, val durationMs: Long, val type: Int)

    fun listRecordings(): List<Segment> {
        val now = System.currentTimeMillis()
        val st = now - 3650L * 24 * 3600 * 1000
        send(M_RECLIST, "{\"filter\":15,\"mode\":2,\"start\":$st,\"end\":$now}")
        val out = ArrayList<Segment>()
        while (true) {
            val p = read()
            if (p.cmd != CMD_IOT) continue
            val data = p.json?.optJSONObject("data") ?: break
            val lst = data.optJSONArray("list")
            if (lst != null) for (i in 0 until lst.length()) {
                val it = lst.optJSONObject(i) ?: continue
                out += Segment(st + it.optLong("s"), it.optLong("d"), it.optInt("t"))
            }
            if (data.optInt("flag", 0) == 0) break
        }
        return out
    }

    // ---------- сеть ----------

    /** Передать камере Wi-Fi сеть. mode 2 — камера уже в сети, mode 1 — камера в режиме точки доступа. */
    fun setWifi(ssid: String, pwd: String, mode: Int = 2) {
        val inner = "{\"mode\":$mode,\"ssid\":\"${Crypto.b64(ssid.toByteArray())}\",\"pwd\":\"${Crypto.b64(pwd.toByteArray())}\"}"
        val r = request(M_ACTION, "{\"daid\":$DAID_NET,\"in\":$inner}")
        val code = r.optJSONObject("result")?.optInt("code", 1000) ?: 1000
        if (code != 1000 && code != 0) throw CameraException(I18n.s.cameraRefused(code))
    }

    // ---------- низкий уровень ----------

    private fun le32(b: ByteArray, o: Int, v: Int) {
        b[o] = v.toByte(); b[o + 1] = (v shr 8).toByte(); b[o + 2] = (v shr 16).toByte(); b[o + 3] = (v shr 24).toByte()
    }
}

internal fun rd32(b: ByteArray, o: Int): Int =
    (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8) or
        ((b[o + 2].toInt() and 0xff) shl 16) or ((b[o + 3].toInt() and 0xff) shl 24)
