package com.anded.v380.proto

import android.util.Log
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.DataInputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Collections
import kotlin.concurrent.thread

private const val TAG = "RtspFixProxy"

/**
 * Локальный RTSP-прокси к камере, чинящий её H.264 по RTP.
 *
 * Камера шлёт SPS и PPS отдельными пакетами, а затем весь ключевой кадр (SPS + PPS + IDR со
 * старт-кодами внутри) одним FU-A с типом NAL 7. ffmpeg находит старт-коды внутри и декодирует,
 * а ExoPlayer не видит IDR (тип 5) и отбрасывает все кадры в ожидании ключевого. Прокси в первом
 * фрагменте такого FU-A отрезает повторные SPS/PPS и ставит тип IDR; остальное идёт как есть.
 */
class RtspFixProxy(private val host: String, private val camPort: Int = 554) : Closeable {
    private val server = ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"))
    private val sockets = Collections.synchronizedList(ArrayList<Socket>())

    val localPort: Int get() = server.localPort

    init {
        thread(isDaemon = true, name = "rtsp-proxy") {
            while (!server.isClosed) {
                val c = try { server.accept() } catch (_: IOException) { break }
                val r = try {
                    Socket().apply { connect(InetSocketAddress(host, camPort), 5000); tcpNoDelay = true }
                } catch (e: IOException) {
                    Log.w(TAG, "нет связи с $host:$camPort: $e")
                    c.close(); continue
                }
                c.tcpNoDelay = true
                sockets += c; sockets += r
                thread(isDaemon = true) { pump(c, r) }
                thread(isDaemon = true) { fixStream(r, c) }
            }
        }
    }

    override fun close() {
        try { server.close() } catch (_: IOException) {}
        synchronized(sockets) { sockets.forEach { try { it.close() } catch (_: IOException) {} } }
    }

    private fun pump(from: Socket, to: Socket) {
        try {
            val buf = ByteArray(16384)
            val i = from.getInputStream()
            val o = to.getOutputStream()
            while (true) {
                val n = i.read(buf)
                if (n < 0) break
                o.write(buf, 0, n)
            }
        } catch (_: IOException) {
        } finally {
            try { from.close() } catch (_: IOException) {}
            try { to.close() } catch (_: IOException) {}
        }
    }

    /** Поток от камеры: RTSP-ответы как есть, interleaved-кадры канала видео (0) — через [fixRtp]. */
    private fun fixStream(cam: Socket, client: Socket) {
        try {
            val i = DataInputStream(BufferedInputStream(cam.getInputStream(), 65536))
            val o = BufferedOutputStream(client.getOutputStream(), 65536)
            var fuType = -1
            while (true) {
                val b = i.read()
                if (b < 0) break
                if (b == '$'.code) {
                    val ch = i.readUnsignedByte()
                    val len = i.readUnsignedShort()
                    var p = ByteArray(len)
                    i.readFully(p)
                    if (ch == 0) {
                        val r = fixRtp(p, fuType)
                        p = r.first; fuType = r.second
                    }
                    o.write('$'.code); o.write(ch); o.write(p.size shr 8); o.write(p.size and 0xff); o.write(p)
                    if (i.available() == 0) o.flush()
                } else {
                    val head = ByteArrayOutputStream()
                    head.write(b)
                    var tail = 0
                    while (tail != 0x0d0a0d0a) {
                        val c = i.read()
                        if (c < 0) break
                        head.write(c)
                        tail = (tail shl 8) or c
                    }
                    val text = head.toString("ISO-8859-1")
                    val cl = Regex("(?i)Content-Length:\\s*(\\d+)").find(text)?.groupValues?.get(1)?.toInt() ?: 0
                    val body = ByteArray(cl)
                    i.readFully(body)
                    o.write(head.toByteArray()); o.write(body); o.flush()
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "поток от камеры: $e")
        } finally {
            try { cam.close() } catch (_: IOException) {}
            try { client.close() } catch (_: IOException) {}
        }
    }

    /** Возвращает исправленный пакет и тип NAL текущего FU-A (-1 — исправлять нечего). */
    private fun fixRtp(p: ByteArray, curType: Int): Pair<ByteArray, Int> {
        if (p.size < 14) return p to curType
        var off = 12 + 4 * (p[0].toInt() and 0x0f)
        if (p[0].toInt() and 0x10 != 0) {
            if (p.size < off + 4) return p to curType
            off += 4 + 4 * (((p[off + 2].toInt() and 0xff) shl 8) or (p[off + 3].toInt() and 0xff))
        }
        if (p.size < off + 2 || p[off].toInt() and 0x1f != 28) return p to curType
        val fu = p[off + 1].toInt() and 0xff
        val start = fu and 0x80 != 0
        val end = fu and 0x40 != 0
        if (start) {
            if (fu and 0x1f != 7) return p to -1
            // Последний старт-код внутри фрагмента — перед NAL кадра.
            var hdr = -1
            var k = off + 2
            while (k + 3 < p.size) {
                if (p[k].toInt() == 0 && p[k + 1].toInt() == 0 && p[k + 2].toInt() == 1) {
                    val t = p[k + 3].toInt() and 0x1f
                    if (t == 5 || t == 1) { hdr = k + 3; break }
                    k += 3
                } else k++
            }
            if (hdr < 0) return p to -1
            val nal = p[hdr].toInt() and 0xff
            val out = ByteArray(off + 2 + (p.size - hdr - 1))
            System.arraycopy(p, 0, out, 0, off)
            out[off] = ((nal and 0x60) or 28).toByte()
            out[off + 1] = (0x80 or (if (end) 0x40 else 0) or (nal and 0x1f)).toByte()
            System.arraycopy(p, hdr + 1, out, off + 2, p.size - hdr - 1)
            return out to (if (end) -1 else nal)
        }
        if (curType < 0) return p to -1
        p[off] = ((curType and 0x60) or 28).toByte()
        p[off + 1] = ((fu and 0xe0) or (curType and 0x1f)).toByte()
        return p to (if (end) -1 else curType)
    }
}
