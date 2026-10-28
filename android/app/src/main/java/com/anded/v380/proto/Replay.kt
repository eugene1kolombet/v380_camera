package com.anded.v380.proto

import com.anded.v380.I18n
import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaFormat
import android.media.MediaMuxer
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer

/** Скачивание записи с SD-карты: REPLAY_CTRL 197154 по управляющей сессии → H.264 + G.711A → mp4. */
object Replay {
    class Progress(val videoFrames: Int, val audioFrames: Int, val fraction: Float?)

    /** Расшифрованный кадр: тип (1 — I, 2 — P, 4 — аудио), данные, время кадра в мс (байты 10..15 заголовка). */
    class Frame(val type: Int, val data: ByteArray, val tsMs: Long)

    /** Получатель кадров во время загрузки (просмотр по мере скачивания). Вызывается из рабочего потока. */
    interface FrameSink {
        fun onFormat(sampleRate: Int)
        fun onFrame(f: Frame)
        /** Загрузка с камеры закончилась (или прервалась). */
        fun onEnd()
    }

    /**
     * Скачивает сегмент в [out] (mp4). [onProgress] вызывается из рабочего потока.
     * [cancelled] проверяется между пакетами. [sink] получает каждый кадр сразу после расшифровки.
     */
    fun download(
        ip: String,
        password: String,
        seg: V380Session.Segment,
        out: File,
        sink: FrameSink?,
        cancelled: () -> Boolean,
        onProgress: (Progress) -> Unit,
    ) {
        val tmpVideo = File(out.path + ".h264")
        val frames = ArrayList<LongArray>() // [смещение, длина, ключевой, время мс]
        val audio = ByteArrayOutputStream()
        var width = 1280
        var height = 720
        var sampleRate = 16000
        var na = 0
        var audioTs = -1L
        try {
            V380Session.open(ip, password).use { ss ->
                RandomAccessFile(tmpVideo, "rw").use { vf ->
                    vf.setLength(0)
                    val req = { p: String -> ss.send(V380Session.M_REPLAY, p) }
                    req("{\"pts\":${seg.startMs},\"sts\":${seg.startMs},\"rtype\":${seg.type},\"time_id\":1,\"vsspec\":0,\"frames\":1000,\"video\":1,\"audio\":1}")
                    val limitMs = System.currentTimeMillis() + seg.durationMs + 15000
                    var done = false
                    while (!done && !cancelled() && System.currentTimeMillis() < limitMs) {
                        val p = try { ss.read() } catch (e: java.net.SocketTimeoutException) { break }
                        when (p.cmd) {
                            V380Session.CMD_MEDIA -> {
                                val f = frameDecrypt(p.body, ss.key) ?: continue
                                sink?.onFrame(f)
                                if (f.type == 1 || f.type == 2) {
                                    frames += longArrayOf(vf.filePointer, f.data.size.toLong(), if (f.type == 1) 1 else 0, f.tsMs)
                                    vf.write(f.data)
                                } else if (f.type == 4) {
                                    if (audioTs < 0) audioTs = f.tsMs
                                    audio.write(f.data); na++
                                }
                                if ((frames.size + na) % 20 == 0 && frames.isNotEmpty()) {
                                    val frac = if (seg.durationMs > 0)
                                        ((frames.last()[3] - seg.startMs).toFloat() / seg.durationMs).coerceIn(0f, 1f) else null
                                    onProgress(Progress(frames.size, na, frac))
                                }
                            }
                            V380Session.CMD_NOTIFY -> {
                                val par = p.json?.optJSONObject("params") ?: continue
                                when (par.optInt("info_id")) {
                                    1 -> {
                                        par.optJSONObject("vattr")?.let {
                                            width = it.optInt("width", width); height = it.optInt("height", height)
                                        }
                                        par.optJSONObject("aattr")?.let { sampleRate = it.optInt("samplerate", sampleRate) }
                                        sink?.onFormat(sampleRate)
                                    }
                                    3 -> done = true
                                    4 -> req("{\"time_id\":1,\"frames\":1000}")
                                }
                            }
                            V380Session.CMD_IOT -> {
                                val code = p.json?.optJSONObject("result")?.optInt("code", 1000) ?: 1000
                                if (code != 1000 && frames.isEmpty()) throw CameraException(I18n.s.noRecording(code))
                            }
                        }
                    }
                }
            }
        } finally {
            sink?.onEnd()
        }
        try {
            if (cancelled()) throw CameraException(I18n.s.cancelled)
            if (frames.isEmpty()) throw CameraException(I18n.s.noFrames)
            onProgress(Progress(frames.size, na, 1f))
            val pcm = alawToPcm(audio.toByteArray())
            val mediaUs = if (pcm.isNotEmpty()) pcm.size / 2 * 1_000_000L / sampleRate
            else if (seg.durationMs > 0) seg.durationMs * 1000 else frames.size * 66_666L
            mux(tmpVideo, frames, width, height, mediaUs, pcm, sampleRate, audioTs, out)
        } finally {
            tmpVideo.delete()
        }
    }

    /**
     * Расшифровка MEDIA-кадра (как frameDecrypt в v380gui.cpp): 32 байта заголовка — AES-CBC
     * (IV = key[16:32]); затем plen открытых байт и циклы [elen шифр + slen открытых], цепочка
     * CBC продолжается от заголовка.
     */
    fun frameDecrypt(body: ByteArray, key: ByteArray): Frame? {
        val len = body.size
        if (len < 32) return null
        val hdr = Crypto.cbc(false, key, key.copyOfRange(16, 32), body, 0, 32)
        var prev = body.copyOfRange(16, 32)
        val ftype = hdr[1].toInt() and 0xff
        var ts = 0L
        for (k in 15 downTo 10) ts = (ts shl 8) or (hdr[k].toLong() and 0xff)
        val plen = rd32(hdr, 0x12).toLong() and 0xffffffffL
        val elen = rd32(hdr, 0x16).toLong() and 0xffffffffL
        val slen = rd32(hdr, 0x1a).toLong() and 0xffffffffL
        val o = ByteArrayOutputStream(len)
        var pos = 32
        var rem = (len - 32).toLong()
        if (plen <= rem) {
            o.write(body, pos, plen.toInt()); pos += plen.toInt(); rem -= plen
        } else {
            o.write(body, pos, rem.toInt()); return Frame(ftype, o.toByteArray(), ts)
        }
        while (elen > 0 && rem >= elen) {
            val full = (elen / 16 * 16).toInt()
            if (full > 0) {
                o.write(Crypto.cbc(false, key, prev, body, pos, full))
                prev = body.copyOfRange(pos + full - 16, pos + full)
            }
            pos += elen.toInt(); rem -= elen
            val sk = minOf(rem, slen).toInt()
            o.write(body, pos, sk); pos += sk; rem -= sk
        }
        if (rem > 0) o.write(body, pos, rem.toInt())
        return Frame(ftype, o.toByteArray(), ts)
    }

    // ---------- G.711 A-law ----------

    private fun alaw(a0: Int): Int {
        val a = a0 xor 0x55
        var t = (a and 0x0f) shl 4
        when (val seg = (a and 0x70) shr 4) {
            0 -> t += 8
            1 -> t += 0x108
            else -> { t += 0x108; t = t shl (seg - 1) }
        }
        return if (a and 0x80 != 0) t else -t
    }

    private val ALAW = IntArray(256) { alaw(it) }

    /** A-law → PCM 16 бит LE. */
    fun alawToPcm(a: ByteArray): ByteArray {
        val o = ByteArray(a.size * 2)
        for (i in a.indices) {
            val v = ALAW[a[i].toInt() and 0xff]
            o[2 * i] = v.toByte(); o[2 * i + 1] = (v shr 8).toByte()
        }
        return o
    }

    // ---------- H.264 Annex-B ----------

    /** NAL-единицы без старт-кодов. */
    fun nals(d: ByteArray): List<ByteArray> {
        val starts = ArrayList<Int>() // индекс первого байта NAL
        var i = 0
        while (i + 3 <= d.size) {
            if (d[i].toInt() == 0 && d[i + 1].toInt() == 0 && d[i + 2].toInt() == 1) {
                starts += i + 3; i += 3
            } else i++
        }
        val res = ArrayList<ByteArray>()
        for ((k, s) in starts.withIndex()) {
            var e = if (k + 1 < starts.size) starts[k + 1] - 3 else d.size
            while (e > s && k + 1 < starts.size && d[e - 1].toInt() == 0) e--
            if (e > s) res += d.copyOfRange(s, e)
        }
        return res
    }

    private val SC = byteArrayOf(0, 0, 0, 1)

    // ---------- mp4 ----------

    private fun mux(
        videoFile: File, frames: List<LongArray>, width: Int, height: Int, mediaUs: Long,
        pcm: ByteArray, sampleRate: Int, audioTs: Long, out: File,
    ) {
        var sps: ByteArray? = null
        var pps: ByteArray? = null
        RandomAccessFile(videoFile, "r").use { vf ->
            for (f in frames) {
                if (f[2] == 0L) continue
                val b = ByteArray(f[1].toInt()); vf.seek(f[0]); vf.readFully(b)
                for (n in nals(b)) when (n[0].toInt() and 0x1f) {
                    7 -> if (sps == null) sps = n
                    8 -> if (pps == null) pps = n
                }
                if (sps != null && pps != null) break
            }
        }
        if (sps == null || pps == null) throw CameraException(I18n.s.noSpsPps)
        val vfmt = MediaFormat.createVideoFormat(MediaFormat.MIMETYPE_VIDEO_AVC, width, height)
        vfmt.setByteBuffer("csd-0", ByteBuffer.wrap(SC + sps!!))
        vfmt.setByteBuffer("csd-1", ByteBuffer.wrap(SC + pps!!))

        // Время кадров из заголовков; если оно не растёт или не сходится с длиной — равномерно по mediaUs.
        val nv = frames.size
        val base = frames[0][3]
        val span = frames[nv - 1][3] - base
        val useTs = span > 0 && span * 1000 <= mediaUs * 2 + 5_000_000 &&
            (1 until nv).all { frames[it][3] >= frames[it - 1][3] }
        val audioOffUs = if (useTs && audioTs >= base && audioTs - base < 10_000) (audioTs - base) * 1000 else 0L
        val aac = if (pcm.isNotEmpty()) encodeAac(pcm, sampleRate, audioOffUs) else null

        val tmpOut = File(out.path + ".part")
        val muxer = MediaMuxer(tmpOut.path, MediaMuxer.OutputFormat.MUXER_OUTPUT_MPEG_4)
        try {
            val vt = muxer.addTrack(vfmt)
            val at = aac?.let { muxer.addTrack(it.first) } ?: -1
            muxer.start()
            val info = MediaCodec.BufferInfo()
            var ai = 0
            var lastPts = -1L
            RandomAccessFile(videoFile, "r").use { vf ->
                val started = frames.indexOfFirst { it[2] == 1L }.coerceAtLeast(0)
                for (i in started until nv) {
                    val f = frames[i]
                    var pts = if (useTs) (f[3] - base) * 1000 else i * mediaUs / nv
                    if (pts <= lastPts) pts = lastPts + 1
                    lastPts = pts
                    if (aac != null) while (ai < aac.second.size && aac.second[ai].second <= pts) {
                        val (d, apts) = aac.second[ai++]
                        info.set(0, d.size, apts, 0)
                        muxer.writeSampleData(at, ByteBuffer.wrap(d), info)
                    }
                    val b = ByteArray(f[1].toInt()); vf.seek(f[0]); vf.readFully(b)
                    val sample = ByteArrayOutputStream(b.size + 16)
                    for (n in nals(b)) {
                        val t = n[0].toInt() and 0x1f
                        if (t == 7 || t == 8 || t == 9) continue
                        sample.write(SC); sample.write(n)
                    }
                    if (sample.size() == 0) continue
                    val sb = sample.toByteArray()
                    info.set(0, sb.size, pts, if (f[2] == 1L) MediaCodec.BUFFER_FLAG_KEY_FRAME else 0)
                    muxer.writeSampleData(vt, ByteBuffer.wrap(sb), info)
                }
            }
            if (aac != null) while (ai < aac.second.size) {
                val (d, apts) = aac.second[ai++]
                info.set(0, d.size, apts, 0)
                muxer.writeSampleData(at, ByteBuffer.wrap(d), info)
            }
            muxer.stop()
        } finally {
            muxer.release()
        }
        out.delete()
        if (!tmpOut.renameTo(out)) throw CameraException(I18n.s.saveFileFailed)
    }

    /** PCM 16 бит моно → AAC-LC: формат дорожки и кадры с pts (мкс), сдвинутыми на [offsetUs]. */
    private fun encodeAac(pcm: ByteArray, sampleRate: Int, offsetUs: Long): Pair<MediaFormat, List<Pair<ByteArray, Long>>> {
        val fmt = MediaFormat.createAudioFormat(MediaFormat.MIMETYPE_AUDIO_AAC, sampleRate, 1)
        fmt.setInteger(MediaFormat.KEY_AAC_PROFILE, MediaCodecInfo.CodecProfileLevel.AACObjectLC)
        fmt.setInteger(MediaFormat.KEY_BIT_RATE, 48000)
        fmt.setInteger(MediaFormat.KEY_MAX_INPUT_SIZE, 16384)
        val enc = MediaCodec.createEncoderByType(MediaFormat.MIMETYPE_AUDIO_AAC)
        val res = ArrayList<Pair<ByteArray, Long>>()
        var outFmt: MediaFormat? = null
        try {
            enc.configure(fmt, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
            enc.start()
            val info = MediaCodec.BufferInfo()
            var inPos = 0
            var inDone = false
            var outDone = false
            while (!outDone) {
                if (!inDone) {
                    val ii = enc.dequeueInputBuffer(10_000)
                    if (ii >= 0) {
                        val buf = enc.getInputBuffer(ii)!!
                        buf.clear()
                        val n = minOf(buf.remaining() / 2 * 2, 4096, pcm.size - inPos)
                        val pts = offsetUs + inPos / 2 * 1_000_000L / sampleRate
                        if (n <= 0) {
                            enc.queueInputBuffer(ii, 0, 0, pts, MediaCodec.BUFFER_FLAG_END_OF_STREAM)
                            inDone = true
                        } else {
                            buf.put(pcm, inPos, n)
                            enc.queueInputBuffer(ii, 0, n, pts, 0)
                            inPos += n
                        }
                    }
                }
                val oi = enc.dequeueOutputBuffer(info, 10_000)
                when {
                    oi == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED -> outFmt = enc.outputFormat
                    oi >= 0 -> {
                        if (info.flags and MediaCodec.BUFFER_FLAG_CODEC_CONFIG == 0 && info.size > 0) {
                            val b = enc.getOutputBuffer(oi)!!
                            val d = ByteArray(info.size)
                            b.position(info.offset); b.get(d)
                            res += d to info.presentationTimeUs
                        }
                        if (info.flags and MediaCodec.BUFFER_FLAG_END_OF_STREAM != 0) outDone = true
                        enc.releaseOutputBuffer(oi, false)
                    }
                }
            }
            enc.stop()
        } finally {
            enc.release()
        }
        return (outFmt ?: throw CameraException(I18n.s.aacNoFormat)) to res
    }
}
