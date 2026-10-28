package com.anded.v380.proto

import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioTrack
import android.media.MediaCodec
import android.media.MediaFormat
import android.view.Surface
import com.anded.v380.I18n
import java.nio.ByteBuffer
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.thread
import kotlin.concurrent.withLock

/**
 * Просмотр записи во время загрузки (как playThread в v380gui.cpp). Камера отдаёт кадры быстрее
 * реального времени; они копятся в очередях и выдаются по своим меткам времени: видео — в MediaCodec,
 * который рисует на [setSurface], звук A-law → PCM — в AudioTrack. Часы стартуют, когда накоплена
 * секунда видео (или загрузка кончилась); если видео в очереди нет, а загрузка идёт, часы стоят.
 */
class StreamPlayer : Replay.FrameSink {
    private val lock = ReentrantLock()
    private val cond = lock.newCondition()
    private val vq = ArrayDeque<Replay.Frame>()
    private val aq = ArrayDeque<Replay.Frame>()
    private var surface: Surface? = null
    private var sampleRate = 16000

    /** Загрузка с камеры закончилась — дальше идёт только сборка mp4. */
    @Volatile var loaded = false
        private set

    @Volatile private var stopped = false

    // Колбэки вызываются из рабочих потоков.
    var onPlaying: (() -> Unit)? = null
    var onSize: ((Int, Int) -> Unit)? = null
    /** Запись доиграла (error == null) или просмотр прервался с ошибкой; после [release] не вызывается. */
    var onEnded: ((error: String?) -> Unit)? = null

    init {
        thread(name = "v380-stream", isDaemon = true) { work() }
    }

    override fun onFormat(sampleRate: Int) = lock.withLock { this.sampleRate = sampleRate }

    override fun onFrame(f: Replay.Frame) = lock.withLock {
        if (f.type == 4) aq.addLast(f) else if (f.type == 1 || f.type == 2) vq.addLast(f)
        cond.signalAll()
    }

    override fun onEnd() = lock.withLock {
        loaded = true
        cond.signalAll()
    }

    fun setSurface(s: Surface?) = lock.withLock {
        surface = s
        cond.signalAll()
    }

    fun release() {
        stopped = true
        lock.withLock { cond.signalAll() }
    }

    /** Ждёт поверхность, первый ключевой кадр и секунду видео; null — просмотр остановлен. */
    private fun waitStart(): Pair<Surface, Replay.Frame>? = lock.withLock {
        while (!stopped) {
            while (vq.isNotEmpty() && vq.first().type != 1) vq.removeFirst()
            val s = surface
            if (s != null && vq.isNotEmpty() && (loaded || vq.last().tsMs - vq.first().tsMs >= 1000)) return s to vq.first()
            if (loaded && vq.isEmpty()) throw CameraException(I18n.s.noFrames)
            cond.await(50, TimeUnit.MILLISECONDS)
        }
        null
    }

    private fun work() {
        var codec: MediaCodec? = null
        var track: AudioTrack? = null
        var drain: Thread? = null
        var error: String? = null
        try {
            val (s, first) = waitStart() ?: return
            val base = first.tsMs

            val fmt = MediaFormat.createVideoFormat(MediaFormat.MIMETYPE_VIDEO_AVC, 1280, 720)
            fmt.setInteger(MediaFormat.KEY_MAX_INPUT_SIZE, 1 shl 20)
            val nals = Replay.nals(first.data)
            val sps = nals.firstOrNull { it[0].toInt() and 0x1f == 7 }
            val pps = nals.firstOrNull { it[0].toInt() and 0x1f == 8 }
            if (sps != null && pps != null) {
                fmt.setByteBuffer("csd-0", ByteBuffer.wrap(SC + sps))
                fmt.setByteBuffer("csd-1", ByteBuffer.wrap(SC + pps))
            }
            val c = MediaCodec.createDecoderByType(MediaFormat.MIMETYPE_VIDEO_AVC)
            codec = c
            c.configure(fmt, s, null, 0)
            c.start()
            drain = thread(name = "v380-stream-out", isDaemon = true) { drainLoop(c) }

            val rate = lock.withLock { sampleRate }
            val minBuf = AudioTrack.getMinBufferSize(rate, AudioFormat.CHANNEL_OUT_MONO, AudioFormat.ENCODING_PCM_16BIT)
            val t = AudioTrack.Builder()
                .setAudioAttributes(
                    AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_MEDIA)
                        .setContentType(AudioAttributes.CONTENT_TYPE_MOVIE).build(),
                )
                .setAudioFormat(
                    AudioFormat.Builder().setSampleRate(rate).setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
                        .setEncoding(AudioFormat.ENCODING_PCM_16BIT).build(),
                )
                .setBufferSizeInBytes(maxOf(minBuf, rate)) // около 0,5 с
                .setTransferMode(AudioTrack.MODE_STREAM)
                .build()
            track = t
            t.play()

            var clock = base.toDouble()
            var last = System.nanoTime()
            var lastPts = -1L
            while (!stopped) {
                var v: Replay.Frame? = null
                var a: Replay.Frame? = null
                var end = false
                lock.withLock {
                    val now = System.nanoTime()
                    if (vq.isNotEmpty() || loaded) clock += (now - last) / 1e6
                    last = now
                    when {
                        vq.isNotEmpty() && vq.first().tsMs <= clock -> v = vq.removeFirst()
                        aq.isNotEmpty() && aq.first().tsMs <= clock -> a = aq.removeFirst()
                        loaded && vq.isEmpty() && aq.isEmpty() -> end = true
                        else -> cond.await(5, TimeUnit.MILLISECONDS)
                    }
                    Unit
                }
                if (end) break
                v?.let { lastPts = feed(c, it.data, maxOf(lastPts + 1, (it.tsMs - base) * 1000), 0) }
                a?.let {
                    if (it.tsMs >= base) {
                        val pcm = Replay.alawToPcm(it.data)
                        t.write(pcm, 0, pcm.size)
                    }
                }
            }
            if (!stopped) {
                feed(c, ByteArray(0), lastPts + 1, MediaCodec.BUFFER_FLAG_END_OF_STREAM)
                drain.join()
            }
        } catch (e: Exception) {
            error = (e as? CameraException)?.message ?: e.message ?: e.javaClass.simpleName
        } finally {
            val byUser = stopped
            stopped = true
            drain?.join(1000)
            try { codec?.stop() } catch (_: Exception) {}
            codec?.release()
            track?.release()
            if (!byUser) onEnded?.invoke(error)
        }
    }

    private fun feed(c: MediaCodec, data: ByteArray, pts: Long, flags: Int): Long {
        while (!stopped) {
            val i = c.dequeueInputBuffer(10_000)
            if (i < 0) continue
            c.getInputBuffer(i)!!.apply { clear(); put(data) }
            c.queueInputBuffer(i, 0, data.size, pts, flags)
            break
        }
        return pts
    }

    /** Кадры с декодера сразу на экран: на вход они уже подаются по часам. */
    private fun drainLoop(c: MediaCodec) {
        val info = MediaCodec.BufferInfo()
        var shown = false
        try {
            while (!stopped) {
                val i = c.dequeueOutputBuffer(info, 20_000)
                if (i == MediaCodec.INFO_OUTPUT_FORMAT_CHANGED) {
                    val f = c.outputFormat
                    val w = if (f.containsKey("crop-right")) f.getInteger("crop-right") - f.getInteger("crop-left") + 1
                    else f.getInteger(MediaFormat.KEY_WIDTH)
                    val h = if (f.containsKey("crop-bottom")) f.getInteger("crop-bottom") - f.getInteger("crop-top") + 1
                    else f.getInteger(MediaFormat.KEY_HEIGHT)
                    onSize?.invoke(w, h)
                } else if (i >= 0) {
                    c.releaseOutputBuffer(i, info.size > 0)
                    if (!shown && info.size > 0) {
                        shown = true
                        onPlaying?.invoke()
                    }
                    if (info.flags and MediaCodec.BUFFER_FLAG_END_OF_STREAM != 0) break
                }
            }
        } catch (_: IllegalStateException) {
            // декодер остановлен из work()
        }
    }

    private companion object {
        val SC = byteArrayOf(0, 0, 0, 1)
    }
}
