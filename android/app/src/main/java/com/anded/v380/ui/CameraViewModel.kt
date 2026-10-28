package com.anded.v380.ui

import android.app.Application
import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Environment
import android.provider.MediaStore
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.anded.v380.I18n
import com.anded.v380.proto.CameraException
import com.anded.v380.proto.Discovery
import com.anded.v380.proto.Replay
import com.anded.v380.proto.V380Session
import com.anded.v380.proto.V380Session.Segment
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.isActive
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class CameraInfo(
    val recordMode: Int,
    val alarm: Int,
    val netMode: Int,
    val netSsid: String,
)

/** Состояние скачивания одной записи. */
data class DownloadState(val text: String, val fraction: Float?, val playWhenDone: Boolean)

class CameraViewModel(app: Application) : AndroidViewModel(app) {
    private val prefs = app.getSharedPreferences("camera", Context.MODE_PRIVATE)

    var ip by mutableStateOf(prefs.getString("ip", "")!!)
    var password by mutableStateOf(prefs.getString("password", "")!!)
    var port by mutableStateOf(prefs.getString("port", V380Session.DEFAULT_PORT.toString())!!)

    var status by mutableStateOf("")
    var busy by mutableStateOf(false)
        private set
    var info by mutableStateOf<CameraInfo?>(null)
        private set
    var segments by mutableStateOf<List<Segment>>(emptyList())
        private set
    var segmentsLoaded by mutableStateOf(false)
        private set
    val downloads = mutableStateMapOf<Long, DownloadState>()
    var playing by mutableStateOf<File?>(null)
    var message by mutableStateOf<String?>(null)

    private val downloadJobs = HashMap<Long, Job>()

    init {
        applyPort()
    }

    /** Порт из поля; пустое или неверное значение — стандартный 8089. */
    private fun applyPort() {
        V380Session.port = port.trim().toIntOrNull()?.takeIf { it in 1..65535 } ?: V380Session.DEFAULT_PORT
    }

    fun saveConnection() {
        applyPort()
        prefs.edit().putString("ip", ip.trim()).putString("password", password).putString("port", port.trim()).apply()
    }

    private fun run(start: String, block: suspend () -> Unit) {
        if (busy) return
        saveConnection()
        busy = true
        status = start
        viewModelScope.launch {
            try {
                block()
            } catch (e: Exception) {
                status = (e as? CameraException)?.message ?: I18n.s.error(e.message ?: e.javaClass.simpleName)
            } finally {
                busy = false
            }
        }
    }

    private suspend fun <T> session(block: (V380Session) -> T): T = withContext(Dispatchers.IO) {
        V380Session.open(ip.trim(), password).use(block)
    }

    // ---------- камера ----------

    fun refresh() = run(I18n.s.connectingToCamera) {
        val (inf, segs) = session { ss ->
            val p = ss.getProps(V380Session.DPID_RECMODE, V380Session.DPID_ALARM_MAIN, V380Session.DPID_NET_MODE, V380Session.DPID_NET_SSID)
            fun int(d: Long) = when (val v = p[d]) { is Boolean -> if (v) 1 else 0; is Number -> v.toInt(); else -> -1 }
            CameraInfo(int(V380Session.DPID_RECMODE), int(V380Session.DPID_ALARM_MAIN), int(V380Session.DPID_NET_MODE),
                p[V380Session.DPID_NET_SSID] as? String ?: "") to ss.listRecordings()
        }
        info = inf
        segments = segs.sortedByDescending { it.startMs }
        segmentsLoaded = true
        status = I18n.s.connected(segs.size)
    }

    fun applyRecordMode(mode: Int) = run(I18n.s.applyingRecordMode) {
        val inf = session { ss ->
            ss.setRecordMode(mode)
            val p = ss.getProps(V380Session.DPID_RECMODE, V380Session.DPID_ALARM_MAIN)
            fun int(d: Long) = when (val v = p[d]) { is Boolean -> if (v) 1 else 0; is Number -> v.toInt(); else -> -1 }
            int(V380Session.DPID_RECMODE) to int(V380Session.DPID_ALARM_MAIN)
        }
        info = (info ?: CameraInfo(-1, -1, -1, "")).copy(recordMode = inf.first, alarm = inf.second)
        status = I18n.s.recordModeStatus(recordModeName(info!!))
    }

    fun setWifi(ssid: String, pwd: String) = run(I18n.s.sendingNetwork(ssid)) {
        session { it.setWifi(ssid, pwd, 2) }
        status = I18n.s.wifiAccepted(ssid)
        message = status
    }

    fun find() = run(I18n.s.searching) {
        val found = Discovery.find(getApplication(), password) { s -> viewModelScope.launch { status = s } }
        if (found != null) {
            ip = found
            saveConnection()
            status = I18n.s.cameraFound(found)
        } else if (status != I18n.s.phoneNotOnLan) {
            status = I18n.s.cameraNotFound
        }
    }

    // ---------- записи ----------

    private val dirMovies: File
        get() = getApplication<Application>().getExternalFilesDir(Environment.DIRECTORY_MOVIES)!!.also { it.mkdirs() }

    fun fileFor(seg: Segment): File =
        File(dirMovies, "v380_" + SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date(seg.startMs)) + ".mp4")

    fun isDownloaded(seg: Segment) = fileFor(seg).let { it.exists() && it.length() > 0 }

    /** Скачать запись; [play] — открыть плеер по готовности. */
    fun download(seg: Segment, play: Boolean) {
        val f = fileFor(seg)
        if (f.exists() && f.length() > 0) {
            if (play) playing = f
            return
        }
        if (downloadJobs[seg.startMs]?.isActive == true) {
            downloads[seg.startMs] = downloads[seg.startMs]!!.copy(playWhenDone = play || downloads[seg.startMs]!!.playWhenDone)
            return
        }
        saveConnection()
        downloads[seg.startMs] = DownloadState(I18n.s.connecting, null, play)
        val camIp = ip.trim()
        val pw = password
        val job = viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    val ctx = coroutineContext
                    Replay.download(camIp, pw, seg, f, { !ctx.isActive }) { p ->
                        val t = if (p.fraction != null) I18n.s.downloading((p.fraction * 100).toInt()) else I18n.s.frames(p.videoFrames)
                        viewModelScope.launch {
                            downloads[seg.startMs]?.let { downloads[seg.startMs] = it.copy(text = t, fraction = p.fraction) }
                        }
                    }
                }
                val st = downloads.remove(seg.startMs)
                if (st?.playWhenDone == true) playing = f
                else message = I18n.s.downloaded(f.name)
            } catch (e: CancellationException) {
                downloads.remove(seg.startMs)
                throw e
            } catch (e: Exception) {
                downloads.remove(seg.startMs)
                message = I18n.s.downloadFailed((e as? CameraException)?.message ?: e.message)
            }
        }
        downloadJobs[seg.startMs] = job
    }

    fun cancelDownload(seg: Segment) {
        downloadJobs.remove(seg.startMs)?.cancel()
        downloads.remove(seg.startMs)
    }

    fun deleteLocal(seg: Segment) {
        fileFor(seg).delete()
        segments = segments.toList()
    }

    /** Скопировать скачанный файл в общую папку Movies/V380 (видно в галерее). */
    fun saveToGallery(f: File) {
        viewModelScope.launch {
            val ok = withContext(Dispatchers.IO) {
                try {
                    val cr = getApplication<Application>().contentResolver
                    val cv = ContentValues().apply {
                        put(MediaStore.Video.Media.DISPLAY_NAME, f.name)
                        put(MediaStore.Video.Media.MIME_TYPE, "video/mp4")
                        put(MediaStore.Video.Media.RELATIVE_PATH, Environment.DIRECTORY_MOVIES + "/V380")
                        put(MediaStore.Video.Media.IS_PENDING, 1)
                    }
                    val uri: Uri = cr.insert(MediaStore.Video.Media.EXTERNAL_CONTENT_URI, cv) ?: return@withContext false
                    cr.openOutputStream(uri)!!.use { o -> f.inputStream().use { it.copyTo(o) } }
                    cv.clear(); cv.put(MediaStore.Video.Media.IS_PENDING, 0)
                    cr.update(uri, cv, null, null)
                    true
                } catch (e: Exception) {
                    false
                }
            }
            message = if (ok) I18n.s.savedToGallery else I18n.s.saveToGalleryFailed
        }
    }

    // ---------- живое видео ----------

    fun rtspUrl(hostPort: String = "${ip.trim()}:554"): String = "rtsp://admin:${Uri.encode(password)}@$hostPort/live/ch00_0"

    /** Включает RTSP и звук в RTSP (свойства 983296/983297), ждёт порт 554. */
    suspend fun prepareLive(onStatus: (String) -> Unit) {
        saveConnection()
        val camIp = ip.trim()
        onStatus(I18n.s.connectingToCamera)
        val changed = session { ss ->
            val p = ss.getProps(V380Session.DPID_ONVIF, V380Session.DPID_RTSP_AUDIO)
            if (p[V380Session.DPID_ONVIF] != true || p[V380Session.DPID_RTSP_AUDIO] != true) {
                ss.setProps(listOf(V380Session.DPID_ONVIF to true, V380Session.DPID_RTSP_AUDIO to true))
                true
            } else false
        }
        if (changed) {
            onStatus(I18n.s.enablingRtsp)
            delay(3000)
        }
        onStatus(I18n.s.waitingRtsp)
        val ok = withContext(Dispatchers.IO) {
            repeat(15) {
                try {
                    Socket().use { it.connect(InetSocketAddress(camIp, 554), 1000) }
                    return@withContext true
                } catch (_: Exception) {
                    Thread.sleep(1000)
                }
            }
            false
        }
        if (!ok) throw CameraException(I18n.s.rtspPortClosed)
    }

    companion object {
        fun recordModeName(i: CameraInfo): String = when (i.recordMode) {
            1 -> I18n.s.rmContinuous
            2 -> if (i.alarm == 0) I18n.s.rmMotionNoAlarm else I18n.s.rmMotion
            3 -> I18n.s.rmBoth
            else -> "?"
        }

        fun netName(i: CameraInfo): String = when {
            i.netMode == 8 -> I18n.s.netCable
            i.netMode <= 0 -> "?"
            else -> I18n.s.netWifi(i.netSsid)
        }
    }
}
