package com.anded.v380.ui

import android.content.Intent
import android.view.SurfaceHolder
import android.view.SurfaceView
import android.view.ViewGroup
import androidx.annotation.OptIn
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.FileProvider
import androidx.media3.common.C
import androidx.media3.common.MediaItem
import androidx.media3.common.PlaybackException
import androidx.media3.common.Player
import androidx.media3.common.util.UnstableApi
import androidx.media3.exoplayer.DefaultLoadControl
import androidx.media3.exoplayer.ExoPlayer
import androidx.media3.exoplayer.rtsp.RtspMediaSource
import androidx.media3.ui.AspectRatioFrameLayout
import androidx.media3.ui.PlayerView
import com.anded.v380.I18n
import com.anded.v380.Lang
import com.anded.v380.proto.RtspFixProxy
import com.anded.v380.proto.StreamPlayer
import com.anded.v380.proto.V380Session.Segment
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

// ===================== Камера: подключение, режим записи, Wi-Fi =====================

// Пароли показываются открытым текстом (без точек), автозамена выключена, чтобы клавиатура не правила ввод.
private val plainPassword = KeyboardOptions(autoCorrect = false, keyboardType = KeyboardType.Text)

@Composable
private fun LanguageSwitch() {
    val ctx = LocalContext.current
    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
        for ((l, name) in listOf(Lang.EN to "EN", Lang.RU to "RU")) {
            if (I18n.lang == l) FilledTonalButton({}) { Text(name) }
            else OutlinedButton({ I18n.set(ctx, l) }) { Text(name) }
        }
    }
}

@Composable
fun CameraScreen(vm: CameraViewModel) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(I18n.s.cameraTitle, style = MaterialTheme.typography.headlineSmall, modifier = Modifier.weight(1f))
            LanguageSwitch()
        }
        Card {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(
                        vm.ip, { vm.ip = it }, Modifier.weight(1f), label = { Text(I18n.s.cameraIp) }, singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                    )
                    OutlinedTextField(
                        vm.port, { v -> vm.port = v.filter { it.isDigit() }.take(5) }, Modifier.width(96.dp),
                        label = { Text(I18n.s.cameraPort) }, singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    )
                }
                OutlinedTextField(
                    vm.password, { vm.password = it }, Modifier.fillMaxWidth(), label = { Text(I18n.s.cameraPassword) },
                    singleLine = true, keyboardOptions = plainPassword,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button({ vm.refresh() }, enabled = !vm.busy) { Text(I18n.s.connect) }
                    OutlinedButton({ vm.find() }, enabled = !vm.busy) { Text(I18n.s.findCamera) }
                }
                StatusLine(vm)
            }
        }

        val info = vm.info
        Card {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(I18n.s.recordMode, style = MaterialTheme.typography.titleMedium)
                Text(I18n.s.now(info?.let { CameraViewModel.recordModeName(it) } ?: I18n.s.pressConnect))
                var sel by remember(info?.recordMode) { mutableIntStateOf(if (info?.recordMode == 2) 2 else 1) }
                Row(Modifier.fillMaxWidth().clickable { sel = 1 }, verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(sel == 1, { sel = 1 }); Text(I18n.s.continuous)
                }
                Row(Modifier.fillMaxWidth().clickable { sel = 2 }, verticalAlignment = Alignment.CenterVertically) {
                    RadioButton(sel == 2, { sel = 2 }); Text(I18n.s.onMotion)
                }
                FilledTonalButton({ vm.applyRecordMode(sel) }, enabled = !vm.busy) { Text(I18n.s.applyToCamera) }
            }
        }

        Card {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(I18n.s.cameraNetwork, style = MaterialTheme.typography.titleMedium)
                Text(I18n.s.now(info?.let { CameraViewModel.netName(it) } ?: "—"))
                var ssid by remember { mutableStateOf("") }
                var pwd by remember { mutableStateOf("") }
                var confirm by remember { mutableStateOf(false) }
                OutlinedTextField(ssid, { ssid = it }, Modifier.fillMaxWidth(), label = { Text(I18n.s.wifiSsid) }, singleLine = true)
                OutlinedTextField(
                    pwd, { pwd = it }, Modifier.fillMaxWidth(), label = { Text(I18n.s.wifiPassword) }, singleLine = true,
                    keyboardOptions = plainPassword,
                )
                FilledTonalButton({ confirm = true }, enabled = !vm.busy && ssid.isNotBlank()) { Text(I18n.s.connectToNetwork) }
                Text(
                    I18n.s.wifiWarning,
                    style = MaterialTheme.typography.bodySmall,
                )
                if (confirm) AlertDialog(
                    onDismissRequest = { confirm = false },
                    title = { Text(I18n.s.changeWifiTitle) },
                    text = { Text(I18n.s.changeWifiText(ssid)) },
                    confirmButton = { TextButton({ confirm = false; vm.setWifi(ssid, pwd) }) { Text(I18n.s.change) } },
                    dismissButton = { TextButton({ confirm = false }) { Text(I18n.s.cancel) } },
                )
            }
        }
    }
}

@Composable
private fun StatusLine(vm: CameraViewModel) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        if (vm.busy) {
            CircularProgressIndicator(Modifier.padding(end = 8.dp).width(18.dp).height(18.dp), strokeWidth = 2.dp)
        }
        Text(vm.status, style = MaterialTheme.typography.bodyMedium)
    }
}

// ===================== Записи =====================

private fun dayFmt() = SimpleDateFormat("d MMMM yyyy, EEEE", I18n.s.locale)
private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.US)

private fun typeName(t: Int) = when (t) {
    2 -> I18n.s.typeMotion
    1 -> I18n.s.typeScheduled
    else -> I18n.s.typeRecording
}

private fun durText(ms: Long): String {
    val s = (ms + 500) / 1000
    return if (s >= 60) I18n.s.durMin(s / 60, s % 60) else I18n.s.durSec(s)
}

@Composable
fun RecordingsScreen(vm: CameraViewModel) {
    LaunchedEffect(Unit) { if (!vm.segmentsLoaded && !vm.busy) vm.refresh() }
    var menuFor by remember { mutableStateOf<Segment?>(null) }
    Column(Modifier.fillMaxSize()) {
        Row(Modifier.fillMaxWidth().padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(I18n.s.recordingsTitle, style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
            OutlinedButton({ vm.refresh() }, enabled = !vm.busy) { Text(I18n.s.refresh) }
        }
        Box(Modifier.padding(horizontal = 12.dp)) { StatusLine(vm) }
        if (vm.segmentsLoaded && vm.segments.isEmpty()) {
            Text(I18n.s.noRecordings, Modifier.padding(16.dp))
        }
        val fmt = dayFmt()
        val groups = vm.segments.groupBy { fmt.format(Date(it.startMs)) }
        LazyColumn(Modifier.fillMaxSize()) {
            groups.forEach { (day, segs) ->
                item(key = "h$day") {
                    Text(
                        day, Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surfaceVariant).padding(12.dp, 6.dp),
                        style = MaterialTheme.typography.labelLarge,
                    )
                }
                items(segs, key = { it.startMs }) { seg -> SegmentRow(vm, seg) { menuFor = seg } }
            }
        }
    }
    menuFor?.let { seg ->
        val ctx = LocalContext.current
        val f = vm.fileFor(seg)
        val have = vm.isDownloaded(seg)
        AlertDialog(
            onDismissRequest = { menuFor = null },
            title = { Text(timeFmt.format(Date(seg.startMs)) + " · " + durText(seg.durationMs)) },
            text = {
                Column {
                    TextButton({ menuFor = null; vm.watch(seg) }) { Text(I18n.s.watch) }
                    if (!have) TextButton({ menuFor = null; vm.download(seg, false) }) { Text(I18n.s.download) }
                    if (have) {
                        TextButton({ menuFor = null; vm.saveToGallery(f) }) { Text(I18n.s.saveToGallery) }
                        TextButton({
                            menuFor = null
                            val uri = FileProvider.getUriForFile(ctx, ctx.packageName + ".files", f)
                            ctx.startActivity(
                                Intent.createChooser(
                                    Intent(Intent.ACTION_SEND).setType("video/mp4").putExtra(Intent.EXTRA_STREAM, uri)
                                        .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION),
                                    I18n.s.shareRecording,
                                ),
                            )
                        }) { Text(I18n.s.share) }
                        TextButton({ menuFor = null; vm.deleteLocal(seg) }) { Text(I18n.s.deleteFromPhone) }
                    }
                    if (vm.downloads.containsKey(seg.startMs)) {
                        TextButton({ menuFor = null; vm.cancelDownload(seg) }) { Text(I18n.s.cancelDownload) }
                    }
                }
            },
            confirmButton = { TextButton({ menuFor = null }) { Text(I18n.s.close) } },
        )
    }
}

@Composable
private fun SegmentRow(vm: CameraViewModel, seg: Segment, onClick: () -> Unit) {
    val dl = vm.downloads[seg.startMs]
    val have = vm.isDownloaded(seg)
    Column(Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 16.dp, vertical = 10.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(timeFmt.format(Date(seg.startMs)), fontWeight = FontWeight.SemiBold, modifier = Modifier.width(90.dp))
            Text(durText(seg.durationMs), Modifier.width(100.dp))
            Text(typeName(seg.type), Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
            if (have) Text(I18n.s.onPhone, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
        }
        if (dl != null) {
            Spacer(Modifier.height(4.dp))
            Text(dl.text, style = MaterialTheme.typography.bodySmall)
            if (dl.fraction != null) LinearProgressIndicator({ dl.fraction }, Modifier.fillMaxWidth())
            else LinearProgressIndicator(Modifier.fillMaxWidth())
        }
    }
    HorizontalDivider()
}

// ===================== Плеер записи =====================

@Composable
fun PlayerScreen(vm: CameraViewModel, file: File) {
    val ctx = LocalContext.current
    val player = remember(file) {
        ExoPlayer.Builder(ctx).build().apply {
            setMediaItem(MediaItem.fromUri(android.net.Uri.fromFile(file)))
            prepare()
            playWhenReady = true
        }
    }
    DisposableEffect(player) { onDispose { player.release() } }
    Box(Modifier.fillMaxSize().background(Color.Black).safeDrawingPadding()) {
        AndroidView(
            factory = {
                PlayerView(it).apply {
                    this.player = player
                    keepScreenOn = true
                    layoutParams = ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
                }
            },
            modifier = Modifier.fillMaxSize(),
        )
        Row(Modifier.align(Alignment.TopStart).padding(8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilledTonalButton({ vm.playing = null }) { Text(I18n.s.back) }
            FilledTonalButton({ vm.saveToGallery(file) }) { Text(I18n.s.toGallery) }
        }
    }
}

// ===================== Просмотр во время загрузки =====================

@Composable
fun StreamScreen(vm: CameraViewModel, sp: StreamPlayer) {
    Box(Modifier.fillMaxSize().background(Color.Black).safeDrawingPadding()) {
        AndroidView(
            factory = { ctx ->
                SurfaceView(ctx).apply {
                    keepScreenOn = true
                    holder.addCallback(object : SurfaceHolder.Callback {
                        override fun surfaceCreated(h: SurfaceHolder) = sp.setSurface(h.surface)
                        override fun surfaceChanged(h: SurfaceHolder, format: Int, w: Int, hh: Int) {}
                        // Экран закрыт или приложение ушло в фон — просмотр заканчивается.
                        override fun surfaceDestroyed(h: SurfaceHolder) {
                            sp.setSurface(null)
                            vm.stopStream()
                        }
                    })
                }
            },
            modifier = Modifier.align(Alignment.Center).aspectRatio(vm.streamAspect),
        )
        vm.streamText?.let { Text(it, Modifier.align(Alignment.Center).padding(16.dp), color = Color.White) }
        Row(
            Modifier.align(Alignment.TopStart).padding(8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            FilledTonalButton({ vm.stopStream() }) { Text(I18n.s.back) }
            vm.streamDownload?.let {
                Text(it.text, color = Color.White.copy(alpha = 0.7f), style = MaterialTheme.typography.labelMedium)
            }
        }
    }
}

// ===================== Живое видео (RTSP камеры) =====================

/**
 * Видео и звук — два отдельных RTSP-сеанса с одной дорожкой каждый (как в v380gui): на второй SETUP
 * камера выдаёт новый Session ID. Оба идут через [RtspFixProxy], который чинит ключевые кадры.
 */
@OptIn(UnstableApi::class)
private fun livePlayer(ctx: android.content.Context, disabledType: Int): ExoPlayer =
    ExoPlayer.Builder(ctx)
        .setLoadControl(DefaultLoadControl.Builder().setBufferDurationsMs(500, 2000, 250, 500).build())
        .build()
        .apply {
            trackSelectionParameters = trackSelectionParameters.buildUpon().setTrackTypeDisabled(disabledType, true).build()
        }

@OptIn(UnstableApi::class)
@Composable
fun LiveScreen(vm: CameraViewModel) {
    val ctx = LocalContext.current
    var state by remember { mutableStateOf(I18n.s.connecting) }
    var playing by remember { mutableStateOf(false) }
    var attempt by remember { mutableIntStateOf(0) }
    var muted by remember { mutableStateOf(false) }
    val video = remember { livePlayer(ctx, C.TRACK_TYPE_AUDIO) }
    val audio = remember { livePlayer(ctx, C.TRACK_TYPE_VIDEO) }
    var proxy by remember { mutableStateOf<RtspFixProxy?>(null) }
    DisposableEffect(video, audio) {
        val l = object : Player.Listener {
            override fun onPlaybackStateChanged(s: Int) {
                if (s == Player.STATE_READY) playing = true
                if (s == Player.STATE_BUFFERING && !playing) state = I18n.s.buffering
            }

            override fun onPlayerError(error: PlaybackException) {
                playing = false
                state = I18n.s.streamInterrupted(error.errorCodeName)
            }
        }
        video.addListener(l)
        onDispose { video.removeListener(l); video.release(); audio.release(); proxy?.close() }
    }
    LaunchedEffect(attempt) {
        playing = false
        video.stop(); audio.stop()
        proxy?.close(); proxy = null
        try {
            vm.prepareLive { state = it }
            state = I18n.s.openingRtsp
            val px = RtspFixProxy(vm.ip.trim()).also { proxy = it }
            val url = vm.rtspUrl("127.0.0.1:${px.localPort}")
            for (p in listOf(video, audio)) {
                val src = RtspMediaSource.Factory().setForceUseRtpTcp(true).createMediaSource(MediaItem.fromUri(url))
                p.setMediaSource(src)
                p.prepare()
                p.playWhenReady = true
            }
            audio.volume = if (muted) 0f else 1f
        } catch (e: Exception) {
            state = e.message ?: I18n.s.connectionError
        }
    }
    Box(Modifier.fillMaxSize().background(Color.Black)) {
        AndroidView(
            factory = {
                PlayerView(it).apply {
                    this.player = video
                    useController = false
                    keepScreenOn = true
                    resizeMode = AspectRatioFrameLayout.RESIZE_MODE_FIT
                }
            },
            modifier = Modifier.fillMaxSize(),
        )
        if (!playing) {
            Column(Modifier.align(Alignment.Center), horizontalAlignment = Alignment.CenterHorizontally) {
                Text(state, color = Color.White)
                Spacer(Modifier.height(8.dp))
                OutlinedButton({ attempt++ }) { Text(I18n.s.retry, color = Color.White) }
            }
        }
        Row(Modifier.align(Alignment.TopEnd).padding(8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilledTonalButton({
                muted = !muted
                audio.volume = if (muted) 0f else 1f
            }) { Text(if (muted) I18n.s.soundOff else I18n.s.soundOn) }
            FilledTonalButton({ attempt++ }) { Text("↻") }
        }
        Text(
            vm.ip, Modifier.align(Alignment.TopStart).padding(12.dp),
            color = Color.White.copy(alpha = 0.7f), style = MaterialTheme.typography.labelMedium,
        )
    }
}
