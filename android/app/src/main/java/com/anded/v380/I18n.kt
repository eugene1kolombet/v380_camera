package com.anded.v380

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.util.Locale

enum class Lang { EN, RU }

/**
 * Язык интерфейса: по умолчанию английский, выбор хранится в настройках. [s] — состояние Compose,
 * поэтому экраны перерисовываются сразу после [set].
 */
object I18n {
    var lang by mutableStateOf(Lang.EN)
        private set

    val s: Strings get() = if (lang == Lang.RU) ru else en

    private val en = Strings(false)
    private val ru = Strings(true)

    private fun prefs(ctx: Context) = ctx.getSharedPreferences("camera", Context.MODE_PRIVATE)

    fun load(ctx: Context) {
        lang = if (prefs(ctx).getString("lang", "en") == "ru") Lang.RU else Lang.EN
    }

    fun set(ctx: Context, l: Lang) {
        lang = l
        prefs(ctx).edit().putString("lang", if (l == Lang.RU) "ru" else "en").apply()
    }
}

/** Все строки интерфейса: английский и русский варианты рядом. */
class Strings(private val ru: Boolean) {
    private fun t(en: String, ru: String) = if (this.ru) ru else en

    val locale: Locale get() = if (ru) Locale("ru") else Locale.ENGLISH

    // ---------- навигация ----------
    val tabCamera get() = t("Camera", "Камера")
    val tabRecordings get() = t("Recordings", "Записи")
    val tabLive get() = t("Live", "Живое")

    // ---------- экран камеры ----------
    val cameraTitle get() = t("V380 Camera", "Камера V380")
    val cameraIp get() = t("Camera IP", "IP камеры")
    val cameraPort get() = t("Port", "Порт")
    val cameraPassword get() = t("Camera password", "Пароль камеры")
    val connect get() = t("Connect", "Подключиться")
    val findCamera get() = t("Find camera", "Найти камеру")
    val recordMode get() = t("Recording mode", "Режим записи")
    fun now(v: String) = t("Now: ", "Сейчас: ") + v
    val pressConnect get() = t("— (press “Connect”)", "— (нажмите «Подключиться»)")
    val continuous get() = t("Continuous", "Постоянно")
    val onMotion get() = t("On motion", "По движению")
    val applyToCamera get() = t("Apply to camera", "Применить к камере")
    val cameraNetwork get() = t("Camera network", "Сеть камеры")
    val wifiSsid get() = t("Wi-Fi network name (SSID)", "Имя сети Wi-Fi (SSID)")
    val wifiPassword get() = t("Wi-Fi password", "Пароль Wi-Fi")
    val connectToNetwork get() = t("Connect camera to this network", "Подключить камеру к этой сети")
    val wifiWarning get() = t(
        "2.4 GHz only. If the network is entered incorrectly, the camera will drop off the network — " +
            "then only a reset with the Reset button will help.",
        "Только 2,4 ГГц. Если сеть указана с ошибкой, камера пропадёт из сети — " +
            "тогда поможет только сброс кнопкой Reset.",
    )
    val changeWifiTitle get() = t("Change camera Wi-Fi?", "Сменить Wi-Fi камеры?")
    fun changeWifiText(ssid: String) = t(
        "The camera will switch to the network “$ssid” and will most likely get a new IP address.",
        "Камера переключится на сеть «$ssid» и, скорее всего, получит новый IP-адрес.",
    )
    val change get() = t("Change", "Сменить")
    val cancel get() = t("Cancel", "Отмена")

    // ---------- записи ----------
    val typeMotion get() = t("motion", "движение")
    val typeScheduled get() = t("scheduled", "по расписанию")
    val typeRecording get() = t("recording", "запись")
    fun durMin(m: Long, s: Long) = t("$m min $s s", "$m мин $s с")
    fun durSec(s: Long) = t("$s s", "$s с")
    val recordingsTitle get() = t("Recordings on SD card", "Записи на SD-карте")
    val refresh get() = t("Refresh", "Обновить")
    val noRecordings get() = t("No recordings", "Записей нет")
    val watch get() = t("Watch", "Смотреть")
    val download get() = t("Download", "Скачать")
    val saveToGallery get() = t("Save to gallery", "Сохранить в галерею")
    val shareRecording get() = t("Share recording", "Поделиться записью")
    val share get() = t("Share", "Поделиться")
    val deleteFromPhone get() = t("Delete from phone", "Удалить с телефона")
    val cancelDownload get() = t("Cancel download", "Отменить загрузку")
    val close get() = t("Close", "Закрыть")
    val onPhone get() = t("on phone", "на телефоне")

    // ---------- плеер и живое видео ----------
    val back get() = t("Back", "Назад")
    val toGallery get() = t("To gallery", "В галерею")
    val connecting get() = t("Connecting…", "Подключение…")
    val buffering get() = t("Buffering…", "Буферизация…")
    fun streamInterrupted(code: String) = t("Video stream interrupted: $code", "Видеопоток прервался: $code")
    val openingRtsp get() = t("Opening RTSP…", "Открываю RTSP…")
    val connectionError get() = t("Connection error", "Ошибка подключения")
    val retry get() = t("Retry", "Повторить")
    val soundOff get() = t("Sound: off", "Звук: выкл")
    val soundOn get() = t("Sound: on", "Звук: вкл")

    // ---------- статусы ----------
    fun error(msg: String) = t("Error: $msg", "Ошибка: $msg")
    val connectingToCamera get() = t("Connecting to camera…", "Подключение к камере…")
    fun connected(n: Int) = t("Connected. Recordings: $n", "Подключено. Записей: $n")
    val applyingRecordMode get() = t("Applying recording mode…", "Применяю режим записи…")
    fun recordModeStatus(name: String) = t("Recording mode: $name", "Режим записи: $name")
    fun sendingNetwork(ssid: String) = t("Sending network “$ssid” to the camera…", "Передаю камере сеть «$ssid»…")
    fun wifiAccepted(ssid: String) = t(
        "The camera accepted the network “$ssid”. If it is on a cable now, it will switch to Wi-Fi after " +
            "the cable is unplugged and get a new address — find it with the “Find camera” button.",
        "Камера приняла сеть «$ssid». Если она сейчас на кабеле, то перейдёт на Wi-Fi после " +
            "отключения кабеля и получит новый адрес — найдите её кнопкой «Найти камеру».",
    )
    val searching get() = t("Searching for camera…", "Поиск камеры…")
    fun cameraFound(ip: String) = t("Camera found: $ip", "Камера найдена: $ip")
    val cameraNotFound get() = t(
        "Camera not found on the local network (or the password is wrong)",
        "Камера не найдена в локальной сети (или пароль не подходит)",
    )
    fun downloading(pct: Int) = t("Downloading $pct %", "Загрузка $pct %")
    fun frames(n: Int) = t("Frames: $n", "Кадров: $n")
    fun downloaded(name: String) = t("Recording downloaded: $name", "Запись скачана: $name")
    fun downloadFailed(msg: String?) = t("Could not download the recording: $msg", "Не удалось скачать запись: $msg")
    val savedToGallery get() = t("Saved to “Movies/V380”", "Сохранено в «Фильмы/V380»")
    val saveToGalleryFailed get() = t("Could not save to gallery", "Не удалось сохранить в галерею")
    val enablingRtsp get() = t("Enabling RTSP on the camera…", "Включаю RTSP на камере…")
    val waitingRtsp get() = t("Waiting for RTSP port 554…", "Жду RTSP-порт 554…")
    val rtspPortClosed get() = t("The camera did not open RTSP port 554", "Камера не открыла RTSP-порт 554")
    val rmContinuous get() = t("continuous", "постоянно")
    val rmMotionNoAlarm get() = t("on motion (alarm is off — not recording)", "по движению (тревога выключена — запись не идёт)")
    val rmMotion get() = t("on motion", "по движению")
    val rmBoth get() = t("continuous + motion", "постоянно + движение")
    val netCable get() = t("cable", "кабель")
    fun netWifi(ssid: String) = t("Wi-Fi “$ssid”", "Wi-Fi «$ssid»")

    // ---------- протокол ----------
    val phoneNotOnLan get() = t("The phone is not connected to a local network (Wi-Fi)", "Телефон не подключён к локальной сети (Wi-Fi)")
    fun searchingIn(prefix: String) = t("Searching for camera in $prefix.x …", "Поиск камеры в сети $prefix.x …")
    fun checking(ip: String) = t("Checking $ip …", "Проверка $ip …")
    fun noConnection(addr: String) = t("No connection to $addr", "Нет связи с $addr")
    fun loginFailed(msg: String?) = t("Login failed: $msg", "Вход не удался: $msg")
    fun badPacketLength(len: Int) = t("Invalid packet length: $len", "Неверная длина пакета: $len")
    val loginRejected get() = t("The camera rejected the login — check the password", "Камера отклонила вход — проверьте пароль")
    val badLoginResponse get() = t("Invalid login response", "Неверный ответ на вход")
    fun cameraRefused(code: Int) = t("The camera refused (code $code)", "Камера отказала (код $code)")
    fun propertyRejected(dpid: Long?, code: Int) = t("Property $dpid was not accepted (code $code)", "Свойство $dpid не принято (код $code)")
    fun noRecording(code: Int) = t("The camera did not return the recording (code $code)", "Камера не отдала запись (код $code)")
    val cancelled get() = t("Cancelled", "Отменено")
    val noFrames get() = t("The camera did not send a single frame", "Камера не прислала ни одного кадра")
    val noSpsPps get() = t("The recording has no SPS/PPS", "В записи нет SPS/PPS")
    val saveFileFailed get() = t("Could not save the file", "Не удалось сохранить файл")
    val aacNoFormat get() = t("The AAC encoder did not return a format", "AAC-кодер не выдал формат")
}
