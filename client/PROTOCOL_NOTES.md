# V380 — заметки по протоколу (реверс)

Камера для тестов: IPC-V380-Q8, прошивка 2.2.90, LAN `192.168.10.5:8089`,
пароль камеры — с наклейки, ID 102802372.

## 1. Управляющий протокол — ГОТОВО, подтверждён вживую

- TCP порт **8089** (IoT; 8800 легаси — на этой камере закрыт).
- Кадр: 16 байт LE `[cmd:4][ver:1][secure:1][b2:1][b3:1][0:4][dataLen:4]` + шифр.
- `cmd` = CMD_COMMON_IOT = 939722776. Медиа: CMD_COMMON_MEDIA = 939722784.
- Шифр `secure=2`: **AES-128-CBC/PKCS7**, ключ=key[0:16], IV=key[16:32]. Подтверждено.
- Вход = обмен ключами X25519 (LANPASS 196870): шлём pub(XOR magic) + sha256(pub‖pwd),
  общий секрет X25519 = ключ сессии. Хэндшейк шифруется статическим ключом
  `LoginHelper.i` (32 байта, в коде). Даёт `sKey` (32 байта), `sid`, `perm`.
- Список записей REC_FILE_LIST (197152), params `{filter,mode,start,end}`:
  - **filter=15** = все типы (НЕ 0!), mode=2 (LIST), start/end = epoch ms.
  - ответ `data.list[]`: `{s:смещение_от_start_мс, d:длительность_мс, t:тип}`.
- Скачивание файла по пути FILE_DOWNLOAD (197184) `{vfid,dfid,vfp,off}` — только
  именованные файлы (снимки/аудио), НЕ видеозаписи SD.

## 2. Воспроизведение/скачивание видео SD — реверс в процессе

Видео отдаёт нативная `libhsMediaLibrary.so` (ARM32, Thumb). Классы:
`HSReplayDataTFV3Transmitter` (наша новая прошивка), базовый
`HSReplayDataBaseTransmitter`, менеджер `HSMediaManager`.

Точки входа (символы):
- `HSMediaManager::startPlayback(tagRecFileParam*)`
- `HSMediaManager::startDownload(JNIEnv*, jobject, tagRecFileParam*)`
- `HSMediaManager::seek2TimeSegment(int, tagRecFileParam*)`
- `HSMediaManager::continueNextSegmentIndex/continueReadNextFile`
- поток-получатель: `replayDataGetterThreadTFV3` (0x4cf61, тонкий thunk)
- `HSReplayDataTFV3Transmitter::startTransmitter` (0x4dbad) — логи + запуск потока
- `HSReplayDataTFV2Transmitter::getDataFromDevice` (0x4bde1, 4480 б) — ЛОГИКА
  запроса/приёма (TFV3 использует родственную).

Параметр `tagRecFileParam` несёт: deviceID, segmentID, fileType, startTime, endTime,
playTime (лог: `play time=%d-%d-%d %d:%d:%d, deviceID=%d, segmentID=%d, fileType=%d`).
TFV3 лог: `segmentId=%d, startTime=%ld, endTime=%ld, playTime=%ld, curGetTime=%ld`.

### Запрос (по логам)
- `GetPlayBackDataFromDevice: send seek index = %d` — отправка seek-индекса.
- TFV3: `posTime send size=(%d,%d), pts=%ld, timeId=%d` — шлётся pts (long) + timeId.
- Похоже на бинарную структуру поверх сессии (не JSON). Точный байт-лейаут —
  извлечь из дизасма send-пути в getDataFromDevice (ищем вызов send и упаковку буфера).

### Ответ (по логам TFV2 — структура та же)
- Param-пакет: `recv res cmd=%d, result=%d, segmentID=%d, videoType=%d, width=%d,
  height=%d, audioType=%d, audioFrequency=%d, audioChannel=%d, audioSampble=%d`.
- Заголовок пакета данных: `type=%d, note=%d, number=%d, dataSize=%d` (проверка
  `checkSpace1 error(%d, 22)` → возможно 22-байтный заголовок).
- Кадр: `frameID=%d, type=%d, timestamp=%lld, frameSize=%d`.
- Типы: PACKET_TYPE_PARAM, PACKET_TYPE_ALIVE, PACKET_TYPE_FINISH (конец сегмента).
- Муксинг: `NVRawVideoToMP4` + `NVEncodeAACToMP4` (видео H.264/H.265 + аудио AAC → mp4).

### Разбор `getDataFromDeviceOrServer` (12420 б) — архитектура воспроизведения

Раскрыто по PLT-импортам и лог-строкам нативной функции:

- **Транспорт медиа** (ИСПРАВЛЕНО в проходах 4–5: для воспроизведения — ТА ЖЕ TCP-сессия
  8089, не UDP; `sendto`/`recvfrom` в либе — connected-TCP relay-пути, см. ниже).
- **Свой обмен ключами** на канале: лог `start keyExchange`, `sid=%d, keyHex=%s,
  ivHex=%s`, `keyExchange fail. code=%d`, `keyExchange uuid info not match` →
  тот же X25519/LANPASS, даёт ключ+IV медиа-сессии (`keyHex/ivHex`).
- **Рамка та же, 16 байт IoT**: лог `packet header cmd=%d, version=%d, secure=%d`.
  `cmd` различает три вида пакетов:
  - **IOTC** (CMD_COMMON_IOT 939722776): управление/ответы, JSON (`IOTC data
    cJsonStr=%s`, `IOTC cipher fail`, `IOTC json parse fail`). Шлётся `initIotcReq`.
  - **NOTIFY** (CMD_COMMON_NOTIFY 939722786): статус, JSON (`NOTIFY data cJsonStr=%s`,
    `REC_FLAG_ALIVE isFinish`) — alive/finish записи.
  - **MEDIA** (CMD_COMMON_MEDIA 939722784): кадры видео/аудио, шифрованные.
- **Запрос** строится нативным `initIotcReq(buf,isMR,...,cJSON*,...)` +
  `createActionJsonObj(cJSON*, daid, vs, noRsp, &out)` + `cipherJsonData` — то же, что
  в Java-управлении. Старт воспроизведения — действие с DAID (кандидат
  `DAID_RECORD_SEG_STATE_CTRL`) и сегментом; точные method_id/ключи — дочитать в
  dataCtrlThreadFunc/initParam/seekTransmitter.
- **Keep-alive**: периодический `initIotcReq` (лог `keep-alive ... iotc req`).
- **Шифр кадра** `iotc_ms_frame_cipher(info, h)` (372 б) + `_init(info, keyType,
  ivType, keyPtr, ivPtr)` (524 б): ключ 32 байта (const 0x20), состояние/счётчик в
  структуре `_media_stream_frame_trans_info` (+0x20 счётчик, +0x34 keystream-блок),
  побайтовый цикл — **похоже на AES-CTR** (keystream XOR data). Заголовок кадра и тело
  шифруются отдельно (`cipher frame herder fail` / `cipher frame fail`). Импорт
  `media_data_decrypt`/`media_data_decrypt_pre_2k` — возможно, первые 2К шифруются иначе.
  → Точный алгоритм (формат счётчика, вывод ключа/IV) — дочитать в iotc_ms_frame_cipher*.
- **Кадр**: лог `cipher_result=%d, id=%d, type=%d, seq=%d`, `sts=%ld, pts=%ld`,
  `HEADER_LEN`, `recvTotalSize=%ld`; потеря — `lost frame video(%d,%d,%d)`; ждём
  ключевой кадр — `wait key frame`. Склейка из UDP-пакетов: `uPacketDataSize, nBlockSize,
  uPacketCount, uPacketNum`.

Ключевые функции (адреса): getDataFromDeviceOrServer @0x4e601 (12420),
dataCtrlThreadFunc @0x4d261 (2096), dataGetThreadFunc @0x4cf71 (732),
seekTransmitter @0x4e101 (444), initParam @0x4de3d (676),
iotc_ms_frame_cipher @0x768fd (372), _init @0x76619 (524).
Дизасм: `scratchpad/disf.py <so> <symbol>` (устойчивый к литер.пулам, резолвит
PLT-вызовы и PC-строки).

### Проход 3 — ПОДТВЕРЖДЕНО (dataCtrlThreadFunc + libaes.so)

**Запрос старта воспроизведения** (dataCtrlThreadFunc @0x4d261):
- method_id = **197154** (REPLAY_CTRL_REQUEST), cmd=CMD_COMMON_IOT, secure=2, b2=sid,
  шифруется медиа-сессионным ключом (как обычный IoT-запрос).
- params JSON-ключи: **`pts`** (позиция, ms, long), **`sts`** (start ts),
  **`rtype`** (тип записи), **`time_id`** (id сессии воспроизведения, эхо),
  **`vsspec`** (видеопоток: 0 главный), **`frames`**.
- Виды запросов в dataCtrlThreadFunc (все 197154): старт/позиционирование (`posTime
  send ... pts=%ld timeId`), `changePlaybackVsSpec`, `response` (на notify), `stop`.

**Шифр кадра — AES-128-ECB** (libaes.so):
- `iotc_ms_frame_cipher` (libhsMediaLibrary) → `media_data_encrypt/decrypt/‥_pre_2k`
  (libaes.so) → общий `media_data_cipher(data,len,key,flag,enc)` → PLT `0x39f0` =
  **`aes128_ecb_encrypt`** (подтверждено резолвом GOT). Режим — ECB (ключ 16 байт).
- Логика выбора региона по `flag`:
  - **flag==0 (кадр):** шифруются **64 байта из каждых 80** (шифр 0x40, шаг 0x50),
    пока осталось ≥64; хвост <64 — открытым. (Выборочное шифрование — работает только
    с ECB, т.к. блоки независимы.)
  - **flag!=0:** весь буфер, выровненный до 16 байт.
  - **pre_2k:** только первые min(len,0x800)=2048 байт (крупные кадры — шифр только
    начало).
- Ключ кадра = медиа-сессионный ключ (из обмена ключами канала; keyHex/ivHex). AES-128
  → первые 16 байт. IV для ECB не нужен.
- Заголовок и тело кадра шифруются отдельно (`cipher frame herder` / `cipher frame`).

### Проход 4 — ЖИВАЯ ПРОВЕРКА (камера 192.168.10.5) — большой прогресс

**Транспорт — ТА ЖЕ TCP-сессия 8089, НЕ UDP.** Отдельный канал и обмен ключами медиа
НЕ нужны: REPLAY_CTRL шлётся по управляющей сессии, медиа идёт по ней же.
(sendto/recvfrom в либе — для relay/MR-пути; LAN direct переиспользует TCP.)

**Запрос воспроизведения РАБОТАЕТ вживую:**
- Шлём IoT-запрос method_id=197154 (REPLAY_CTRL), secure=2, b2=sid, шифр сессионным
  ключом; params `{"pts":<ms>,"sts":<ms>,"rtype":<t>,"time_id":1,"vsspec":0,"frames":30}`.
- Камера отвечает **197155 code 1000** (принято) и шлёт NOTIFY (cmd 939722786).
- NOTIFY method_id=197156 (REPLAY_INFORMATION):
  - `info_id=1`: инфо сегмента — `{fts, duration, type, vattr:{codec:4(H.264),width,
    height,pano_*}, aattr:{codec:103,samplerate:16000,bits:16,chns:1}}`. РАБОТАЕТ:
    возвращает кодек/разрешение любого сегмента.
  - `info_id=4`: **REC_FLAG_ALIVE** (keep-alive «жив, жду»; обработчик @0x4fc26,
    строка «ResponseTest NOTIFY REC_FLAG_ALIVE isFinish»). Повторяется ~каждые 2с.
  - `info_id=3`: ещё одна ветка (@0x4fcc6, ставит флаг [r6,#0x333]=1 — вероятно finish).
- Видеокадры — ожидаются как cmd **939722784 (CMD_COMMON_MEDIA)**.

**Все запросы воспроизведения — method 197154 с одним набором ключей**
`{sts,pts,time_id,frames,rtype,vsspec}`, различаются ЗНАЧЕНИЯМИ (start/stop/posTime/
response/credit — builders в dataCtrlThreadFunc @0x4d261). `rtype`, похоже, кодирует
действие, не только тип записи. Везде в логах флаг `download=%d` — у скачивания свой режим.

**МИКРО-БЛОКЕР (следующий проход):** камера принимает запрос, отдаёт инфо и шлёт только
ALIVE — кадры (939722784) не начинаются. Нужен точный ответ/кредит клиента, чтобы
поток пошёл. Перепробовано (не сработало): ack notify (method 197156 result, b2=0 и
b2=sid), повторный 197154 с разными rtype(0..5), frames=0/30/100/1000/-1, pts=0.
→ Дочитать точно: builder «response/credit» (@~0x4d660, ключ `frames`) — его метод,
значение frames, и КАКОЙ info_id его триггерит; плюс путь download-флага
(startDownload vs startPlayback) — возможно, нужен флаг download или отдельная
подписка на данные. Связь потоков — флаги [this+0x330]/[+0x333]/[+0x304].

### Проход 5 — КАДРЫ ПОШЛИ (живая камера) + формат кадра

**РЕШЕНИЕ МИКРО-БЛОКЕРА: в запрос 197154 добавить `"video":1,"audio":1`!**
Полный рабочий запрос старта воспроизведения:
```
params = {"pts":segstart,"sts":segstart,"rtype":seg["t"],"time_id":1,
          "vsspec":0,"frames":100,"video":1,"audio":1}
method 197154, secure=2, b2=sid, шифр сессионным ключом.
```
→ камера шлёт MEDIA-пакеты (cmd 939722784), первый большой (~82КБ) = видео-ключкадр.
(audio:0 → только видео; frames = кредит, 100–200.) Поток кадров подтверждён.

**MEDIA-пакет (cmd 939722784):** 16-байтный IoT-заголовок, затем тело:
- **[0:32] — заголовок кадра, AES-128-ECB (ключ сессии[:16])**, расшифровка даёт:
  `byte0=0x4c 'L'`, `byte1`=тип (видео-I/видео-P/аудио — 3 значения в сессии),
  `byte3=0x02`, `byte4..5=0x6f41`, `byte6..7`=seq, `byte8..9`=0x..42,
  `byte12..15 = магия 0x60297bc2` (константа). Остальные байты — size/pts (разобрать).
- **[32:] — тело кадра.** Видео: открытый H.264 **SPS** (старт-код `00000001 27 4de028`
  = Main L4.0, 1280×720), затем **PPS+слайс ЗАШИФРОВАНЫ AES-128-ECB** (старт-кодов
  после SPS нет). Аудио (codec 103): тело без H.264 старт-кода.

**ПОСЛЕДНЕЕ (следующий проход):** точный split «открытый SPS / шифрованный остаток».
Перебор ffmpeg: ecb@16..48 убирает ошибки SPS/PPS по одиночному ключкадру, но на склейке
всех кадров снова «non-existing PPS 0» — значит offset/длина НЕ фиксированные, а заданы
полями в 32-байтном заголовке кадра (в шифре `iotc_ms_frame_cipher` это [struct+0x18] и
[struct+0x1c] — длина открытой части и шифрованной; ставятся в `_init` @0x76619,
значения рядом: 0x40=64, 0x12=18, 0x20=32). Надо: (а) разобрать поля размера в 32-байтном
заголовке кадра; (б) прочитать в `_init`, что кладётся в [0x18]/[0x1c]; (в) применить
ECB к точному региону [plainlen : plainlen+enclen] каждого кадра; аудио — свой разбор.

**ffmpeg есть** (`C:\Program Files\ffmpeg\bin\ffmpeg`). Склейка видео (SPS от I-кадра +
decrypt остальных) → `ffmpeg -framerate 15 -i v.h264 -c copy out.mp4`. Аудио codec 103
(вероятно G.711/ADPCM) — добавить вторым потоком.

### Проход 6 — инструмент + ключевая нестыковка

- В клиент добавлено: `start_replay()` (рабочий запрос video:1,audio:1), `capture_media_raw()`
  и CLI **`capture`** — пишет сырые MEDIA-пакеты в файл `[4б len][тело]…` для оффлайн-анализа.
  Проверено: `python v380pull.py --ip 192.168.10.5 --password <пароль> capture --out media.raw`.
- `iotc_ms_frame_cipher_init`: [0x14]=0x20 (размер ключа 32), [0x18]/[0x1c] = рантайм-счётчики
  (0 на старте), не фиксированный split. Значит split задаётся при вызове шифра.
- **НЕСТЫКОВКА (главная задача след. прохода):** 32-байтный заголовок кадра расшифровывается
  сессионным ключом **непостоянно** (в проходе 5 → `0x4c…` магия; в проходе 6 → мусор), и ECB
  тела ни на одном 16-выровненном offset не вскрывает старт-коды PPS(8)/IDR(5). Вывод: тело и
  заголовок кадра, скорее всего, шифруются **ОТДЕЛЬНЫМ медиа-ключом** (keyHex/ivHex из обмена
  ключами канала воспроизведения — поля uuid/cS в getDataFromDeviceOrServer), а НЕ управляющим
  сессионным ключом. Нужно: (а) восстановить вывод медиа-ключа/IV (функция обмена ключами
  воспроизведения: `start keyExchange` → `sid, keyHex, ivHex`; `HSReplayDataTFV3Transmitter::
  refreshMqKeyExchangeInfo`/`refreshSession`), (б) этим ключом расшифровать заголовок (ECB) и
  тело (media_data_cipher: AES-128-ECB, выборочно), (в) проверить появление PPS/IDR и декод ffmpeg.
- Для анализа есть `media.raw` (сырые кадры). Декод. SPS в теле открыт — значит шифруется только
  часть после него тем же медиа-ключом.

### Проход 7 — отсечены простые схемы, укреплён вывод про медиа-ключ

Проверено на живом ключкадре (payload head `00000001 27 4de028 8df0aff1…`):
- Заголовок кадра при ECB(сессионный ключ) даёт структуру, УСТОЙЧИВУЮ внутри сессии
  (const байты и «магия» на фикс. позициях), но РАЗНУЮ между сессиями (0x4c vs 0x95,
  магия 0x60297bc2 vs 0x6f6de702). Для блочного ECB так быть не может (один меняющийся
  байт скремблирует весь 16-байтный блок) → это **артефакт дешифра неверным ключом**.
- Тело: открытый SPS обрывается ~на 8–12 байте (ffmpeg: «illegal POC type 20» —
  pic_order_cnt_type зашифрован), дальше шифр. НЕ вскрывается: ECB с offset 0..96,
  AES-CTR(iv=0 / iv=заголовок / iv=rawhdr), OFB(iv=0), plain[:O]+ctr0.
- **ВЫВОД: кадры (заголовок+тело) шифруются ОТДЕЛЬНЫМ медиа-ключом/IV**, а не управляющим
  сессионным. Его даёт обмен ключами канала воспроизведения (натив: `start keyExchange` →
  `sid, keyHex, ivHex`, поля uuid/cS). Я его НЕ делал (переиспользовал сессию), поэтому
  ключ неверный. Камера кадры шлёт, но под медиа-ключом.

Следующий проход (точно):
1. Снять дизассемблером ТОЧНЫЙ вызов шифра кадра: source ключа (медиа vs сессия), режим
   (ECB/CTR), offset/длину. Функции: обработка MEDIA в getDataFromDeviceOrServer (ветка
   cmd==939722784), `iotc_ms_frame_cipher`/`media_data_cipher`; вывод ключа —
   `refreshMqKeyExchangeInfo`/`refreshSession`/ED25519 на канале.
2. ЛИБО реализовать медиа-обмен ключами (uuid/cS) и взять keyHex/ivHex.
3. Данные для оффлайн-подбора: `scratchpad/media.raw` (сырые кадры), известный
   открытый префикс SPS (`00000001 27 4de0 28 …`) — атака по известному тексту на keystream.

### Проход 8 — дизасм вызова шифра: ОТКУДА КЛЮЧ (ответ получен)

Снято дизассемблером:
- **Шифр кадра** = `iotc_ms_frame_cipher` → `media_data_cipher` (libaes) → `aes128_ecb_encrypt`
  (AES-128-ECB примитив), выборочно. Вызывается НЕ в getDataFromDeviceOrServer напрямую
  (0x8146c/0x81478 там нет) — в хелпере обработки кадра.
- **ИСТОЧНИК КЛЮЧА = отдельный медиа-ключ `keyHex/ivHex`**, который натив ВЫВОДИТ в обмене
  ключами канала воспроизведения внутри getDataFromDeviceOrServer: лог `start keyExchange`
  → `sid=%d, keyHex=%s, ivHex=%s` → `keyExchange fail. code=%d`. Запрос обмена: JSON-поля
  `uuid, cS` (строки) + `mode, video, audio, rtype, pts, sts, time_id, vsspec, frames,
  speed, flag, decode_tms`. НЕТ `cKM` → обмен опирается на уже аутентифицированную сессию
  (по `uuid`), ключ выводится по X25519-схеме (как LANPASS), даёт keyHex/ivHex.
- **Проверено, что ключ кадра — НЕ**: сессионный shared[:16]/[16:32]/полный(AES-256),
  SHA256(session), статический HANDSHAKE_KEY, режимы ECB/CBC/CTR/OFB. Хардкод-ключей в
  libaes/libhsMediaLibrary нет. → ключ действительно только из медиа-обмена.

**Вывод:** применить шифр к `media.raw` невозможно без медиа-ключа. Оба пути сошлись:
НУЖНО выполнить/реверснуть медиа-обмен ключами (uuid/cS → keyHex/ivHex). Это и есть
последний шаг. Я кадры получал БЕЗ обмена (переиспользовал сессию) — камера всё равно
шифрует медиа-ключом; значит в запрос воспроизведения надо добавить поля обмена
(uuid + свой X25519 pub + cS) и вывести общий секрет = keyHex/ivHex.

### ПРОХОД 10 — РЕШЕНО (Ghidra): скачивание видео в mp4 работает

Ghidra (11.0.3, JDK 17) декомпилировала `iotc_ms_frame_cipher*` и `parseKeyExchange`:

- **Ключ кадра = сессионный ключ** (X25519 shared секрет управляющего входа). Медиа-обмен
  ключами (`parseKeyExchange`: `curve25519_CreateSharedKey(out, my_priv, base64(devpub))`)
  даёт тот же X25519 — при переиспользовании сессии камера шифрует сессионным ключом.
  Предыдущие провалы были из-за НЕВЕРНОГО ШИФРА (брал ECB), а не ключа.
- **Шифр кадра = AES-128-CBC** (`mvt_cipher`, type 2), ключ=session[:16], iv=session[16:32].
- **Схема кадра** (`iotc_ms_frame_cipher_init`/`iotc_ms_frame_cipher`):
  1. Первые **32 байта** — заголовок, расшифровать CBC. В нём: byte0=0x01 (маркер),
     byte1=тип (1=видео-I, 2=видео-P, 4=аудио); поля длин — offset **0x12=plen**
     (открытый префикс), **0x16=elen** (длина шифр-блока), **0x1a=slen** (длина пропуска).
     Длины РАНДОМНЫЕ на кодировании (rand()), поэтому плавали.
  2. Тело: `plen` открытых байт, затем цикл [`elen` шифр (CBC-цепочка ПРОДОЛЖАЕТСЯ от
     заголовка и между блоками) + `slen` открытых], хвост (<elen) открытый.
- **Поток кадров**: запрос REPLAY_CTRL (197154) с `video:1,audio:1,frames:100` → камера
  шлёт до 100 кадров, затем NOTIFY info_id=4 (alive). На каждый alive слать 197154
  `{time_id:1,frames:100}` (пополнить кредит) → поток продолжается до конца сегмента
  (info_id=3 finish). Видео (тип 1/2) → H.264 поток → `ffmpeg -r <fps> -i - -c copy mp4`.

**РАБОТАЕТ ВЖИВУЮ:** `python v380pull.py --ip 192.168.10.5 --password <пароль> download
--seg 0 --out rec.mp4` → полный сегмент 66с, 1269 кадров 1280×720, проигрывается.

**АУДИО ТОЖЕ ГОТОВО:** тип 4, codec 103 = G.711 A-law (MV_MEDIA_CODEC_AUDIO_G711A), 16кГц
моно, 16 бит. Аудио-кадр шифруется так же (plen=0/elen=весь). payload — сырой G.711 A-law
(тишина=0xd5). Мукс: `ffmpeg -r <fps> -i видео.h264 -f alaw -ar 16000 -ac 1 -i аудио.alaw
-map 0:v:0 -map 1:a:0 -c:v copy -c:a aac out.mp4` (БЕЗ -shortest — он обрезает аудио на
сыром h264). Команда `download` теперь собирает видео+аудио.

### Проход 9 — предел статики: шифр зовётся через указатель

- `iotc_ms_frame_cipher`/`_init` — ЛОКАЛЬНЫЕ функции (0x768fd/0x76619), но **ни одна
  функция по символам не вызывает их прямым BL** (ни по PLT 0x81478/0x8146c, ни по
  прямым 0x768fc/0x76618). → шифр вызывается **через указатель на функцию** (C++
  vtable/крипто-абстракция). Значит ключ подаётся косвенно, статически проследить
  источник до keyHex/ivHex моим инструментом (capstone + разрывы на литпулах) нельзя.
- Регион вывода keyHex/ivHex (0x50648→0x4e90c→…→0x50746) — сложное ветвление с
  литпулами; capstone разбирает с пробелами. Для чистого реверса нужен Ghidra/IDA.
- Сессионный ключ как ключ кадра ОКОНЧАТЕЛЬНО отсечён (ECB с любым offset 0..48 по
  обоим половинам ключа не даёт старт-кодов PPS/IDR).

**Реальные пути к медиа-ключу (следующий шаг, нужен более тяжёлый инструмент/устройство):**
1. **Ghidra/IDA** на `getDataFromDeviceOrServer` + косвенный вызов шифра: восстановить
   вывод keyHex/ivHex и источник ключа точно (capstone тут не тянет).
2. **Рантайм-захват ключа** (самый быстрый, если есть Android-устройство/эмулятор):
   приложение ЛОГИРУЕТ `keyHex=%s, ivHex=%s` — снять logcat или хук Frida на
   `iotc_ms_frame_cipher_init` и вытащить реальные key/iv; затем ими дешифровать
   `media.raw` (AES-128-ECB, выборочно) и собрать mp4. REA (C:\rea) — под рантайм-анализ.
3. Реализовать медиа-обмен ключами (uuid/cS/pub → X25519 → keyHex/ivHex) — но нужен
   точный вывод из п.1 (как именно формируются uuid и cS, и KDF из shared в key+iv).

### Итог статуса
Работает вживую: вход, список записей, инфо сегмента, **поток кадров** (видео H.264
1280×720 + аудио). Остался ОДИН барьер — медиа-ключ шифрования кадра. Он не статический
и не сессионный; его дают либо Ghidra-реверс derivation, либо рантайм-захват ключа с
устройства. `media.raw` + `v380pull.py capture` готовы к применению ключа.

### Как слать запрос воспроизведения (готовый код-набросок)
```python
# после v.lan_login -> sk,sid; segstart = queryStart_ms + seg["s"]
params={"pts":segstart,"sts":segstart,"rtype":seg["t"],"time_id":1,"vsspec":0,"frames":30}
pkt,_=v.build_packet(197154, params, sk, b2=sid); s.sendall(pkt)
# читать пакеты: 939722776=IOTC(резп), 939722786=NOTIFY(JSON info/alive), 939722784=MEDIA
```

### План реализации
1. Дизасм send-пути getDataFromDevice (TFV2/TFV3) → точный формат запроса (cmd, поля).
2. Дизасм разбора param/frame-заголовков → формат ответа и кадра.
3. Реализовать в Python: старт воспроизведения сегмента, приём кадров, запись raw
   H.264 → mux ffmpeg в mp4 (аудио — если есть, AAC).
4. Проверка на живой камере 192.168.10.5 по сегментам из `list`.

## Инструменты
- Дизасм: `scratchpad/disasm.py` (capstone + pyelftools, Thumb). Пример:
  `python -I disasm.py libhsMediaLibrary.so <mangled_symbol>`.
- `.so`: `C:\v380\native\lib\armeabi-v7a\libhsMediaLibrary.so` (ARM32).

### Режим записи (постоянно / по движению) — SET/GET свойств

- Свойство **DPID_RECORD_MODE = (2<<16)|256|3 = 131331** (битовая маска):
  бит0(1)=автозапись (постоянно/по расписанию), бит1(2)=запись по тревоге/движению,
  бит3(8)=таймлапс. Значения: 1=постоянно, 2=только по движению, 3=оба.
- GET: method **GET_PROPERTIES 197376**, params `{"dplist":[131331]}` (массив ЧИСЕЛ) →
  ответ `data.dplist_result=[{"dpid":131331,"value":N,"code":1000}]`.
- SET: method **SET_PROPERTIES 197378**, params `{"dplist":[{"dpid":131331,"value":2}]}`
  (ключ тоже "dplist", объекты {dpid,value}; НЕ "list" — с "list" код 1000, но без эффекта).
  Проверено вживую: SET=2 → GET=2. Полный конфиг записи шлёт ещё DPID_RECORD_QUALITY(131332),
  _AUDIO(131333), _LOOP(131334), но смена режима работает и одним DPID_RECORD_MODE.
- Встроено в GUI (v380gui): выпадающий список режима + кнопка «Применить к камере».
- **Режим 2 сам по себе НЕ пишет**: камера записывает по движению, только если включена
  тревога. Свойства группы ALARM (DGID 10, dpid = (10<<16)|256|idx), значения bool — JSON
  `true/false`:
  - `DPID_ALARM_MAIN_SW` 655616 — главный выключатель тревоги (был `false` → записей нет);
  - `DPID_ALARM_MT_SW` 655620 — детектор движения;
  - `DPID_ALARM_TIMER_INFO` 655621 — расписание `{"Mon":{"cnt":1,"sche":[{"enable":true,
    "mode":1,"s_time":"0:0:0","e_time":"23:59:59"}]},…,"Sun":…}` (mode 1 = ABL_ALERT_DETECT_MOTION;
    так приложение шлёт «круглосуточно»);
  - `DPID_ALARM_MT_AREA` 655622 — зона 6×8 (`alarm_area_row_cnt/line_cnt/alarm_area[48]`);
  - MT_SENSITIVITY 655619 и группа ALERT_V2 (DGID 14) на этой камере не поддерживаются (код 1114).
  GUI для «По движению» шлёт одним SET: TIMER_INFO, MT_SW=true, MAIN_SW=true, RECORD_MODE=2;
  для «Постоянно» — MAIN_SW=false, RECORD_MODE=1.

### Живой поток — РЕШЕНО через RTSP (встроенный, включается свойством)

Собственный live-протокол V380 по LAN действительно закрыт облаком (см. ниже: даже в
LAN-режиме приложение перед стартом шлёт `mqExchangePublish` через облачный MQTT,
регистрируя свой ED25519-ключ, — без этого 196872 даёт 1119). Но у камеры есть штатный
**RTSP/ONVIF**, по умолчанию выключенный:

- Способности (ABILITY_REQUEST 197386) → `data.misc[7]` (MVS_DMISC_ABLC_EXTPROT) = 3 =
  ONVIF(1)|RTSP(2) — поддерживается.
- Свойство **DPID_EXTPROT_ONVIF_SW = (15<<16)|256|0 = 983296** (bool). Было `false`.
  SET `true` → через несколько секунд открываются порты **554 (RTSP)** и **8899 (ONVIF)**.
  DPID_EXTPROT_RTSP_AUDIO_SW = 983297 — звук в RTSP (по умолчанию `false`); после `true`
  в обоих потоках появляется дорожка **pcm_alaw 8 кГц моно**.
- Потоки: `rtsp://admin:<пароль камеры>@<ip>:554/live/ch00_0` — H.264 1280×720,
  `…/live/ch00_1` — H.264 640×360. Транспорт TCP. Задержка < 1 с, ~20 к/с.
  Камера держит несколько RTSP-сессий одновременно (проверено 2: видео + аудио).
- Часы камеры (OSD на кадре) идут по UTC.
- GUI: кнопка «Живое видео» — включает ONVIF_SW и RTSP_AUDIO_SW при необходимости, ждёт
  порт 554, запускает два ffmpeg: видео (`-allowed_media_types video … -f rawvideo
  -pix_fmt bgr24 -`, кадры в окно) и звук (`-allowed_media_types audio … -ar 16000 -f
  s16le -`, в waveOut; очередь ≤ 0,5 с, лишнее отбрасывается, чтобы не копилась задержка).

Записи, которая пишется сейчас, в REC_FILE_LIST нет, а 197154 с pts внутри неё → 2001,
так что «почти живое» через воспроизведение отстаёт на длину сегмента (5 мин) — не нужно.

### Метка времени кадра и скорость выдачи записи

- В расшифрованном 32-байтном заголовке кадра **байты 10..15 — время кадра в мс** (uint48 LE).
  У первого кадра оно равно началу сегмента (`startMs` из REC_FILE_LIST). Видео идёт с шагом
  ~50 мс, аудио — блоками по 960 байт A-law 16 кГц (60 мс). Байты 2..3 — номер кадра своего типа.
- Скорость выдачи зависит от кредита `frames` в 197154 (замер на кабеле, 20 с):
  100 → 0,81× реального времени (воспроизведение отстаёт), 400 → 1,45×, 1000 → 1,66×,
  3000 → 1,93×. GUI шлёт 1000 и в первом запросе, и при пополнении по info_id=4.
  По Wi-Fi камера отдала тот же 66-секундный сегмент с вдвое меньшим числом видеокадров
  (585 против ~1300 по кабелю) — похоже, при медленном канале прореживает кадры.
- GUI «Смотреть»: кадры копятся в очередях и выдаются по меткам времени — видео в
  `ffmpeg -f h264 -i - … -f rawvideo -` (stdin/stdout pipe), звук декодируется из A-law
  прямо в программе и уходит в waveOut с опережением 300 мс (очередь начинается с такой же
  тишины). Старт после 1 с буфера; замер: 40 с реального времени = 40 с записи.

### Подсветка (белый свет)

Группа DGID_IOTC_LIGHT = 5. Способности `data.light = [0,0,7,10,3]`: ИК-подсветки нет
(IRLED = 0), белый свет WLIGHT = 7 = SWITCH | SCHEDULE | SENSITIVITY.

| dpid | имя | значение на камере |
|---|---|---|
| 327936 | DPID_LIGHT_FLOODLIGHT_SW | int: **0** (заводское), **1** = включён, **2** = выключен; 3 → 1106 |
| 327937 | DPID_LIGHT_FLOODLIGHT_STATUS | горит ли сейчас: 1 = да, 2 = нет |
| 327938 | DPID_LIGHT_FLOODLIGHT_LIGHTNESS | 1114 |
| 327939 | DPID_LIGHT_FLOODLIGHT_SENSITIVITY | 2 |
| 327940 | DPID_LIGHT_SCHEDULE | `{defaultAction, capability, total, time_schedule:[{enable,s_time,e_time}]}` |
| 327941 | DPID_LIGHT_INDICATOR_SW | 1114 |

Проверено вживую: SW = 1 → STATUS = 1, кадр из ночного ч/б становится цветным; SW = 2 →
STATUS = 2. Значение 0 — заводское; по способностям (расписание, чувствительность) это,
видимо, автоматический режим, но его срабатывание (свет по движению в темноте) не
проверялось. GUI: список «Свет» (Выключен = 2, Включён = 1, Авто = 0), SET одного свойства.

### Сеть: кабель / Wi-Fi

Группа DGID_IOTC_NETWORK = 4 (Protocol.java):

| dpid | имя | что видно на камере |
|---|---|---|
| 262400 | DPID_NET_STATIC_IP | `{network_ip_sw:false, network_ip, network_mask, network_gateway, network_dns1/2}` |
| 262401 | DPID_NET_NETWORK_MODE | активный интерфейс: **8 = Ethernet, 2 = Wi-Fi** |
| 262402 | DPID_NET_MODULE_SIGNAL_LEVEL | на кабеле → 2001, на Wi-Fi → 0 |
| 262403 | DPID_NET_WIFI_AP_SSID | имя своей точки доступа: `HSC_102802372` |
| 262404 | DPID_NET_WIFI_STA_SSID | сеть Wi-Fi, к которой привязана камера |
| 262405 | DPID_NET_WIFI_AP_PWD | 1114 (не поддерживается) |

Способности `data.net = [41, 3]`: интерфейсы 41 = Wi-Fi 2.4 | Ethernet | BLE (5 ГГц нет),
настройка 3 = ROUTER_CFG | STATIC_IP.

Смена Wi-Fi — действие **DAID_NET_CONFIG 262656** (ACTION 197384) `{"mode":M,"ssid":b64,"pwd":b64}`:
- `mode:1` — `setWiFiAPConfig`, камера в режиме точки доступа (первая настройка, `provision`);
- `mode:2` — `setNetworkConfig` для IoT-камеры, которая уже в сети (экран «Сеть» в приложении).

Проверено (mode 2 на кабеле): ответ 1000, STA_SSID сразу стал новым, перезагрузки нет,
NETWORK_MODE остаётся 8 — пока подключён кабель, камера работает через него, в Wi-Fi-сети
её нет. После отключения кабеля камера ушла в Wi-Fi (NETWORK_MODE = 2) с новым адресом по
DHCP (другой MAC: 192.168.10.5 → 192.168.10.7); настройки записи, тревоги и RTSP
сохранились, список записей и живое видео работают. UDP-поиск `CMD_DEVICE_LAN_SCAN` камера не отвечает; GUI ищет её перебором
адресов /24 всех своих интерфейсов по TCP 8089 с проверкой пароля.

### Живой поток (live view) — история реверса собственного протокола

- Метод LIVE_CTRL = 197122 (ответ 197123). Ключи запроса (из HSLiveDataV3Transmitter):
  quality, video, audio, IDRreq, vsspec (+ key_exchange: uuid, cS). Метод в дизасме
  также 0x30200=197120, но он игнорируется.
- На управляющей сессии 197122 ВСЕГДА возвращает только `{"data":{"lines":{up,upmax,
  down,downmax}}}` (пропускная способность) и НЕ стартует поток — ни кадров, ни notify.
  Перепробовано: с/без IDRreq, quality, с обменом ключами (uuid/cS в запросе), 197120,
  двухшагово (negotiate→start). Официальное приложение V380 при этом не запущено.
- Вывод: живое видео идёт по ОТДЕЛЬНОМУ медиа-каналу (вероятно, своё соединение +
  обмен ключами + стрим), в отличие от воспроизведения/скачивания, которое работает по
  управляющей сессии. Нужен отдельный реверс канала live (сравнимо по объёму с реверсом
  воспроизведения). Near-live через воспроизведение не подходит: последний завершённый
  сегмент отстаёт на ~10 мин.

### Живой поток — проход 3 (Ghidra, getDataFromDeviceOrServer @0x4c810, 25918 б)

ИСПРАВЛЕНИЕ прохода 2: канал НЕ UDP. `socket(2,1,0)` = AF_INET/SOCK_STREAM = **TCP**
(sendto/recvfrom с NULL-адресом работают на connected-TCP). Полная декомпиляция
`getDataFromDeviceOrServer` (900с) раскрыла путь транспортёра `HSLiveDataV3Transmitter`:

- **Отдельное TCP-соединение** к IP камеры : порт (`inet_addr(param_5)`, порт `param_6`
  из поля транспортёра +0x344). Управляющую сессию не трогает.
- **Свой обмен ключами**, метод **0x30108 = 196872** (сосед LANPASS-логина 196870),
  через `initIotcReq(...,0x30108,json)`; JSON из 2 строковых полей (имена в rodata
  зашифрованы, статически не читаются) → `parseKeyExchange` → ключ медиа-сессии.
- **Стрим-запрос** метод **0x30202 = 197122**, keep-alive **0x30200 = 197120**. Payload
  стрима — вложенный объект `{quality, video:1.0, audio, IDRreq:1.0 (+vsspec)}`.
- Кадры — та же выборочная AES-CBC (лог `cipher_result: quality/type/seq/len/ts/...`).

**Эмпирика на камере 192.168.10.5 (всё проверено живьём):**
- Открыт ТОЛЬКО порт 8089 (скан 24 портов) — отдельного медиапорта нет.
- Метод **196872 камера отвергает с code 1110** при ЛЮБОМ payload (verify-nested,
  плоский cKM/cS, pub/sign, пустой) и после логина, и на свежем сокете. Значит это
  облачный/relay-путь (сервер-посредник), а прямой LAN его не принимает.
- **197122 на LAN = только статистика полосы** `{"data":{"lines":{up,down,...}}}`
  (code 1000), поток не стартует — с b2=sid и без, с вложенным/плоским payload.
- Кадры (CMD_COMMON_MEDIA 939722784) на управляющей сессии даёт ТОЛЬКО 197154
  (REPLAY_CTRL) для РЕАЛЬНОЙ записанной позиции pts (download работает). pts=now или
  pts=-1 → code 2001 (нет данных в этой позиции — запись по движению, «сейчас» пусто).
- Развёртка методов 0x30000..0x30122 и 0x30200..0x30322 (b2=sid, {video,audio,frames}) —
  ни один не отдаёт MEDIA вне 197154.

**Проход 3b — почему 196872 нельзя пройти по LAN (decomp3.txt).** После логина 196872
отвечает 1106 (нет params), с полем `cS` — 1119 (подпись/ключ не проходит), значение
`uuid` на код не влияет. Декомпиляция показала, что ОБА поля keyExchange **предвычислены
при инициализации** и лежат в объекте транспортёра: field1 (uuid) — строка по +0x15c,
field2 (cS, 64 б) — блоб по +0x1dc. Заполняет их `HSLiveDataV3Transmitter::
refreshMqKeyExchangeInfo(uuid, blob2, blob3)` (@0x53f04): `strcpy(this+0x15c, uuid)` и
копии 64-байтных блобов в +0x19c/+0x1dc из param_2/param_3. **«Mq» = облачный
message-queue (MQTT).** То есть uuid и cS-блоб ВЫДАЁТ ОБЛАКО производителя при P2P/облачном
сеансе — это не локально вычисляемая из пароля подпись (как в LAN-логине 196870). Без
облака поле пустое → keyExchange медиа-канала отвергается (1119).

**ОКОНЧАТЕЛЬНЫЙ ВЫВОД:** истинное «живое видео сейчас» на этой камере завязано на облако
Macrovideo (keyExchange медиа-канала авторизуется cloud-выданными uuid+блобом через MQTT).
Чистого LAN-пути к живому НЕТ — что согласуется с исходным симптомом (официальное
приложение к камере не подключается = облачная привязка не работает). По LAN доступно
только воспроизведение записей (197154) — оно работает (download/list). Near-live через
replay не годится: запись по движению, последний сегмент отстаёт.
Зонды: scratchpad/tools/{liveprobe,liveprobe2,sweep,sweep2,kx,kx2,snap}.py. Ghidra-проект —
scratchpad/tools/ghproj (ghidra.zip там же; scratchpad чистит распакованную папку).
