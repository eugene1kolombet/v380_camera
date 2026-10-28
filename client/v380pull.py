#!/usr/bin/env python3
"""
v380pull — скачивание записей с камеры V380 Pro по локальной сети.

Протокол восстановлен из декомпилированного SDK приложения V380 Pro 2.2.90
(com.macrovideo.sdk). Это не официальный код — см. README.md, раздел
«Что проверено, а что нужно подтвердить на камере».

Поток работы (LAN):
  1. TCP-подключение к камере (порт 8089 — IoT-прошивки, 8800 — легаси).
  2. Обмен ключами X25519 + проверка пароля камеры (sha256(pub||pwd)).
     В локальной сети это одновременно и вход — отдельного логина нет.
  3. Запрос списка записей (метод REC_FILE_LIST) за диапазон времени.
  4. Скачивание файла по пути (метод FILE_DOWNLOAD) с возобновлением по смещению.

Зависимости: pip install cryptography
"""

import argparse
import base64
import hashlib
import json
import os
import secrets
import socket
import string
import struct
import sys
import time
from datetime import datetime, timedelta

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    sys.exit("Нужна библиотека cryptography:  pip install cryptography")

# ---------------------------------------------------------------------------
# Константы протокола (из com.macrovideo.sdk.defines.Protocol / Defines)
# ---------------------------------------------------------------------------

CMD_COMMON_IOT = 939722776  # заголовок всех IoT-пакетов (cmd в 16-байтном хедере)

METHOD_ID_IOTC_LANPASS_REQUEST = 196870
METHOD_ID_IOTC_LANPASS_RESPONSE = 196871
METHOD_ID_REC_FILE_LIST_REQUEST = 197152
METHOD_ID_REC_FILE_LIST_RESPONSE = 197153
METHOD_ID_FILE_DOWNLOAD_REQUEST = 197184
METHOD_ID_FILE_DOWNLOAD_RESPONSE = 197185
METHOD_ID_FILE_LIST_REQUEST = 197190
METHOD_ID_FILE_LIST_RESPONSE = 197191
METHOD_ID_ACTION_REQUEST = 197384
METHOD_ID_ACTION_RESPONSE = 197385
METHOD_ID_REPLAY_CTRL_REQUEST = 197154   # старт воспроизведения записи
METHOD_ID_REPLAY_CTRL_RESPONSE = 197155
METHOD_ID_REPLAY_INFORMATION = 197156    # NOTIFY: инфо сегмента / alive
CMD_COMMON_MEDIA = 939722784             # пакет видео/аудио кадра
CMD_COMMON_NOTIFY = 939722786            # NOTIFY (JSON)

# «Действие устройства» DAID_NET_CONFIG = MVSPT_IOTC_DAID(DGID_IOTC_NETWORK=4, idx=0)
#   = (idx & 255) | ((4 & 255) << 16) | 512  = 262656
DAID_NET_CONFIG = (4 << 16) | 512  # 262656

# Адрес камеры в режиме точки доступа (AP): она — шлюз своей сети.
AP_DEFAULT_IP = "192.168.1.1"

PORT_IOT = 8089   # Protocol.IOT_PLATFORM_DEVICE_DEFAULT_PORT
PORT_LEGACY = 8800  # Defines._MRPort

SECURE_PLAIN = 0
SECURE_TYPE1 = 1
SECURE_TYPE2 = 2  # то, что реально использует прошивка 2.2.90

# Статический ключ, которым шифруется САМ пакет обмена ключами (LoginHelper.i).
# 32 байта: [0:16] — ключ AES, [16:32] — IV.
HANDSHAKE_KEY = bytes([
    54, 58, 229, 40, 22, 56, 207, 132, 150, 154, 99, 78, 159, 150, 106, 152,
    181, 115, 209, 255, 233, 55, 178, 119, 209, 241, 214, 43, 56, 116, 138, 229,
])

# Типы записей — битовая маска IOT_REC_TYPE_* (filter).
# ВАЖНО: «все типы» в IoT-протоколе = 15, а не 0 (0 возвращает пустой список).
REC_TYPE_ALL = 15      # IOT_REC_TYPE_ALL (AUTO|ALARM|MINIATURE|AOV)
REC_TYPE_AUTO = 1      # обычная запись по расписанию
REC_TYPE_ALARM = 2     # по движению/тревоге
REC_TYPE_MINIATURE = 4
REC_TYPE_AOV = 8
SEARCH_MODE_LIST = 2   # RecordFileHelper.SEARCH_MODE_LIST

REC_TYPE_NAMES = {1: "по расписанию", 2: "движение/тревога", 4: "миниатюра", 8: "AOV"}

DEBUG = False


def dbg(*a):
    if DEBUG:
        print("[debug]", *a, file=sys.stderr)


def hx(b):
    return b.hex() if b else ""


# ---------------------------------------------------------------------------
# Крипто-слой пакета.  secure==2 -> AES-128-CBC/PKCS7, ключ=key[0:16], iv=key[16:32].
#
# ВНИМАНИЕ: сам шифр в приложении делает нативная libHSMbedtls (mbedtls).
# Java отдаёт туда key[0:16] и iv[16:32] от 32-байтного ключа — это однозначно
# указывает на AES-128-CBC.  Если первый живой запрос к камере не расшифруется,
# менять нужно ТОЛЬКО эти две функции (например, на ECB) — остальной код не трогать.
# ---------------------------------------------------------------------------

def _pkcs7_pad(data, block=16):
    n = block - (len(data) % block)
    return data + bytes([n]) * n


def _pkcs7_unpad(data):
    if not data:
        return data
    n = data[-1]
    if 1 <= n <= 16 and data[-n:] == bytes([n]) * n:
        return data[:-n]
    return data  # не трогаем, если padding не похож на PKCS7


def cipher_encrypt(plaintext, key32, secure=SECURE_TYPE2):
    if secure == SECURE_PLAIN:
        return plaintext
    key, iv = key32[:16], key32[16:32]
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(_pkcs7_pad(plaintext)) + enc.finalize()


def cipher_decrypt(ciphertext, key32, secure=SECURE_TYPE2):
    if secure == SECURE_PLAIN:
        return ciphertext
    key, iv = key32[:16], key32[16:32]
    if len(ciphertext) % 16:
        ciphertext = ciphertext[: len(ciphertext) - (len(ciphertext) % 16)]
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return _pkcs7_unpad(dec.update(ciphertext) + dec.finalize())


# ---------------------------------------------------------------------------
# Кадрирование пакета (Protocol.createCommonJsonRequestBuffer / parseResponseHeader)
# 16-байтный заголовок, little-endian:
#   [0:4]  cmd  (CMD_COMMON_IOT)
#   [4]    version (1)
#   [5]    secureType
#   [6]    b2  (обмен ключами: 0;  после входа: sid)
#   [7]    b3  (обмен ключами: magic;  после входа: 0)
#   [8:12] 0
#   [12:16] длина полезных данных
# ---------------------------------------------------------------------------

def build_packet(method_id, params, key32, secure=SECURE_TYPE2,
                 b2=0, b3=0, chn=1, rand_id=None):
    if rand_id is None:
        rand_id = secrets.randbits(31)
    header_json = {
        "id": rand_id,
        "method_id": method_id,
        "chn": chn,
        "ts": int(time.time()),
        "params": params,
    }
    body = json.dumps(header_json, separators=(",", ":")).encode("utf-8")
    enc = cipher_encrypt(body, key32, secure)
    hdr = bytearray(16)
    struct.pack_into("<I", hdr, 0, CMD_COMMON_IOT & 0xFFFFFFFF)
    hdr[4] = 1
    hdr[5] = secure
    hdr[6] = b2 & 0xFF
    hdr[7] = b3 & 0xFF
    struct.pack_into("<I", hdr, 12, len(enc))
    dbg("send method", method_id, "rand", rand_id, "json", header_json)
    return bytes(hdr) + enc, rand_id


def read_exact(sock, n, timeout=8.0):
    sock.settimeout(timeout)
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def read_packet(sock, key32):
    """Читает один ответный пакет -> (cmd, secure, dict|None, raw_payload)."""
    hdr = read_exact(sock, 16)
    if len(hdr) < 16:
        raise IOError("короткий заголовок ответа (%d байт)" % len(hdr))
    cmd = struct.unpack_from("<I", hdr, 0)[0]
    secure = hdr[5]
    data_size = struct.unpack_from("<I", hdr, 12)[0]
    payload = read_exact(sock, data_size) if data_size else b""
    dbg("recv cmd", cmd, "secure", secure, "size", data_size, "hdr", hx(hdr))
    obj = None
    if payload:
        try:
            text = cipher_decrypt(payload, key32, secure).decode("utf-8", "replace")
            obj = json.loads(text)
            dbg("recv json", obj)
        except Exception as e:  # noqa: BLE001
            dbg("не JSON / не расшифровалось:", e, "payloadHex", hx(payload[:64]))
    return cmd, secure, obj, payload


# ---------------------------------------------------------------------------
# Обмен ключами X25519 = вход в локальной сети
# ---------------------------------------------------------------------------

def _rand_seed32():
    alphabet = (string.ascii_letters + string.digits).encode()
    return bytes(secrets.choice(alphabet) for _ in range(32))


def _xor(data, one_byte):
    return bytes(b ^ one_byte for b in data)


def lan_login(sock, lan_password):
    """Возвращает (session_key32, sid, perm).  Бросает RuntimeError при отказе."""
    seed = _rand_seed32()
    priv = X25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes_raw()  # 32 байта

    magic = secrets.randbits(8)
    pub_xored = _xor(pub, magic)
    ckm = base64.b64encode(pub_xored).decode()
    cs = base64.b64encode(
        hashlib.sha256(pub_xored + lan_password.encode()).digest()
    ).decode()

    params = {
        "act": 1,
        "verify": {
            "cKM": ckm,
            "cS": cs,
            "tz": _timezone_value(),
            "ts": int(time.time()),
        },
    }
    pkt, rand_id = build_packet(
        METHOD_ID_IOTC_LANPASS_REQUEST, params, HANDSHAKE_KEY,
        secure=SECURE_TYPE2, b2=0, b3=magic,
    )
    sock.sendall(pkt)

    cmd, secure, obj, _ = read_packet(sock, HANDSHAKE_KEY)
    if cmd != CMD_COMMON_IOT or obj is None:
        raise RuntimeError("камера ответила не тем пакетом на обмен ключами "
                           "(cmd=%s). Проверьте порт/шифр — см. README." % cmd)

    verify = (obj.get("data") or {}).get("verify") or {}
    dk_b64 = verify.get("dK")
    ds_b64 = verify.get("dS")
    if not dk_b64:
        code = (obj.get("result") or {}).get("code")
        raise RuntimeError("обмен ключами отклонён камерой (code=%s). "
                           "Чаще всего — неверный пароль камеры." % code)

    dk = base64.b64decode(dk_b64)
    # Проверка dS = sha256(dK), как в приложении.
    if ds_b64 and base64.b64encode(hashlib.sha256(dk).digest()).decode() != ds_b64:
        print("! предупреждение: dS не совпал с sha256(dK) — продолжаю всё равно",
              file=sys.stderr)

    peer = X25519PublicKey.from_public_bytes(dk)
    session_key = priv.exchange(peer)  # 32 байта — общий секрет = ключ сессии
    sid = int(verify.get("sid", 0))
    perm = verify.get("perm")
    dbg("session_key", hx(session_key), "sid", sid, "perm", perm)
    return session_key, sid, perm


def _timezone_value():
    """Пояс в формате камеры: часы*100 + минуты (UTC+3 -> 300), как
    DatetimeUtils.getCustomTimeZone2 в приложении (число, не строка "+03:00")."""
    off = -time.timezone if (time.localtime().tm_isdst == 0) else -time.altzone
    sign = 1 if off >= 0 else -1
    off = abs(off) // 60
    return sign * (off // 60 * 100 + off % 60)


# ---------------------------------------------------------------------------
# Передача камере Wi-Fi сети (провижининг в режиме AP)
# DeviceNetworkSetting.setWiFiAPConfig -> действие DAID_NET_CONFIG
# ---------------------------------------------------------------------------

def set_wifi(sock, session_key, sid, ssid, wifi_password):
    inner = {
        "mode": 1,
        "ssid": base64.b64encode(ssid.encode()).decode(),
        "pwd": base64.b64encode(wifi_password.encode()).decode(),
    }
    params = {"daid": DAID_NET_CONFIG, "in": inner}
    pkt, rand_id = build_packet(
        METHOD_ID_ACTION_REQUEST, params, session_key,
        secure=SECURE_TYPE2, b2=sid, b3=0,
    )
    sock.sendall(pkt)
    try:
        cmd, secure, obj, _ = read_packet(sock, session_key)
    except (IOError, socket.timeout):
        # Камера может сразу уйти перезагружаться и не ответить — это не всегда ошибка.
        return None, None
    code = (obj or {}).get("result", {}).get("code") if obj else None
    return code, obj


# ---------------------------------------------------------------------------
# Воспроизведение записи: запуск потока кадров (РАБОТАЕТ — video:1,audio:1)
# Дешифр тела кадра ещё дорабатывается (см. PROTOCOL_NOTES.md «Проход 5/6»).
# ---------------------------------------------------------------------------

def start_replay(sock, session_key, sid, seg_start_ms, rec_type,
                 time_id=1, frames=100, video=1, audio=1, vsspec=0):
    """Запускает воспроизведение сегмента. Возвращает (code, obj) ответа 197155."""
    params = {"pts": seg_start_ms, "sts": seg_start_ms, "rtype": rec_type,
              "time_id": time_id, "vsspec": vsspec, "frames": frames,
              "video": video, "audio": audio}
    pkt, rand_id = build_packet(
        METHOD_ID_REPLAY_CTRL_REQUEST, params, session_key,
        secure=SECURE_TYPE2, b2=sid, b3=0,
    )
    sock.sendall(pkt)
    return rand_id


def _frame_decrypt(body, key, iv):
    """Расшифровывает MEDIA-кадр. Шифр — AES-128-CBC (ключ=session[:16], iv=session[16:32]),
    выборочно: [32б заголовок CBC] затем тело = plen открытых, далее повтор
    [elen шифр (CBC-цепочка продолжается) + slen открытых], хвост открытый.
    plen/elen/slen берутся из расшифрованного заголовка (offsets 0x12/0x16/0x1a).
    Возвращает (тип_кадра, payload). Тип: 1=видео-I, 2=видео-P, 4=аудио."""
    prev = [iv]

    def dec_region(data):
        out = bytearray()
        n = len(data) - len(data) % 16
        for i in range(0, n, 16):
            blk = bytes(data[i:i + 16])
            pt = Cipher(algorithms.AES(key), modes.ECB()).decryptor().update(blk)
            out += bytes(a ^ b for a, b in zip(pt, prev[0]))
            prev[0] = blk
        return bytes(out)

    hdr = dec_region(body[:32])
    plen = int.from_bytes(hdr[0x12:0x16], "little")
    elen = int.from_bytes(hdr[0x16:0x1a], "little")
    slen = int.from_bytes(hdr[0x1a:0x1e], "little")
    pos, rem = 32, len(body) - 32
    out = bytearray()
    out += body[pos:pos + plen]; pos += plen; rem -= plen
    while elen > 0 and rem >= elen:
        out += dec_region(body[pos:pos + elen]); pos += elen; rem -= elen
        sk2 = min(slen, rem)
        out += body[pos:pos + sk2]; pos += sk2; rem -= sk2
    out += body[pos:pos + rem]
    return hdr[1], bytes(out)


def download_recording(sock, session_key, sid, seg, out_mp4, ffmpeg="ffmpeg",
                       max_seconds=None):
    """Скачивает запись сегмента в mp4 (видео H.264). Запускает воспроизведение,
    пополняет кредит кадров на каждый alive, расшифровывает кадры, собирает mp4."""
    import subprocess, tempfile, os
    key, iv = session_key[:16], session_key[16:32]
    seg_ms = int(seg["start"].timestamp() * 1000)
    dur = seg["duration_s"]
    limit = max_seconds if max_seconds else dur + 15

    def req(params):
        pkt, _ = build_packet(METHOD_ID_REPLAY_CTRL_REQUEST, params, session_key,
                              secure=SECURE_TYPE2, b2=sid, b3=0)
        sock.sendall(pkt)

    req({"pts": seg_ms, "sts": seg_ms, "rtype": seg["type"], "time_id": 1,
         "vsspec": 0, "frames": 100, "video": 1, "audio": 1})

    video = bytearray(); audio = bytearray(); nv = 0; na = 0
    sock.settimeout(8.0); t0 = time.time(); done = False
    while not done and time.time() - t0 < limit:
        try:
            hdr = read_exact(sock, 16, 8.0)
        except (IOError, socket.timeout):
            break
        if len(hdr) < 16:
            break
        cmd = struct.unpack_from("<I", hdr, 0)[0]
        secure = hdr[5]
        data_size = struct.unpack_from("<I", hdr, 12)[0]
        body = read_exact(sock, data_size, 8.0) if data_size else b""
        if cmd == CMD_COMMON_MEDIA:
            ftype, payload = _frame_decrypt(body, key, iv)
            if ftype in (1, 2):          # видео I/P
                video += payload; nv += 1
            elif ftype == 4:             # аудио G.711 A-law (codec 103)
                audio += payload; na += 1
        elif cmd == CMD_COMMON_NOTIFY:
            try:
                o = json.loads(cipher_decrypt(body, session_key, secure).decode("utf-8", "replace"))
            except Exception:  # noqa: BLE001
                continue
            iid = (o.get("params") or {}).get("info_id")
            if iid == 4:                     # alive -> пополнить кредит кадров
                req({"time_id": 1, "frames": 100})
            elif iid == 3:                   # finish
                done = True

    if nv == 0:
        return 0, 0, None
    fps = max(1, round(nv / dur)) if dur > 0 else 15
    vtmp = out_mp4 + ".h264"
    with open(vtmp, "wb") as f:
        f.write(video)
    cmd = [ffmpeg, "-v", "error", "-y", "-r", str(fps), "-i", vtmp]
    atmp = None
    if audio:                               # G.711 A-law, 16 кГц моно -> AAC
        atmp = out_mp4 + ".alaw"
        with open(atmp, "wb") as f:
            f.write(audio)
        cmd += ["-f", "alaw", "-ar", "16000", "-ac", "1", "-i", atmp,
                "-map", "0:v:0", "-map", "1:a:0",
                "-c:v", "copy", "-c:a", "aac", out_mp4]
    else:
        cmd += ["-c", "copy", out_mp4]
    r = subprocess.run(cmd, capture_output=True, text=True)
    for p in (vtmp, atmp):
        if p:
            try:
                os.remove(p)
            except OSError:
                pass
    if r.returncode != 0:
        raise RuntimeError("ffmpeg: " + r.stderr[:200])
    return nv, na, fps


def capture_media_raw(sock, session_key, out_path, seconds=8.0):
    """Пишет сырые MEDIA-пакеты (cmd 939722784) в файл: [4б len][тело]… для анализа.
    Тело = [32б заголовок кадра][payload]. Возвращает число пакетов."""
    sock.settimeout(seconds)
    t0 = time.time()
    n = 0
    with open(out_path, "wb") as f:
        while time.time() - t0 < seconds:
            try:
                hdr = read_exact(sock, 16, seconds)
            except (IOError, socket.timeout):
                break
            if len(hdr) < 16:
                break
            cmd = struct.unpack_from("<I", hdr, 0)[0]
            data_size = struct.unpack_from("<I", hdr, 12)[0]
            body = read_exact(sock, data_size, seconds) if data_size else b""
            if cmd == CMD_COMMON_MEDIA:
                f.write(struct.pack("<I", len(body)) + body)
                n += 1
    return n


# ---------------------------------------------------------------------------
# Список записей за период
# ---------------------------------------------------------------------------

def list_recordings(sock, session_key, sid, start_dt, end_dt,
                    rec_type=REC_TYPE_ALL, mode=SEARCH_MODE_LIST):
    start_ms = int(start_dt.timestamp() * 1000)
    end_ms = int(end_dt.timestamp() * 1000)
    params = {"filter": rec_type, "mode": mode, "start": start_ms, "end": end_ms}
    pkt, rand_id = build_packet(
        METHOD_ID_REC_FILE_LIST_REQUEST, params, session_key,
        secure=SECURE_TYPE2, b2=sid, b3=0,
    )
    sock.sendall(pkt)

    segments = []
    # Камера отдаёт список срезами; flag!=0 означает «есть ещё».
    while True:
        try:
            cmd, secure, obj, _ = read_packet(sock, session_key)
        except (IOError, socket.timeout):
            break
        if obj is None:
            break
        data = obj.get("data") or {}
        for d in data.get("list") or []:
            s = d.get("s", 0)        # смещение начала от start, мс
            dur = d.get("d", 0)      # длительность, мс
            segments.append({
                "start": datetime.fromtimestamp((start_ms + s) / 1000),
                "offset_ms": s,
                "duration_s": dur / 1000.0,
                "type": d.get("t", 0),
                "raw": d,
            })
        if not data.get("flag"):  # 0 / отсутствует -> последний срез
            break
    return segments


# ---------------------------------------------------------------------------
# Скачивание файла по пути (generic FILE_DOWNLOAD)
# ---------------------------------------------------------------------------

def download_file(sock, session_key, sid, dfid, vfp, out_path, vfid=1):
    """Скачивает именованный файл vfp в out_path, с возобновлением по смещению."""
    off = os.path.getsize(out_path) if os.path.exists(out_path) else 0
    mode = "ab" if off else "wb"
    params = {
        "vfid": (vfid % 25 or 1) + 225,  # DeviceFileSetting.downloadFile
        "dfid": dfid,
        "vfp": vfp,
        "off": off,
    }
    pkt, rand_id = build_packet(
        METHOD_ID_FILE_DOWNLOAD_REQUEST, params, session_key,
        secure=SECURE_TYPE2, b2=sid, b3=0,
    )
    sock.sendall(pkt)

    written = 0
    with open(out_path, mode) as f:
        while True:
            try:
                cmd, secure, obj, payload = read_packet(sock, session_key)
            except (IOError, socket.timeout):
                break
            if obj is not None:
                code = (obj.get("result") or {}).get("code")
                if code not in (None, 1000):
                    print("! камера вернула код %s на скачивание" % code,
                          file=sys.stderr)
                    break
                data = obj.get("data") or {}
                if data.get("eof") or data.get("fin"):
                    break
                # Управляющий пакет без двоичных данных — читаем дальше.
                continue
            if payload:
                # Двоичный кусок файла (в этой ветке payload не JSON).
                f.write(payload)
                written += len(payload)
            else:
                break
    return off + written


# ---------------------------------------------------------------------------
# Обнаружение камеры в сети (best-effort, UDP CMD_DEVICE_LAN_SCAN)
# ---------------------------------------------------------------------------

def discover(timeout=3.0):
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.settimeout(timeout)
    probe = struct.pack("<I", 1280)  # CMD_DEVICE_LAN_SCAN
    for port in (PORT_IOT, PORT_LEGACY):
        try:
            s.sendto(probe, ("255.255.255.255", port))
        except OSError:
            pass
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            data, addr = s.recvfrom(2048)
        except socket.timeout:
            break
        except OSError:
            break
        found[addr[0]] = len(data)
    s.close()
    return found


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def connect(ip, port):
    s = socket.create_connection((ip, port), timeout=5.0)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


def main():
    global DEBUG
    ap = argparse.ArgumentParser(description="Скачивание записей с камеры V380 по LAN")
    ap.add_argument("--ip", help="IP камеры в локальной сети")
    ap.add_argument("--port", type=int, default=PORT_IOT,
                    help="порт (8089 IoT по умолчанию, 8800 легаси)")
    ap.add_argument("--password", default="", help="пароль камеры (LAN)")
    ap.add_argument("--debug", action="store_true", help="подробный лог пакетов")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("discover", help="найти камеры в сети")

    pp = sub.add_parser("provision",
                        help="передать камере Wi-Fi сеть (камера в режиме AP)")
    pp.add_argument("--ssid", required=True, help="имя Wi-Fi сети роутера")
    pp.add_argument("--wifi-password", default="", help="пароль Wi-Fi сети роутера")

    pl = sub.add_parser("list", help="показать записи за период")
    pl.add_argument("--from", dest="dfrom", help="начало (YYYY-MM-DD[ HH:MM])")
    pl.add_argument("--to", dest="dto", help="конец (YYYY-MM-DD[ HH:MM])")
    pl.add_argument("--hours", type=float, default=24.0,
                    help="если не задан --from: последние N часов (24)")
    pl.add_argument("--type", type=int, default=REC_TYPE_ALL,
                    help="0 все, 1 обычные, 2 движение, 3 тревоги")

    pdl = sub.add_parser("download", help="скачать запись сегмента в mp4 (видео)")
    pdl.add_argument("--seg", type=int, default=0, help="номер сегмента из list")
    pdl.add_argument("--out", default="recording.mp4", help="выходной mp4")
    pdl.add_argument("--ffmpeg", default="ffmpeg", help="путь к ffmpeg")

    pc = sub.add_parser("capture", help="запустить воспроизведение и сохранить сырые кадры")
    pc.add_argument("--seg", type=int, default=0, help="номер сегмента из list (0)")
    pc.add_argument("--out", default="media.raw", help="файл для сырых MEDIA-пакетов")
    pc.add_argument("--seconds", type=float, default=8.0)

    pd = sub.add_parser("download-file", help="скачать файл по пути (vfp)")
    pd.add_argument("--dfid", type=int, required=True, help="идентификатор набора файлов")
    pd.add_argument("--vfp", required=True, help="путь файла на камере")
    pd.add_argument("--out", required=True, help="куда сохранить")

    args = ap.parse_args()
    DEBUG = args.debug

    if args.cmd == "discover":
        found = discover()
        if not found:
            print("Камеры не найдены. Укажите --ip вручную "
                  "(посмотрите в роутере, какой IP у камеры).")
        for ip, n in found.items():
            print("Найдено устройство: %s (ответ %d байт)" % (ip, n))
        return

    # В режиме AP камера — шлюз своей сети (192.168.1.1), IP можно не указывать.
    ip = args.ip or (AP_DEFAULT_IP if args.cmd == "provision" else None)
    if not ip:
        sys.exit("Укажите --ip камеры (или сначала: discover).")

    sock = connect(ip, args.port)
    try:
        print("Вхожу в камеру %s:%d ..." % (ip, args.port))
        session_key, sid, perm = lan_login(sock, args.password)
        print("Вход выполнен (sid=%s)." % sid)

        if args.cmd == "provision":
            print("Передаю камере сеть %r ..." % args.ssid)
            code, obj = set_wifi(sock, session_key, sid,
                                 args.ssid, args.wifi_password)
            if code in (1000, None):
                print("Готово. Камера должна перезагрузиться и подключиться к %r."
                      % args.ssid)
                print("Через ~30 сек подключите ПК обратно к своей сети и "
                      "найдите камеру:  python v380pull.py discover")
            else:
                print("Камера вернула код %s. Запустите с --debug для деталей." % code)
            return

        if args.cmd == "list":
            if args.dfrom:
                start_dt = _parse_dt(args.dfrom)
                end_dt = _parse_dt(args.dto) if args.dto else datetime.now()
            else:
                end_dt = datetime.now()
                start_dt = end_dt - timedelta(hours=args.hours)
            segs = list_recordings(sock, session_key, sid, start_dt, end_dt,
                                   rec_type=args.type)
            if not segs:
                print("Записей за период не найдено "
                      "(или нужно подстроить схему — запустите с --debug).")
            for i, s in enumerate(segs):
                print("%3d  %s  %6.1f c  %s" % (
                    i, s["start"].strftime("%Y-%m-%d %H:%M:%S"),
                    s["duration_s"],
                    REC_TYPE_NAMES.get(s["type"], "тип=%d" % s["type"])))
            print("Всего сегментов: %d" % len(segs))

        elif args.cmd == "download":
            end_dt = datetime.now()
            start_dt = end_dt - timedelta(days=3650)
            segs = list_recordings(sock, session_key, sid, start_dt, end_dt,
                                   rec_type=REC_TYPE_ALL)
            if not segs:
                sys.exit("Записей не найдено.")
            seg = segs[min(args.seg, len(segs) - 1)]
            print("Скачиваю запись %s (%.0f c)..." % (
                seg["start"].strftime("%Y-%m-%d %H:%M:%S"), seg["duration_s"]))
            nv, na, fps = download_recording(sock, session_key, sid, seg,
                                             args.out, ffmpeg=args.ffmpeg)
            if nv == 0:
                sys.exit("Кадры не получены.")
            print("Готово: %d видеокадров (%d аудио) @ %s fps -> %s" % (
                nv, na, fps, args.out))

        elif args.cmd == "capture":
            end_dt = datetime.now()
            start_dt = end_dt - timedelta(days=3650)
            segs = list_recordings(sock, session_key, sid, start_dt, end_dt,
                                   rec_type=REC_TYPE_ALL)
            if not segs:
                sys.exit("Записей не найдено.")
            seg = segs[min(args.seg, len(segs) - 1)]
            seg_ms = int(seg["start"].timestamp() * 1000)
            print("Воспроизвожу сегмент %s (%.0f c)..." % (
                seg["start"].strftime("%Y-%m-%d %H:%M:%S"), seg["duration_s"]))
            start_replay(sock, session_key, sid, seg_ms, seg["type"])
            n = capture_media_raw(sock, session_key, args.out, args.seconds)
            print("Сохранено %d MEDIA-пакетов -> %s" % (n, args.out))

        elif args.cmd == "download-file":
            total = download_file(sock, session_key, sid, args.dfid,
                                  args.vfp, args.out)
            print("Сохранено %d байт -> %s" % (total, args.out))
    finally:
        sock.close()


def _parse_dt(s):
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    raise SystemExit("Не понял дату: %r (нужно YYYY-MM-DD или YYYY-MM-DD HH:MM)" % s)


if __name__ == "__main__":
    main()
