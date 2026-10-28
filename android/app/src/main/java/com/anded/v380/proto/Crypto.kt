package com.anded.v380.proto

import android.util.Base64
import org.bouncycastle.math.ec.rfc7748.X25519
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal object Crypto {
    val rnd = SecureRandom()

    fun x25519Base(priv: ByteArray): ByteArray =
        ByteArray(32).also { X25519.scalarMultBase(priv, 0, it, 0) }

    fun x25519(priv: ByteArray, pub: ByteArray): ByteArray =
        ByteArray(32).also { X25519.scalarMult(priv, 0, pub, 0, it, 0) }

    fun sha256(d: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(d)

    /** AES-128-CBC без паддинга: ключ = key[0:16], IV передаётся явно. Длина кратна 16. */
    fun cbc(encrypt: Boolean, key: ByteArray, iv: ByteArray, data: ByteArray, off: Int = 0, len: Int = data.size): ByteArray {
        val c = Cipher.getInstance("AES/CBC/NoPadding")
        c.init(
            if (encrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE,
            SecretKeySpec(key, 0, 16, "AES"),
            IvParameterSpec(iv, 0, 16),
        )
        return c.doFinal(data, off, len)
    }

    fun pkcs7pad(d: ByteArray): ByteArray {
        val n = 16 - d.size % 16
        return d + ByteArray(n) { n.toByte() }
    }

    fun pkcs7unpad(d: ByteArray): ByteArray {
        if (d.isEmpty()) return d
        val n = d.last().toInt() and 0xff
        if (n in 1..16 && n <= d.size && (1..n).all { d[d.size - it].toInt() and 0xff == n }) {
            return d.copyOf(d.size - n)
        }
        return d
    }

    fun b64(d: ByteArray): String = Base64.encodeToString(d, Base64.NO_WRAP)
    fun unb64(s: String): ByteArray = Base64.decode(s, Base64.DEFAULT)
}
