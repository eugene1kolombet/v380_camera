package com.anded.v380.proto

import com.anded.v380.I18n
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Поиск камеры: UDP-поиск камера не отвечает, поэтому, как в v380gui, перебираем адреса /24
 * своих сетей по TCP 8089 и проверяем вход паролем.
 */
@OptIn(ExperimentalCoroutinesApi::class)
object Discovery {
    /** Свои IPv4-адреса в локальных сетях (Wi-Fi и Ethernet; сотовая сеть пропускается). */
    fun ownAddresses(ctx: Context): List<Inet4Address> {
        val cm = ctx.getSystemService(ConnectivityManager::class.java)
        val res = ArrayList<Inet4Address>()
        @Suppress("DEPRECATION")
        for (n in cm.allNetworks) {
            val caps = cm.getNetworkCapabilities(n) ?: continue
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) continue
            val lp = cm.getLinkProperties(n) ?: continue
            for (la in lp.linkAddresses) {
                val a = la.address
                if (a is Inet4Address && !a.isLoopbackAddress && !a.isLinkLocalAddress) res += a
            }
        }
        return res
    }

    suspend fun find(ctx: Context, password: String, onStatus: (String) -> Unit): String? = withContext(Dispatchers.IO) {
        val own = ownAddresses(ctx)
        if (own.isEmpty()) {
            onStatus(I18n.s.phoneNotOnLan)
            return@withContext null
        }
        val nets = own.map { it.address.copyOf(3) }.distinctBy { it.toList() }
        val ownSet = own.map { it.hostAddress }.toSet()
        val io = Dispatchers.IO.limitedParallelism(64)
        for (net in nets) {
            val prefix = net.joinToString(".") { (it.toInt() and 0xff).toString() }
            onStatus(I18n.s.searchingIn(prefix))
            val open = coroutineScope {
                (1..254).map { h ->
                    async(io) {
                        val ip = "$prefix.$h"
                        if (ip in ownSet) return@async null
                        try {
                            Socket().use { it.connect(InetSocketAddress(ip, V380Session.port), 700) }
                            ip
                        } catch (_: Exception) {
                            null
                        }
                    }
                }.awaitAll().filterNotNull()
            }
            for (ip in open) {
                onStatus(I18n.s.checking(ip))
                try {
                    V380Session.open(ip, password).close()
                    return@withContext ip
                } catch (_: Exception) {
                }
            }
        }
        null
    }
}
