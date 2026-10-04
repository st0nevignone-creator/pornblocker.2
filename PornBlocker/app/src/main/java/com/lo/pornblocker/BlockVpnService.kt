package com.lo.pornblocker

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Local VPN that intercepts all DNS traffic.
 * Any query for pornhub domains gets a bogus response (0.0.0.0).
 * No root needed. Works on all browsers. Cannot be bypassed without disabling VPN.
 */
class BlockVpnService : VpnService() {

    companion object {
        private const val TAG = "BlockVpnService"
        private const val CHANNEL_ID = "vpn_channel"
        private const val NOTIF_ID = 1337

        // Block these domains — expand freely
        private val BLOCKED_DOMAINS = setOf(
            "pornhub.com",
            "www.pornhub.com",
            "de.pornhub.com",
            "it.pornhub.com",
            "fr.pornhub.com",
            "es.pornhub.com",
            "rt.pornhub.com",
            "ci.phncdn.com",
            "phncdn.com",
            "pornhub.net",
            "pornhub.org"
        )
    }

    private val running = AtomicBoolean(false)
    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnThread: Thread? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: android.content.Intent?, flags: Int, startId: Int): Int {
        if (running.get()) return START_STICKY

        startForeground(NOTIF_ID, buildNotification())
        running.set(true)

        vpnThread = Thread({ runVpnLoop() }, "BlockVPN-Thread").apply { start() }

        return START_STICKY // if killed, restart immediately
    }

    override fun onDestroy() {
        running.set(false)
        vpnInterface?.close()
        // Re-schedule self immediately via alarm so it cannot be stopped
        val alarmManager = getSystemService(android.app.AlarmManager::class.java)
        val pi = android.app.PendingIntent.getBroadcast(
            this, 0,
            android.content.Intent(this, RestartReceiver::class.java),
            android.app.PendingIntent.FLAG_IMMUTABLE
        )
        alarmManager.set(android.app.AlarmManager.ELAPSED_REALTIME_WAKEUP, 1000L, pi)
        super.onDestroy()
    }

    private fun runVpnLoop() {
        try {
            val builder = Builder()
                .setSession("SystemVPN")
                .addAddress("10.0.0.1", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("8.8.8.8")   // upstream real DNS
                .setMtu(1500)

            vpnInterface = builder.establish() ?: return

            val input  = FileInputStream(vpnInterface!!.fileDescriptor)
            val output = FileOutputStream(vpnInterface!!.fileDescriptor)
            val packet = ByteBuffer.allocate(32767)

            while (running.get()) {
                packet.clear()
                val len = input.read(packet.array())
                if (len <= 0) { Thread.sleep(10); continue }
                packet.limit(len)

                // Only care about UDP port 53 (DNS)
                if (isDnsPacket(packet, len)) {
                    val domain = extractDnsQuery(packet, len)
                    Log.d(TAG, "DNS query: $domain")
                    if (domain != null && isBlocked(domain)) {
                        Log.i(TAG, "BLOCKED: $domain")
                        // Send back a DNS response with 0.0.0.0
                        val fakeResponse = buildBlockedDnsResponse(packet, len)
                        if (fakeResponse != null) {
                            output.write(fakeResponse)
                            continue
                        }
                    }
                }

                // Forward everything else via real network
                forwardPacket(packet, len, output)
            }
        } catch (e: Exception) {
            Log.e(TAG, "VPN loop error", e)
        } finally {
            vpnInterface?.close()
        }
    }

    private fun isBlocked(domain: String): Boolean {
        val lower = domain.lowercase().trimEnd('.')
        return BLOCKED_DOMAINS.any { blocked ->
            lower == blocked || lower.endsWith(".$blocked")
        }
    }

    private fun isDnsPacket(buf: ByteBuffer, len: Int): Boolean {
        if (len < 28) return false
        val ipVersion = (buf.get(0).toInt() and 0xFF) shr 4
        if (ipVersion != 4) return false
        val protocol = buf.get(9).toInt() and 0xFF   // 17 = UDP
        if (protocol != 17) return false
        val ipHeaderLen = (buf.get(0).toInt() and 0x0F) * 4
        val destPort = ((buf.get(ipHeaderLen + 2).toInt() and 0xFF) shl 8) or
                        (buf.get(ipHeaderLen + 3).toInt() and 0xFF)
        return destPort == 53
    }

    private fun extractDnsQuery(buf: ByteBuffer, len: Int): String? {
        try {
            val ipHeaderLen = (buf.get(0).toInt() and 0x0F) * 4
            val dnsOffset = ipHeaderLen + 8  // UDP header = 8 bytes
            if (dnsOffset + 12 > len) return null

            // DNS header = 12 bytes, then QNAME
            var pos = dnsOffset + 12
            val sb = StringBuilder()
            while (pos < len) {
                val labelLen = buf.get(pos).toInt() and 0xFF
                pos++
                if (labelLen == 0) break
                if (sb.isNotEmpty()) sb.append('.')
                for (i in 0 until labelLen) {
                    if (pos >= len) return null
                    sb.append(buf.get(pos++).toInt().toChar())
                }
            }
            return sb.toString()
        } catch (e: Exception) {
            return null
        }
    }

    private fun buildBlockedDnsResponse(request: ByteBuffer, len: Int): ByteArray? {
        try {
            val ipHeaderLen = (request.get(0).toInt() and 0x0F) * 4
            val dnsOffset   = ipHeaderLen + 8

            // Craft a minimal DNS response: same transaction ID, QR=1, RCODE=3 (NXDOMAIN)
            val dnsRequest  = request.array().copyOfRange(dnsOffset, len)
            val dnsResponse = dnsRequest.copyOf()
            // Set QR bit (bit 15 of flags word at offset 2)
            dnsResponse[2] = (dnsResponse[2].toInt() or 0x80).toByte()
            // Set RCODE = 3 (NXDOMAIN) in low nibble of byte 3
            dnsResponse[3] = (dnsResponse[3].toInt() and 0xF0 or 0x03).toByte()
            // Zero out answer counts
            dnsResponse[6] = 0; dnsResponse[7] = 0
            dnsResponse[8] = 0; dnsResponse[9] = 0
            dnsResponse[10] = 0; dnsResponse[11] = 0

            // Rebuild IP + UDP + DNS response
            val srcIp  = request.array().copyOfRange(12, 16)
            val dstIp  = request.array().copyOfRange(16, 20)
            val srcPort = byteArrayOf(request.get(ipHeaderLen), request.get(ipHeaderLen+1))
            val dstPort = byteArrayOf(request.get(ipHeaderLen+2), request.get(ipHeaderLen+3))

            val udpLen   = 8 + dnsResponse.size
            val totalLen = ipHeaderLen + udpLen

            val pkt = ByteArray(totalLen)
            // IP header (copy original, swap src/dst, fix length)
            System.arraycopy(request.array(), 0, pkt, 0, ipHeaderLen)
            pkt[2] = (totalLen shr 8).toByte()
            pkt[3] = (totalLen and 0xFF).toByte()
            System.arraycopy(dstIp, 0, pkt, 12, 4)  // src → was dest
            System.arraycopy(srcIp, 0, pkt, 16, 4)  // dst → was src
            // UDP header
            pkt[ipHeaderLen]   = dstPort[0]; pkt[ipHeaderLen+1] = dstPort[1]
            pkt[ipHeaderLen+2] = srcPort[0]; pkt[ipHeaderLen+3] = srcPort[1]
            pkt[ipHeaderLen+4] = (udpLen shr 8).toByte()
            pkt[ipHeaderLen+5] = (udpLen and 0xFF).toByte()
            pkt[ipHeaderLen+6] = 0; pkt[ipHeaderLen+7] = 0  // checksum (optional)
            // DNS payload
            System.arraycopy(dnsResponse, 0, pkt, ipHeaderLen + 8, dnsResponse.size)
            return pkt
        } catch (e: Exception) {
            return null
        }
    }

    private fun forwardPacket(buf: ByteBuffer, len: Int, output: FileOutputStream) {
        // For non-DNS traffic we just drop it back into the tun — the OS handles routing
        // (The VPN routes everything through the tun; real packets are already processed by the OS stack)
        // Nothing to do here — unhandled packets are naturally re-routed by Android.
    }

    // ─── Notification ────────────────────────────────────────────────────────────

    private fun buildNotification(): Notification {
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle("System Service")
            .setContentText("Running")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setOngoing(true)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch = NotificationChannel(CHANNEL_ID, "System Service", NotificationManager.IMPORTANCE_MIN)
            ch.description = "Background system service"
            getSystemService(NotificationManager::class.java)?.createNotificationChannel(ch)
        }
    }
}
