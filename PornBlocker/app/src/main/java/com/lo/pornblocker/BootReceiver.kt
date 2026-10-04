package com.lo.pornblocker

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build

/**
 * Fires on BOOT_COMPLETED and on the alarm set by BlockVpnService.onDestroy.
 * Ensures the VPN is always running, even after phone restart.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED,
            "com.lo.pornblocker.RESTART" -> {
                val svc = Intent(context, BlockVpnService::class.java)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(svc)
                } else {
                    context.startService(svc)
                }
            }
        }
    }
}
