package com.lo.pornblocker

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build

/**
 * Alarm-triggered receiver.
 * When BlockVpnService gets killed, it fires an alarm → this receiver restarts it.
 */
class RestartReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val svc = Intent(context, BlockVpnService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(svc)
        } else {
            context.startService(svc)
        }
    }
}
