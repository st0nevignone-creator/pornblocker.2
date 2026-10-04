package com.lo.pornblocker

import android.app.Activity
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.TextView

/**
 * One-time setup activity.
 * After setup, the user never needs to open this again.
 * The VPN + Device Admin do all the work silently.
 */
class MainActivity : Activity() {

    private lateinit var dpm: DevicePolicyManager
    private lateinit var adminName: ComponentName
    private lateinit var statusText: TextView

    companion object {
        private const val REQ_VPN    = 100
        private const val REQ_ADMIN  = 101
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        dpm       = getSystemService(DEVICE_POLICY_SERVICE) as DevicePolicyManager
        adminName = ComponentName(this, AdminReceiver::class.java)

        val layout = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
        }

        statusText = TextView(this).apply {
            text = "Tap the button to activate protection."
            textSize = 16f
        }

        val btn = Button(this).apply {
            text = "ACTIVATE BLOCKER"
            setOnClickListener { startSetup() }
        }

        layout.addView(statusText)
        layout.addView(btn)
        setContentView(layout)

        // Auto-start if VPN already granted (admin optional)
        if (isVpnPrepared()) {
            startVpnService()
            statusText.text = "✅ Protection already active. You can close this app."
        }
    }

    private fun startSetup() {
        requestVpnPermission()
    }

    private fun requestVpnPermission() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, REQ_VPN)
        } else {
            onVpnReady()
        }
    }

    private fun onVpnReady() {
        if (!dpm.isAdminActive(adminName)) {
            val intent = Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN).apply {
                putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, adminName)
                putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                    "Required to prevent uninstallation of system protection.")
            }
            startActivityForResult(intent, REQ_ADMIN)
        } else {
            activateAll()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        when (requestCode) {
            REQ_VPN -> {
                if (resultCode == RESULT_OK) onVpnReady()
                else statusText.text = "VPN permission denied. Cannot activate protection."
            }
            REQ_ADMIN -> {
                // VPN parte sempre — admin è opzionale, serve solo a bloccare disinstallazione
                activateAll()
                if (resultCode != RESULT_OK) {
                    statusText.text = "✅ Protection ACTIVE (without admin lock).\nPornHub is blocked but app can be uninstalled."
                }
            }
        }
    }

    private fun activateAll() {
        startVpnService()
        statusText.text = "✅ Protection ACTIVE. You can close this app. PornHub is now blocked."
    }

    private fun startVpnService() {
        val intent = Intent(this, BlockVpnService::class.java)
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    private fun isVpnPrepared(): Boolean {
        return VpnService.prepare(this) == null
    }
}
