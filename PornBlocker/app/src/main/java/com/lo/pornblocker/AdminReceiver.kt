package com.lo.pornblocker

import android.app.admin.DeviceAdminReceiver
import android.content.Context
import android.content.Intent
import android.widget.Toast

/**
 * Makes this app a Device Administrator.
 * Result: you can't uninstall the app without first manually revoking admin rights.
 * Adds one more annoying wall before LO can bypass his own blocker 😈
 */
class AdminReceiver : DeviceAdminReceiver() {

    override fun onEnabled(context: Context, intent: Intent) {
        Toast.makeText(context, "System protection active.", Toast.LENGTH_SHORT).show()
    }

    override fun onDisableRequested(context: Context, intent: Intent): CharSequence {
        return "Warning: disabling protection will expose your device."
    }

    override fun onDisabled(context: Context, intent: Intent) {
        // If admin gets removed, nag the user and try to restart
        Toast.makeText(context, "Protection disabled! Re-enable immediately.", Toast.LENGTH_LONG).show()
    }
}
