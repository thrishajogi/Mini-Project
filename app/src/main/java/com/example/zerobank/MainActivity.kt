package com.example.zerobank

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity

/**
 * Launcher activity: if secret exists -> ShowTotpActivity
 * otherwise -> ScanQrActivity
 * Also handles deep link if app launched by otpauth:// URI (intent.data).
 */
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // If app opened directly by otpauth:// link, forward to ShowTotpActivity (it handles saving)
        intent?.data?.let { uri ->
            val showIntent = Intent(this, ShowTotpActivity::class.java).apply {
                data = uri
            }
            startActivity(showIntent)
            finish()
            return
        }

        // If secret already stored -> open TOTP viewer
        val secret = SecurePrefs(this).getSecret()
        if (!secret.isNullOrEmpty()) {
            startActivity(Intent(this, ShowTotpActivity::class.java))
            finish()
            return
        }

        // else show scanner to register secret
        startActivity(Intent(this, ScanQrActivity::class.java))
        finish()
    }
}
