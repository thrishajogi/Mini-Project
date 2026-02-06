package com.example.zerobank

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import java.lang.Integer.min
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.floor

class ShowTotpActivity : AppCompatActivity() {

    private val handler = Handler(Looper.getMainLooper())
    private lateinit var totpText: TextView
    private lateinit var countdownText: TextView
    private lateinit var securePrefs: SecurePrefs
    private var secretBase32: String? = null

    private val updateRunnable = object : Runnable {
        override fun run() {
            val secret = secretBase32
            if (secret.isNullOrEmpty()) {
                Toast.makeText(this@ShowTotpActivity, "No TOTP secret stored", Toast.LENGTH_SHORT).show()
                finish()
                return
            }

            val nowSeconds = System.currentTimeMillis() / 1000L
            val timeStep = 30L
            val counter = nowSeconds / timeStep
            val remaining = (timeStep - (nowSeconds % timeStep)).toInt()
            countdownText.text = "Expires in ${remaining}s"

            val code = TotpUtil.generateTOTP(secret, 6, counter)
            totpText.text = code

            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_show_totp)

        totpText = findViewById(R.id.totpCode)
        countdownText = findViewById(R.id.countdown)
        securePrefs = SecurePrefs(this)

        // If launched with otpauth://... (deep link) parse and save secret
        intent?.data?.let { data: Uri ->
            parseAndSaveOtpauth(data)
        }

        // load secret
        secretBase32 = securePrefs.getSecret()
        if (secretBase32.isNullOrEmpty()) {
            // nothing stored — go to scanner
            startActivity(Intent(this, ScanQrActivity::class.java))
            finish()
            return
        }

        handler.post(updateRunnable)
    }

    override fun onDestroy() {
        handler.removeCallbacks(updateRunnable)
        super.onDestroy()
    }

    private fun parseAndSaveOtpauth(uri: Uri) {
        // Example: otpauth://totp/ZeroBank:user?secret=JBSWY3DPEHPK3PXP&issuer=ZeroBank
        val secret = uri.getQueryParameter("secret")
        if (!secret.isNullOrBlank()) {
            securePrefs.saveSecret(secret)
            secretBase32 = secret
            Toast.makeText(this, "Authenticator registered", Toast.LENGTH_SHORT).show()
        }
    }
}
