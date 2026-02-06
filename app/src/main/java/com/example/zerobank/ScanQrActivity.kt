package com.example.zerobank

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Button
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.zxing.integration.android.IntentIntegrator

class ScanQrActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Simple layout with single button that triggers scan
        setContentView(R.layout.activity_scan_qr)

        val startBtn = findViewById<Button>(R.id.startScanBtn)
        startBtn.setOnClickListener { startScanner() }

        // If opened by deep link (user tapped otpauth:// link), forward to ShowTotpActivity
        intent?.data?.let { uri ->
            val i = Intent(this, ShowTotpActivity::class.java).apply { data = uri }
            startActivity(i)
            finish()
        }
    }

    private fun startScanner() {
        IntentIntegrator(this)
            .setDesiredBarcodeFormats(IntentIntegrator.QR_CODE)
            .setPrompt("Scan OTP QR")
            .setBeepEnabled(true)
            .setBarcodeImageEnabled(false)
            .initiateScan()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        if (result != null) {
            if (result.contents == null) {
                Toast.makeText(this, "Scan canceled", Toast.LENGTH_SHORT).show()
            } else {
                // Got the content (may be otpauth://... or an otpauth QR string)
                handleScannedContent(result.contents)
            }
        } else {
            super.onActivityResult(requestCode, resultCode, data)
        }
    }

    private fun handleScannedContent(content: String) {
        // If it's an otpauth URI, forward it to ShowTotpActivity which saves secret
        if (content.startsWith("otpauth://")) {
            val i = Intent(this, ShowTotpActivity::class.java).apply {
                data = Uri.parse(content)
            }
            startActivity(i)
            finish()
            return
        }

        // fallback: if just secret, save directly
        val maybeSecret = content.trim()
        if (maybeSecret.matches(Regex("^[A-Z2-7]+=*\$"))) {
            SecurePrefs(this).saveSecret(maybeSecret)
            startActivity(Intent(this, ShowTotpActivity::class.java))
            finish()
        } else {
            Toast.makeText(this, "Unrecognized QR content", Toast.LENGTH_LONG).show()
        }
    }
}
