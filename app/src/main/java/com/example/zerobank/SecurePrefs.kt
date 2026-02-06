package com.example.zerobank

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class SecurePrefs(private val ctx: Context) {
    private val fileName = "totp_prefs"

    private val prefs by lazy {
        val masterKey = MasterKey.Builder(ctx)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        EncryptedSharedPreferences.create(
            ctx,
            fileName,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    fun saveSecret(base32Secret: String) {
        prefs.edit().putString("totp_secret", base32Secret).apply()
    }

    fun getSecret(): String? {
        return prefs.getString("totp_secret", null)
    }

    fun clearSecret() {
        prefs.edit().remove("totp_secret").apply()
    }
}
