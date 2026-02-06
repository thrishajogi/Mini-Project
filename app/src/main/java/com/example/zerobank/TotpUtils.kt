package com.example.zerobank

import java.lang.StringBuilder
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.absoluteValue

object TotpUtil {

    // Decode Base32 (RFC4648) to bytes
    fun base32Decode(base32: String): ByteArray {
        // normalize
        val input = base32.trim().replace("=", "").replace("\\s".toRegex(), "").uppercase()
        if (input.isEmpty()) return ByteArray(0)

        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        val output = ArrayList<Byte>()
        var buffer = 0
        var bitsLeft = 0
        for (c in input) {
            val valIndex = alphabet.indexOf(c)
            if (valIndex == -1) throw IllegalArgumentException("Invalid Base32 character: $c")
            buffer = (buffer shl 5) or valIndex
            bitsLeft += 5
            if (bitsLeft >= 8) {
                bitsLeft -= 8
                val b = (buffer shr bitsLeft) and 0xFF
                output.add(b.toByte())
            }
        }
        return output.toByteArray()
    }

    // Generate TOTP code (6-digit default) using HMAC-SHA1
    // counter is the moving factor (time/30)
    fun generateTOTP(secretBase32: String, digits: Int = 6, counter: Long): String {
        val key = base32Decode(secretBase32)
        val data = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(counter).array()

        val mac = Mac.getInstance("HmacSHA1")
        val secretKey = SecretKeySpec(key, "HmacSHA1")
        mac.init(secretKey)
        val hash = mac.doFinal(data)

        val offset = (hash[hash.size - 1].toInt() and 0x0F)
        val binary =
            ((hash[offset].toInt() and 0x7f) shl 24) or
                    ((hash[offset + 1].toInt() and 0xff) shl 16) or
                    ((hash[offset + 2].toInt() and 0xff) shl 8) or
                    ((hash[offset + 3].toInt() and 0xff))

        val otp = (binary % Math.pow(10.0, digits.toDouble()).toInt()).absoluteValue
        return String.format("%0${digits}d", otp)
    }
}
