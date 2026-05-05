package com.example.secretlab.secure

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Minimal local authenticated encryption helper.
 *
 * Encoding format (for the lab): `iv || ciphertextAndTag` as raw bytes.
 */
class SecretBox(
    private val keyProvider: KeyProvider,
    private val random: SecureRandom = SecureRandom(),
) {
    fun generateIv(): ByteArray {
        val iv = ByteArray(IV_BYTES)
        random.nextBytes(iv)
        return iv
    }

    fun encrypt(plaintext: ByteArray, iv: ByteArray): ByteArray {
        if (iv.size != IV_BYTES) {
            throw IllegalArgumentException("Invalid IV length")
        }
        val cipher = cipherEncrypt(iv)
        val ciphertextAndTag = cipher.doFinal(plaintext)
        return iv + ciphertextAndTag
    }

    fun decrypt(message: ByteArray): ByteArray? {
        if (message.size < IV_BYTES + (TAG_BITS / 8)) {
            return null
        }
        val iv = message.sliceArray(0 until IV_BYTES)
        val ciphertextAndTag = message.sliceArray(IV_BYTES until message.size)
        return try {
            val cipher = cipherDecrypt(iv)
            cipher.doFinal(ciphertextAndTag)
        } catch (e: Exception) {
            null
        }
    }

    fun encryptBound(plaintext: ByteArray, iv: ByteArray, context: ByteArray): ByteArray {
        if (iv.size != IV_BYTES) {
            throw IllegalArgumentException("Invalid IV length")
        }
        val cipher = cipherEncrypt(iv)
        cipher.updateAAD(context)
        val ciphertextAndTag = cipher.doFinal(plaintext)
        return iv + ciphertextAndTag
    }

    fun decryptBound(message: ByteArray, context: ByteArray): ByteArray? {
        if (message.size < IV_BYTES + (TAG_BITS / 8)) {
            return null
        }
        val iv = message.sliceArray(0 until IV_BYTES)
        val ciphertextAndTag = message.sliceArray(IV_BYTES until message.size)
        return try {
            val cipher = cipherDecrypt(iv)
            cipher.updateAAD(context)
            cipher.doFinal(ciphertextAndTag)
        } catch (e: Exception) {
            null
        }
    }

    private fun cipherEncrypt(iv: ByteArray): Cipher {
        val key = SecretKeySpec(keyProvider.getOrCreateAesKey(), "AES")
        return Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
        }
    }

    private fun cipherDecrypt(iv: ByteArray): Cipher {
        val key = SecretKeySpec(keyProvider.getOrCreateAesKey(), "AES")
        return Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
        }
    }

    companion object {
        const val IV_BYTES: Int = 12
        private const val TAG_BITS: Int = 128
    }
}
