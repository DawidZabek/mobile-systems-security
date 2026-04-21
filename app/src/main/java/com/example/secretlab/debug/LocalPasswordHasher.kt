package com.example.secretlab.debug

import java.security.spec.KeySpec
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

object LocalPasswordHasher {
    const val ALGORITHM_NAME = "PBKDF2WithHmacSHA256"
    const val ITERATION_COUNT = 120_000
    const val KEY_LENGTH_BITS = 256
    const val RECORD_PREFIX = "pbkdf2_sha256"

    fun derive(password: String, saltText: String): String {
        val saltBytes = saltText.toByteArray(Charsets.UTF_8)

        val spec = PBEKeySpec(
            password.toCharArray(),
            saltBytes,
            ITERATION_COUNT,
            KEY_LENGTH_BITS
        )

        val factory = SecretKeyFactory.getInstance(ALGORITHM_NAME)
        val hashBytes = factory.generateSecret(spec).encoded

        return toHex(hashBytes)
    }

    fun buildRecord(password: String, saltText: String): String {
        val hashHex = derive(password, saltText)
        val saltHex = toHex(saltText.toByteArray(Charsets.UTF_8))

        return "$RECORD_PREFIX\$$ITERATION_COUNT\$$saltHex\$$hashHex"
    }

    fun verify(password: String, record: String): Boolean {
        val parts = record.split("$")
        if (parts.size != 4) return false

        val algorithm = parts[0]
        val iterationsStr = parts[1]
        val saltHex = parts[2]
        val hashHex = parts[3]

        if (algorithm != RECORD_PREFIX) return false
        val iterations = iterationsStr.toIntOrNull() ?: return false

        val saltBytes = fromHex(saltHex)
        val spec = PBEKeySpec(
            password.toCharArray(),
            saltBytes,
            iterations,
            KEY_LENGTH_BITS
        )

        val factory = SecretKeyFactory.getInstance(ALGORITHM_NAME)
        val computedHashBytes = factory.generateSecret(spec).encoded
        val computedHashHex = toHex(computedHashBytes)

        return computedHashHex == hashHex
    }

    fun utf8Bytes(text: String): ByteArray = text.toByteArray(Charsets.UTF_8)

    fun toHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    fun fromHex(text: String): ByteArray {
        require(text.length % 2 == 0)
        return text.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    @Suppress("unused")
    fun deriveReference(password: String, saltText: String): String {
        val keySpec: KeySpec = PBEKeySpec(
            password.toCharArray(),
            utf8Bytes(saltText),
            ITERATION_COUNT,
            KEY_LENGTH_BITS,
        )
        val factory = SecretKeyFactory.getInstance(ALGORITHM_NAME)
        return toHex(factory.generateSecret(keySpec).encoded)
    }
}
