package com.example.secretlab.face

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class FaceEnrollmentStoreStudentTest {
    @Test
    fun ensuresFiveUsersWithTenSamplesEach() {
        val store = FaceEnrollmentStore()
        store.ensureFiveUsers()
        val snapshot = store.snapshot()
        assertEquals(5, snapshot.samplesByUser.size)
        assertTrue(snapshot.samplesByUser.values.all { it.size >= 10 })
    }

    @Test
    fun storesOnlyFaceFrames() {
        val store = FaceEnrollmentStore()
        store.addSample("user-1", faceFrame(1))
        val snapshot = store.snapshot()
        assertEquals(1, snapshot.samplesByUser["user-1"]?.size)
        assertEquals(32, snapshot.samplesByUser["user-1"]?.first()?.width)
    }

    private fun faceFrame(seed: Int): FaceFrame {
        val width = 32
        val height = 32
        val pixels = IntArray(width * height) { index ->
            val value = ((index * 7 + seed * 31) and 0xFF)
            0xFF000000.toInt() or (value shl 16) or (value shl 8) or value
        }
        return FaceFrame(width, height, pixels)
    }
}
