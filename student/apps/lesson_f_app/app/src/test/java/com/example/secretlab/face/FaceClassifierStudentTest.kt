package com.example.secretlab.face

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class FaceClassifierStudentTest {
    @Test
    fun trainsARealHeadOnImageFeatures() {
        val store = FaceEnrollmentStore().apply {
            repeat(10) { addSample("alice", faceFrame(10)) }
            repeat(10) { addSample("bob", faceFrame(80)) }
        }
        val classifier = FaceClassifier()
        classifier.train(store.snapshot())
        assertNotNull(classifier.modelSummary())
    }

    @Test
    fun classifiesTrainedUserAboveThreshold() {
        val store = FaceEnrollmentStore().apply {
            repeat(10) { addSample("alice", faceFrame(10)) }
            repeat(10) { addSample("bob", faceFrame(80)) }
        }
        val classifier = FaceClassifier()
        classifier.train(store.snapshot())
        val result = classifier.classify(faceFrame(10))
        assertEquals("alice", result.userId)
    }

    @Test
    fun returnsSignedOutWhenUntrained() {
        val classifier = FaceClassifier()
        val result = classifier.classify(faceFrame(42))
        assertNull(result.userId)
    }

    private fun faceFrame(seed: Int): FaceFrame {
        val width = 32
        val height = 32
        val pixels = IntArray(width * height) { index ->
            val value = ((index * 9 + seed * 13) and 0xFF)
            0xFF000000.toInt() or (value shl 16) or (value shl 8) or value
        }
        return FaceFrame(width, height, pixels)
    }
}
