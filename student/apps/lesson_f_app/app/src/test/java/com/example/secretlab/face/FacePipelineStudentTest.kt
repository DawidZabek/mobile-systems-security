package com.example.secretlab.face

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class FacePipelineStudentTest {
    @Test
    fun runsEndToEndInference() {
        val enrollment = FaceEnrollmentStore().apply {
            repeat(10) { addSample("alice", frame(5)) }
            repeat(10) { addSample("bob", frame(120)) }
        }
        val classifier = FaceClassifier()
        val pipeline = FacePipeline(enrollment, classifier)
        pipeline.train()
        val result = pipeline.infer(frame(5))
        assertEquals("alice", result.userId)
    }

    @Test
    fun returnsSignedOutBelowThreshold() {
        val enrollment = FaceEnrollmentStore().apply {
            repeat(10) { addSample("alice", frame(5)) }
            repeat(10) { addSample("bob", frame(120)) }
        }
        val classifier = FaceClassifier()
        val pipeline = FacePipeline(enrollment, classifier)
        pipeline.train()
        val result = pipeline.infer(frame(220))
        assertNull(result.userId)
    }

    private fun frame(seed: Int): FaceFrame {
        val width = 32
        val height = 32
        val pixels = IntArray(width * height) { index ->
            val value = ((index * 11 + seed * 19) and 0xFF)
            0xFF000000.toInt() or (value shl 16) or (value shl 8) or value
        }
        return FaceFrame(width, height, pixels)
    }
}
