package com.example.secretlab.face

import org.junit.Assert.assertEquals
import org.junit.Test

class FaceInputPolicyStudentTest {
    @Test
    fun cameraIsPreferredAndGalleryIsFallback() {
        val policy = FaceInputPolicy(cameraPreferred = true)
        assertEquals(FaceInputSource.CAMERA, policy.preferredSource())
        assertEquals(FaceInputSource.GALLERY, policy.fallbackSource())
    }

    @Test
    fun galleryCanBeMadePrimaryForFallbackMode() {
        val policy = FaceInputPolicy(cameraPreferred = false)
        assertEquals(FaceInputSource.GALLERY, policy.preferredSource())
        assertEquals(FaceInputSource.CAMERA, policy.fallbackSource())
    }
}
