package com.example.secretlab.face

import android.net.Uri

data class FaceFrame(
    val width: Int,
    val height: Int,
    val pixels: IntArray,
    val source: Uri? = null,
)

data class FaceEnrollmentSnapshot(
    val samplesByUser: Map<String, List<FaceFrame>>,
)

data class FaceClassification(
    val userId: String?,
    val confidence: Double,
    val reason: String,
)
