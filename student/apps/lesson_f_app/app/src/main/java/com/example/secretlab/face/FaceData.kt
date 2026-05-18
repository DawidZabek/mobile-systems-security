package com.example.secretlab.face

data class FaceFrame(
    val width: Int,
    val height: Int,
    val pixels: IntArray,
)

data class FaceSample(
    val userId: String,
    val frame: FaceFrame,
)

data class FaceEnrollmentSnapshot(
    val samplesByUser: Map<String, List<FaceFrame>>,
)

data class FaceClassification(
    val userId: String?,
    val confidence: Double,
    val reason: String,
)
