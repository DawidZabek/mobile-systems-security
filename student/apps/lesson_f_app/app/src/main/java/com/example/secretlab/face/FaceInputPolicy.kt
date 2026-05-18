package com.example.secretlab.face

enum class FaceInputSource {
    CAMERA,
    GALLERY,
}

class FaceInputPolicy(
    private val cameraPreferred: Boolean = true,
) {
    fun preferredSource(): FaceInputSource =
        if (cameraPreferred) FaceInputSource.CAMERA else FaceInputSource.GALLERY

    fun fallbackSource(): FaceInputSource =
        if (cameraPreferred) FaceInputSource.GALLERY else FaceInputSource.CAMERA
}
