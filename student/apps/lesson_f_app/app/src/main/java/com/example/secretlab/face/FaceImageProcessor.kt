package com.example.secretlab.face

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import com.google.mlkit.vision.common.InputImage
import com.google.mlkit.vision.face.Face
import com.google.mlkit.vision.face.FaceDetection
import com.google.mlkit.vision.face.FaceDetectorOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.tasks.await
import kotlinx.coroutines.withContext

class FaceImageProcessor(context: Context) {
    private val detector = FaceDetection.getClient(
        FaceDetectorOptions.Builder()
            .setPerformanceMode(FaceDetectorOptions.PERFORMANCE_MODE_FAST)
            .setLandmarkMode(FaceDetectorOptions.LANDMARK_MODE_NONE)
            .setContourMode(FaceDetectorOptions.CONTOUR_MODE_NONE)
            .setClassificationMode(FaceDetectorOptions.CLASSIFICATION_MODE_NONE)
            .enableTracking()
            .build(),
    )

    suspend fun loadAndCropFace(context: Context, uri: Uri): FaceFrame? = withContext(Dispatchers.IO) {
        val bitmap = context.contentResolver.openInputStream(uri)?.use { input ->
            BitmapFactory.decodeStream(input)
        } ?: return@withContext null
        val image = InputImage.fromBitmap(bitmap, 0)
        val faces = detector.process(image).await()
        val face = faces.maxByOrNull { it.boundingBox.width() * it.boundingBox.height() } ?: return@withContext null
        cropFace(bitmap, face, uri)
    }

    private fun cropFace(bitmap: Bitmap, face: Face, uri: Uri): FaceFrame {
        val marginX = (face.boundingBox.width() * 0.15f).toInt()
        val marginY = (face.boundingBox.height() * 0.20f).toInt()
        val left = (face.boundingBox.left - marginX).coerceAtLeast(0)
        val top = (face.boundingBox.top - marginY).coerceAtLeast(0)
        val right = (face.boundingBox.right + marginX).coerceAtMost(bitmap.width)
        val bottom = (face.boundingBox.bottom + marginY).coerceAtMost(bitmap.height)
        val crop = Bitmap.createBitmap(bitmap, left, top, right - left, bottom - top)
        val scaled = Bitmap.createScaledBitmap(crop, 32, 32, true)
        val pixels = IntArray(32 * 32)
        scaled.getPixels(pixels, 0, 32, 0, 0, 32, 32)
        return FaceFrame(32, 32, pixels, source = uri)
    }
}
