package com.example.secretlab.face

data class FaceModelArtifact(
    val spec: FaceBackboneSpec = FaceBackboneSpec(),
    val pathOnDevice: String = "app/src/main/assets/tiny_face_backbone.tflite",
    val labelsPath: String = "app/src/main/assets/tiny_face_labels.txt",
)

data class FacePreprocessingPipeline(
    val targetWidth: Int = FaceBackboneSpec().inputWidth,
    val targetHeight: Int = FaceBackboneSpec().inputHeight,
    val normalizeToUnitRange: Boolean = true,
)

data class FaceInferencePolicy(
    val rejectThreshold: Float = 0.72f,
    val backgroundInferenceEverySeconds: Int = 2,
)

data class FaceFineTuningBridge(
    val artifact: FaceModelArtifact = FaceModelArtifact(),
    val preprocessing: FacePreprocessingPipeline = FacePreprocessingPipeline(),
    val policy: FaceInferencePolicy = FaceInferencePolicy(),
) {
    val isReadyForOnDeviceTraining: Boolean
        get() = artifact.spec == preprocessing.toSpec() && artifact.pathOnDevice.isNotBlank()

    val isReadyForInference: Boolean
        get() = isReadyForOnDeviceTraining && artifact.labelsPath.isNotBlank() && policy.rejectThreshold in 0.0f..1.0f

    val sessionSummary: String
        get() = "${artifact.spec.modelName}:${artifact.spec.inputShape}/${artifact.spec.embeddingSize}d"
}

private fun FacePreprocessingPipeline.toSpec(): FaceBackboneSpec = FaceBackboneSpec(
    inputWidth = targetWidth,
    inputHeight = targetHeight,
    inputChannels = 3,
)
