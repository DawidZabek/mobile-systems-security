package com.example.secretlab.face

data class FaceClassification(
    val userId: String?,
    val confidence: Double,
    val reason: String,
)

class FaceClassifier {
    private var centroids = emptyMap<String, Double>()

    fun train(snapshot: FaceEnrollmentSnapshot) {
        centroids = snapshot.samplesByUser.mapValues { (_, samples) ->
            if (samples.isEmpty()) 0.0 else samples.map { it.hashCode().toDouble() }.average()
        }
    }

    fun classify(sampleId: String): FaceClassification {
        if (centroids.isEmpty()) {
            return FaceClassification(null, 0.0, "Model not trained yet.")
        }
        val value = sampleId.hashCode().toDouble()
        val best = centroids.minByOrNull { (_, centroid) -> kotlin.math.abs(centroid - value) }
        val confidence = best?.let { 1.0 / (1.0 + kotlin.math.abs(it.value - value) / 1_000_000.0) } ?: 0.0
        return if (best != null && confidence >= 0.55) {
            FaceClassification(best.key, confidence, "Matched ${best.key}.")
        } else {
            FaceClassification(null, confidence, "Low confidence, signed out.")
        }
    }

    fun modelSummary(): String = if (centroids.isEmpty()) "untrained" else "${centroids.size} centroids"
}
