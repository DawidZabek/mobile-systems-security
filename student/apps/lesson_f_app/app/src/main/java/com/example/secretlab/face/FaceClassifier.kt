package com.example.secretlab.face

import kotlin.math.exp
import kotlin.math.max

class FaceClassifier(
    private val featureWidth: Int = 16,
    private val featureHeight: Int = 16,
    private val threshold: Double = 0.55,
) {
    private var labels: List<String> = emptyList()
    private var weights: Array<DoubleArray> = emptyArray()
    private var bias: DoubleArray = doubleArrayOf()
    private var trained = false

    fun train(snapshot: FaceEnrollmentSnapshot, epochs: Int = 80, learningRate: Double = 0.15) {
        val dataset = snapshot.samplesByUser.entries.flatMap { (userId, frames) ->
            frames.map { userId to extractFeatures(it) }
        }
        val distinctLabels = snapshot.samplesByUser.keys.sorted()
        require(distinctLabels.isNotEmpty()) { "No enrolled users" }
        labels = distinctLabels
        val featureSize = featureWidth * featureHeight
        weights = Array(labels.size) { DoubleArray(featureSize) }
        bias = DoubleArray(labels.size)

        repeat(epochs) {
            for ((userId, features) in dataset) {
                val targetIndex = labels.indexOf(userId)
                val logits = logits(features)
                val probs = softmax(logits)
                for (classIndex in labels.indices) {
                    val error = probs[classIndex] - if (classIndex == targetIndex) 1.0 else 0.0
                    for (i in features.indices) {
                        weights[classIndex][i] -= learningRate * error * features[i]
                    }
                    bias[classIndex] -= learningRate * error
                }
            }
        }
        trained = true
    }

    fun classify(frame: FaceFrame): FaceClassification {
        if (!trained || labels.isEmpty()) {
            return FaceClassification(null, 0.0, "Model not trained yet.")
        }
        val features = extractFeatures(frame)
        val probs = softmax(logits(features))
        val bestIndex = probs.indices.maxByOrNull { probs[it] } ?: return FaceClassification(null, 0.0, "No prediction.")
        val confidence = probs[bestIndex]
        val userId = labels[bestIndex]
        return if (confidence >= threshold) {
            FaceClassification(userId, confidence, "Matched $userId.")
        } else {
            FaceClassification(null, confidence, "Below threshold, signed out.")
        }
    }

    fun modelSummary(): String =
        if (!trained) "untrained" else "logreg(${labels.size} classes, ${featureWidth}x$featureHeight)"

    private fun logits(features: DoubleArray): DoubleArray {
        val result = DoubleArray(labels.size)
        for (classIndex in labels.indices) {
            var sum = bias[classIndex]
            for (i in features.indices) {
                sum += weights[classIndex][i] * features[i]
            }
            result[classIndex] = sum
        }
        return result
    }

    private fun softmax(logits: DoubleArray): DoubleArray {
        val maxLogit = logits.maxOrNull() ?: 0.0
        val expValues = DoubleArray(logits.size) { exp(logits[it] - maxLogit) }
        val total = expValues.sum().coerceAtLeast(1e-12)
        return DoubleArray(logits.size) { expValues[it] / total }
    }

    private fun extractFeatures(frame: FaceFrame): DoubleArray {
        val out = DoubleArray(featureWidth * featureHeight)
        val scaleX = frame.width.toDouble() / featureWidth
        val scaleY = frame.height.toDouble() / featureHeight
        var index = 0
        for (fy in 0 until featureHeight) {
            for (fx in 0 until featureWidth) {
                val x = minOf(frame.width - 1, (fx * scaleX).toInt())
                val y = minOf(frame.height - 1, (fy * scaleY).toInt())
                val color = frame.pixels[y * frame.width + x]
                val r = (color shr 16) and 0xFF
                val g = (color shr 8) and 0xFF
                val b = color and 0xFF
                val gray = (r * 0.299 + g * 0.587 + b * 0.114) / 255.0
                out[index++] = gray
            }
        }
        return out
    }
}
