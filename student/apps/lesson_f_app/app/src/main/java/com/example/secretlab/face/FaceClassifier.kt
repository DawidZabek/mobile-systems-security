package com.example.secretlab.face

import kotlin.math.exp

class FaceClassifier(
    private val featureWidth: Int = 16,
    private val featureHeight: Int = 16,
    private val threshold: Double = 0.6,
) {
    private var labels: List<String> = emptyList()
    private var weights: Array<DoubleArray> = emptyArray()
    private var bias: DoubleArray = doubleArrayOf()
    private var trained = false

    fun train(snapshot: FaceEnrollmentSnapshot, epochs: Int = 120, learningRate: Double = 0.12) {
        val dataset = snapshot.samplesByUser.entries.flatMap { (userId, frames) ->
            frames.map { userId to extractFeatures(it) }
        }
        val distinctLabels = snapshot.samplesByUser.keys.sorted()
        require(distinctLabels.size >= 5) { "Need at least 5 enrolled users" }
        require(dataset.all { it.second.isNotEmpty() }) { "Empty training sample" }

        labels = distinctLabels
        val featureSize = featureWidth * featureHeight
        weights = Array(labels.size) { DoubleArray(featureSize) }
        bias = DoubleArray(labels.size)

        repeat(epochs) {
            for ((userId, features) in dataset) {
                val targetIndex = labels.indexOf(userId)
                val probs = softmax(logits(features))
                for (classIndex in labels.indices) {
                    val target = if (classIndex == targetIndex) 1.0 else 0.0
                    val error = probs[classIndex] - target
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
        if (!trained) {
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

    fun modelSummary(): String = if (!trained) "untrained" else "logreg(${labels.size} classes)"

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
        val exps = DoubleArray(logits.size) { exp(logits[it] - maxLogit) }
        val total = exps.sum().coerceAtLeast(1e-12)
        return DoubleArray(logits.size) { exps[it] / total }
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
                out[index++] = (r * 0.299 + g * 0.587 + b * 0.114) / 255.0
            }
        }
        return out
    }
}
