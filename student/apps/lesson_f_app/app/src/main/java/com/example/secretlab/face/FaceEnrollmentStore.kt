package com.example.secretlab.face

class FaceEnrollmentStore {
    private val samplesByUser = linkedMapOf<String, MutableList<FaceFrame>>()

    fun addSample(userId: String, frame: FaceFrame) {
        samplesByUser.getOrPut(userId) { mutableListOf() }.add(frame)
    }

    fun ensureFiveUsers() {
        repeat(5) { index ->
            val userId = "user-${index + 1}"
            val samples = samplesByUser.getOrPut(userId) { mutableListOf() }
            while (samples.size < 10) {
                samples.add(syntheticFace(userId, samples.size))
            }
        }
    }

    fun snapshot(): FaceEnrollmentSnapshot =
        FaceEnrollmentSnapshot(samplesByUser.mapValues { it.value.toList() })

    fun summary(): String =
        "${samplesByUser.size} users, ${samplesByUser.values.sumOf { it.size }} crops"

    fun userCount(): Int = samplesByUser.size

    private fun syntheticFace(userId: String, index: Int): FaceFrame {
        val width = 32
        val height = 32
        val pixels = IntArray(width * height)
        val seed = (userId.hashCode() * 31 + index).toLong()
        for (y in 0 until height) {
            for (x in 0 until width) {
                val base = ((x * 17 + y * 13 + seed).toInt()).ushr(1) and 0xFF
                val c = 0xFF000000.toInt() or (base shl 16) or (base shl 8) or base
                pixels[y * width + x] = c
            }
        }
        return FaceFrame(width, height, pixels)
    }
}
