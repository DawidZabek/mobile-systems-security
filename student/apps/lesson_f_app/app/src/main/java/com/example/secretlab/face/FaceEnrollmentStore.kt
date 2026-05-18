package com.example.secretlab.face

data class FaceEnrollmentSnapshot(
    val samplesByUser: Map<String, List<String>>,
)

class FaceEnrollmentStore {
    private val samplesByUser = linkedMapOf<String, MutableList<String>>()

    fun addSample(userId: String, sampleId: String) {
        samplesByUser.getOrPut(userId) { mutableListOf() }.add(sampleId)
    }

    fun ensureFiveUsers() {
        repeat(5) { index ->
            val userId = "user-${index + 1}"
            val samples = samplesByUser.getOrPut(userId) { mutableListOf() }
            while (samples.size < 10) {
                samples.add("$userId-face-${samples.size + 1}")
            }
        }
    }

    fun snapshot(): FaceEnrollmentSnapshot =
        FaceEnrollmentSnapshot(samplesByUser.mapValues { it.value.toList() })

    fun summary(): String =
        buildString {
            append(samplesByUser.size)
            append(" users, ")
            append(samplesByUser.values.sumOf { it.size })
            append(" crops")
        }

    fun userCount(): Int = samplesByUser.size
}
