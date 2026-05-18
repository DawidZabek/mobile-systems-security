package com.example.secretlab.face

class FaceEnrollmentStore {
    private val samplesByUser = linkedMapOf<String, MutableList<FaceFrame>>()

    fun addSample(userId: String, frame: FaceFrame) {
        samplesByUser.getOrPut(userId) { mutableListOf() }.add(frame)
    }

    fun snapshot(): FaceEnrollmentSnapshot =
        FaceEnrollmentSnapshot(samplesByUser.mapValues { it.value.toList() })

    fun summary(): String =
        "${samplesByUser.size} users, ${samplesByUser.values.sumOf { it.size }} crops"

    fun userCount(): Int = samplesByUser.size

    fun cropCountFor(userId: String): Int = samplesByUser[userId]?.size ?: 0

    fun nextUserId(): String = "user-${userCount() + 1}"

    fun hasEnoughData(): Boolean = samplesByUser.size >= 5 && samplesByUser.values.all { it.size >= 10 }
}
