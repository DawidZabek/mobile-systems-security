package com.example.secretlab.face

class FacePipeline(
    private val enrollmentStore: FaceEnrollmentStore,
    private val classifier: FaceClassifier,
) {
    fun infer(sampleId: String): FaceClassification {
        return classifier.classify(sampleId)
    }
}
