package com.example.secretlab.face

class FacePipeline(
    private val enrollmentStore: FaceEnrollmentStore,
    private val classifier: FaceClassifier,
) {
    fun train() {
        classifier.train(enrollmentStore.snapshot())
    }

    fun infer(frame: FaceFrame): FaceClassification = classifier.classify(frame)

    fun canTrain(): Boolean = enrollmentStore.hasEnoughData()
}
