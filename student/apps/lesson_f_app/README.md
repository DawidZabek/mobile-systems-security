# Lesson F App (Lab 6)

Starter Android app for lesson F (Lab 6): face enrollment, tiny on-device classifier, and local sign-in/out.

What is intentionally unfinished or weak:
- face enrollment and cropping flow are intentionally incomplete
- the local classifier/training path is intentionally tiny and student-facing
- live camera inference and signed-in/signed-out state handling need to be completed

Main files used by the notebook:
- `app/src/main/java/com/example/secretlab/MainActivity.kt`
- `app/src/main/java/com/example/secretlab/face/FaceEnrollmentStore.kt`
- `app/src/main/java/com/example/secretlab/face/FaceClassifier.kt`
- `app/src/main/java/com/example/secretlab/face/FacePipeline.kt`
- `app/src/main/java/com/example/secretlab/face/FaceCameraGate.kt`

Student-facing test suite:
- `app/src/test/java/com/example/secretlab/face/FaceEnrollmentStoreStudentTest.kt`
- `app/src/test/java/com/example/secretlab/face/FaceClassifierStudentTest.kt`
- `app/src/test/java/com/example/secretlab/face/FacePipelineStudentTest.kt`

Notes:
- The project is scaffolded for Android Studio.
- The Gradle wrapper JAR is not included in this workspace snapshot.
- The lab should stay runnable on low-end Android devices and should have a simulator-friendly fallback using gallery images.
