# Lesson F App (Lab 6)

Starter Android app for lesson F (Lab 6): face enrollment, tiny on-device classifier, and local sign-in/out.

What is intentionally unfinished or weak:
- face enrollment uses a gallery picker and a real face detector, but the end-to-end UI flow still needs refinement
- the local classifier/training path is intentionally small, but it trains on real cropped face pixels
- the live inference path should be completed and hardened for device variations

Main files used by the notebook:
- `app/src/main/java/com/example/secretlab/MainActivity.kt`
- `app/src/main/java/com/example/secretlab/face/FaceData.kt`
- `app/src/main/java/com/example/secretlab/face/FaceEnrollmentStore.kt`
- `app/src/main/java/com/example/secretlab/face/FaceClassifier.kt`
- `app/src/main/java/com/example/secretlab/face/FacePipeline.kt`
- `app/src/main/java/com/example/secretlab/face/FaceCameraGate.kt`
- `app/src/main/java/com/example/secretlab/face/FaceImageProcessor.kt`

Student-facing test suite:
- `app/src/test/java/com/example/secretlab/face/FaceEnrollmentStoreStudentTest.kt`
- `app/src/test/java/com/example/secretlab/face/FaceClassifierStudentTest.kt`
- `app/src/test/java/com/example/secretlab/face/FacePipelineStudentTest.kt`

Notes:
- The project is scaffolded for Android Studio.
- The Gradle wrapper JAR is not included in this workspace snapshot.
- The lab stays runnable on low-end Android devices by using a small classifier and gallery-based enrollment/inference fallback.
