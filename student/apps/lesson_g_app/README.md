# Lesson G App

Starter Android app for the next mobile security lab.

The base app already includes:

- a small location map
- photo picking from gallery
- photo capture from camera
- a student ID field
- a Kotlin answer-submission helper that mirrors the notebook flow

What is intentionally left for students:

- secure API key storage
- hardened location permission handling
- hardened camera/gallery data handling
- any security policy logic that belongs to tasks 2-4

Main files used by the notebook:

- `app/src/main/java/com/example/secretlab/MainActivity.kt`
- `app/src/main/AndroidManifest.xml`
- `app/src/main/res/xml/file_paths.xml`

Notes:

- The project is scaffolded for Android Studio.
- The Gradle wrapper JAR is not included in this workspace snapshot.
- Task 1 auto-submits once permissions are correct and the expected password is entered.
