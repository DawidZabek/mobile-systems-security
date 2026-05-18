package com.example.secretlab

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.example.secretlab.face.FaceFrame
import com.example.secretlab.face.FaceCameraGate
import com.example.secretlab.face.FaceClassifier
import com.example.secretlab.face.FaceEnrollmentStore
import com.example.secretlab.face.FacePipeline
import com.example.secretlab.ui.theme.SecretLabTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            SecretLabTheme {
                FaceLabApp()
            }
        }
    }
}

@Composable
private fun FaceLabApp() {
    val enrollmentStore = remember { FaceEnrollmentStore() }
    val classifier = remember { FaceClassifier() }
    val pipeline = remember { FacePipeline(enrollmentStore, classifier) }
    val cameraGate = remember { FaceCameraGate() }

    var banner by remember { mutableStateOf("Enroll 5 users, train the tiny head, then run local sign-in.") }
    var enrolled by remember { mutableStateOf(enrollmentStore.summary()) }
    var activeUser by remember { mutableStateOf("") }
    var status by remember { mutableStateOf("signed out") }
    var confidence by remember { mutableStateOf("0.00") }
    var sampleInput by remember { mutableStateOf("face_sample_01") }

    Scaffold(modifier = Modifier.fillMaxSize()) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text("Secret Lab - Face Biometrics", style = MaterialTheme.typography.headlineMedium)
            Text(banner)

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("Enrollment", style = MaterialTheme.typography.titleLarge)
                    OutlinedTextField(
                        value = sampleInput,
                        onValueChange = { sampleInput = it },
                        label = { Text("Sample face crop id") },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Button(onClick = {
                        val userId = "user-${enrollmentStore.userCount() + 1}"
                        enrollmentStore.addSample(userId, syntheticFrame(sampleInput))
                        enrolled = enrollmentStore.summary()
                        banner = "Added sample for $userId"
                    }) {
                        Text("Add crop to next user")
                    }
                    Button(onClick = {
                        enrollmentStore.ensureFiveUsers()
                        enrolled = enrollmentStore.summary()
                        banner = "Prepared 5 users with starter enrollment sets."
                    }) {
                        Text("Seed 5 users")
                    }
                    Text(enrolled)
                }
            }

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("Training", style = MaterialTheme.typography.titleLarge)
                    Text("Tiny local logistic regression on face crops.")
                    Button(onClick = {
                        classifier.train(enrollmentStore.snapshot())
                        banner = "Local model trained from ${enrollmentStore.userCount()} users."
                    }) {
                        Text("Train")
                    }
                    Text("Model: ${classifier.modelSummary()}")
                }
            }

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("Live inference", style = MaterialTheme.typography.titleLarge)
                    Text("This is simulator-friendly: the gate can run from imported samples.")
                    Button(onClick = {
                        if (!cameraGate.isAvailable()) {
                            banner = "Camera unavailable; using imported sample fallback."
                        }
                        val result = pipeline.infer(syntheticFrame(sampleInput))
                        activeUser = result.userId.orEmpty()
                        confidence = "%.2f".format(result.confidence)
                        status = if (result.userId == null) "signed out" else "signed in as ${result.userId}"
                        banner = result.reason
                    }) {
                        Text("Run inference")
                    }
                    Text("Status: $status")
                    Text("Active user: ${if (activeUser.isBlank()) "—" else activeUser}")
                    Text("Confidence: $confidence")
                }
            }
        }
    }
}

private fun syntheticFrame(seedText: String): FaceFrame {
    val width = 32
    val height = 32
    val pixels = IntArray(width * height)
    val seed = seedText.hashCode()
    for (y in 0 until height) {
        for (x in 0 until width) {
            val value = ((x * 31 + y * 17 + seed) and 0xFF).coerceIn(0, 255)
            pixels[y * width + x] = 0xFF000000.toInt() or (value shl 16) or (value shl 8) or value
        }
    }
    return FaceFrame(width, height, pixels)
}
