package com.example.secretlab

import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.example.secretlab.face.FaceCameraGate
import com.example.secretlab.face.FaceClassifier
import com.example.secretlab.face.FaceEnrollmentStore
import com.example.secretlab.face.FaceImageProcessor
import com.example.secretlab.face.FacePipeline
import com.example.secretlab.ui.theme.SecretLabTheme
import kotlinx.coroutines.launch

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
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val enrollmentStore = remember { FaceEnrollmentStore() }
    val classifier = remember { FaceClassifier() }
    val pipeline = remember { FacePipeline(enrollmentStore, classifier) }
    val cameraGate = remember { FaceCameraGate() }
    val processor = remember { FaceImageProcessor(context) }

    var banner by remember { mutableStateOf("Enroll 5 users, 10 face crops each, then train and infer.") }
    var enrolled by remember { mutableStateOf(enrollmentStore.summary()) }
    var activeUser by remember { mutableStateOf("") }
    var status by remember { mutableStateOf("signed out") }
    var confidence by remember { mutableStateOf("0.00") }
    var selectedUri by remember { mutableStateOf<Uri?>(null) }
    var selectedUser by remember { mutableStateOf(enrollmentStore.nextUserId()) }

    val pickImage = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent(),
    ) { uri ->
        selectedUri = uri
    }

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
                        value = selectedUser,
                        onValueChange = { selectedUser = it },
                        label = { Text("Current user id") },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Button(onClick = { pickImage.launch("image/*") }) {
                        Text("Pick face photo")
                    }
                    Button(onClick = {
                        scope.launch {
                            val uri = selectedUri ?: run {
                                banner = "Pick a photo first."
                                return@launch
                            }
                            val frame = processor.loadAndCropFace(context, uri)
                            if (frame == null) {
                                banner = "No face detected."
                                return@launch
                            }
                            enrollmentStore.addSample(selectedUser, frame)
                            enrolled = enrollmentStore.summary()
                            selectedUser = enrollmentStore.nextUserId()
                            banner = "Added face crop for $selectedUser"
                        }
                    }) {
                        Text("Add selected face crop")
                    }
                    Text("Selected user: $selectedUser")
                    Text(enrolled)
                }
            }

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("Training", style = MaterialTheme.typography.titleLarge)
                    Text("Train a small local classifier on the enrolled face crops.")
                    Button(onClick = {
                        if (!enrollmentStore.hasEnoughData()) {
                            banner = "Need 5 users and at least 10 face crops each."
                            return@Button
                        }
                        pipeline.train()
                        banner = "Local model trained from real face crops."
                    }) {
                        Text("Train")
                    }
                    Text("Model: ${classifier.modelSummary()}")
                }
            }

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("Live inference", style = MaterialTheme.typography.titleLarge)
                    Text("Gallery fallback works on emulator and low-end devices.")
                    Button(onClick = { pickImage.launch("image/*") }) {
                        Text("Pick inference photo")
                    }
                    Button(onClick = {
                        scope.launch {
                            val uri = selectedUri ?: run {
                                banner = "Pick a photo first."
                                return@launch
                            }
                            val frame = processor.loadAndCropFace(context, uri)
                            if (frame == null) {
                                banner = "No face detected."
                                return@launch
                            }
                            if (!cameraGate.isAvailable()) {
                                banner = "Camera unavailable; using imported photo fallback."
                            }
                            val result = pipeline.infer(frame)
                            activeUser = result.userId.orEmpty()
                            confidence = "%.2f".format(result.confidence)
                            status = if (result.userId == null) "signed out" else "signed in as ${result.userId}"
                            banner = result.reason
                        }
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
