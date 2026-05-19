package com.example.secretlab

import android.content.Context
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import com.example.secretlab.face.FaceEnrollmentBox
import com.example.secretlab.face.FaceBackboneCheckpoint
import com.example.secretlab.face.FaceFineTuningBridge
import com.example.secretlab.face.FacePhoto
import com.example.secretlab.face.FaceInputPolicy
import com.example.secretlab.face.FaceTrainingPolicy
import com.example.secretlab.face.InputSource
import java.io.File

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MaterialTheme { FaceLabScreen() } }
    }
}

@Composable
private fun FaceLabScreen() {
    val context = LocalContext.current
    val box = remember { FaceEnrollmentBox() }
    val inputPolicy = remember { FaceInputPolicy(InputSource.CAMERA) }
    val trainingPolicy = remember { FaceTrainingPolicy(backboneTrainedInColab = true) }
    val backbone = remember { FaceBackboneCheckpoint(exportedFromColab = true) }
    val runnerBridge = remember { FaceFineTuningBridge() }
    var banner by remember { mutableStateOf("Five users. Edit photos per user. Train when every slot is ready.") }
    var editor by remember { mutableStateOf<Int?>(null) }
    var selectedPhoto by remember { mutableStateOf<Uri?>(null) }
    var selectedPhotoIndex by remember { mutableStateOf<Int?>(null) }
    var cameraTarget by remember { mutableStateOf<Int?>(null) }
    var pendingCapture by remember { mutableStateOf<Uri?>(null) }

    val galleryLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.PickVisualMedia(),
    ) { uri ->
        editor?.let { userIndex ->
            if (uri != null) {
                box.addPhoto(userIndex, FacePhoto(uri = uri, label = box.slot(userIndex).displayName))
                selectedPhoto = uri
                selectedPhotoIndex = box.slot(userIndex).photos.lastIndex
                banner = "Added gallery photo to ${box.slot(userIndex).displayName}."
            }
        }
        editor = null
    }

    val cameraLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.TakePicture(),
    ) { ok ->
        cameraTarget?.let { userIndex ->
            val uri = pendingCapture
            if (ok && uri != null) {
                box.addPhoto(userIndex, FacePhoto(uri = uri, label = box.slot(userIndex).displayName))
                selectedPhoto = uri
                selectedPhotoIndex = box.slot(userIndex).photos.lastIndex
                banner = "Captured camera photo for ${box.slot(userIndex).displayName}."
            }
        }
        cameraTarget = null
        pendingCapture = null
        editor = null
    }

    Scaffold(modifier = Modifier.fillMaxSize()) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("Secret Lab - Face Enrollment", style = MaterialTheme.typography.headlineMedium)
            Text(banner)
            Text("Main input: ${inputPolicy.preferredSource} / fallback: ${inputPolicy.fallbackSource}")
            Text("Colab backbone ready: ${trainingPolicy.backboneTrainedInColab}")
            Text("Backbone: ${backbone.spec.modelName} ${backbone.spec.inputShape} -> ${backbone.spec.embeddingSize}d")
            Text("Runner ready: ${runnerBridge.isReadyForOnDeviceTraining}")
            Text("Live camera loop: every ${trainingPolicy.backgroundInferenceEverySeconds} seconds")
            selectedPhoto?.let { Text("Last selected photo: $it") }

            box.slots.forEachIndexed { index, slot ->
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("${index + 1}. ${slot.displayName}")
                        Text("Photos: ${slot.photos.size}")
                        Button(onClick = { editor = index }) {
                            Icon(Icons.Default.Edit, contentDescription = null)
                            Text("Edit photos")
                        }
                        if (slot.photos.isNotEmpty()) {
                            Text("Latest: ${slot.photos.last().label}")
                        }
                    }
                }
            }

            Button(
                onClick = {
                    banner = if (box.allReady()) "Ready for training." else "Need 10 photos per user."
                },
            ) {
                Icon(Icons.Default.Add, contentDescription = null)
                Text("Train")
            }
        }
    }

    if (editor != null) {
        EditPhotosDialog(
            title = box.slot(editor!!).displayName,
            photos = box.slot(editor!!).photos.mapIndexed { index, photo ->
                PhotoChoice(index = index, label = photo.label, uri = photo.uri)
            },
            selectedIndex = selectedPhotoIndex,
            onSelectPhoto = { selectedPhotoIndex = it },
            onAddCamera = {
                editor?.let { userIndex ->
                    val uri = createTempImageUri(context)
                    cameraTarget = userIndex
                    pendingCapture = uri
                    cameraLauncher.launch(uri)
                }
            },
            onAddGallery = {
                galleryLauncher.launch(
                    PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly),
                )
            },
            onRemoveLast = {
                editor?.let { userIndex ->
                    val slot = box.slot(userIndex)
                    val index = selectedPhotoIndex ?: slot.photos.lastIndex
                    if (index in slot.photos.indices) {
                        val removed = slot.photos.removeAt(index)
                        selectedPhoto = removed.uri
                        selectedPhotoIndex = null
                        banner = "Removed selected photo from ${box.slot(userIndex).displayName}."
                    }
                }
            },
            onReplaceLast = {
                editor?.let { userIndex ->
                    val slot = box.slot(userIndex)
                    val index = selectedPhotoIndex ?: slot.photos.lastIndex
                    if (index in slot.photos.indices) {
                        slot.photos.removeAt(index)
                    }
                    val uri = createTempImageUri(context)
                    cameraTarget = userIndex
                    pendingCapture = uri
                    cameraLauncher.launch(uri)
                }
            },
            onDismiss = { editor = null },
        )
    }
}

@Composable
private fun EditPhotosDialog(
    title: String,
    photos: List<PhotoChoice>,
    selectedIndex: Int?,
    onSelectPhoto: (Int) -> Unit,
    onAddCamera: () -> Unit,
    onAddGallery: () -> Unit,
    onRemoveLast: () -> Unit,
    onReplaceLast: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                photos.forEach { photo ->
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        TextButton(onClick = { onSelectPhoto(photo.index) }) {
                            Text(if (selectedIndex == photo.index) "Selected: ${photo.label}" else photo.label)
                        }
                    }
                }
                Button(onClick = onAddCamera) { Text("Add from camera") }
                Button(onClick = onAddGallery) { Text("Add from gallery") }
                OutlinedButton(onClick = onRemoveLast) {
                    Icon(Icons.Default.Delete, contentDescription = null)
                    Text("Remove selected")
                }
                OutlinedButton(onClick = onReplaceLast) { Text("Replace selected") }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("Close") }
        },
    )
}

private data class PhotoChoice(
    val index: Int,
    val label: String,
    val uri: Uri,
)

private fun createTempImageUri(context: Context): Uri {
    val directory = File(context.cacheDir, "face-captures").apply { mkdirs() }
    val file = File.createTempFile("capture_", ".jpg", directory)
    return FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
}
