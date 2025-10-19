package com.example.zerodef

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.example.zerodef.ui.theme.ZeroDefTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnService()
        } else {
            updateVpnState(false)
        }
    }

    private fun updateVpnState(running: Boolean) {
        ZeroDefVpnService.isRunning = running
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            ZeroDefTheme {
                VpnControlScreen(
                    onVpnToggle = { shouldStart ->
                        if (shouldStart) {
                            requestVpnPermission()
                        } else {
                            stopVpnService()
                        }
                    }
                )
            }
        }
    }

    private fun requestVpnPermission() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, ZeroDefVpnService::class.java).apply {
            action = ZeroDefVpnService.ACTION_START
        }
        startService(intent)
        updateVpnState(true)
    }

    private fun stopVpnService() {
        val intent = Intent(this, ZeroDefVpnService::class.java).apply {
            action = ZeroDefVpnService.ACTION_STOP
        }
        startService(intent)
        updateVpnState(false)
    }
}

@Composable
fun VpnControlScreen(modifier: Modifier = Modifier, onVpnToggle: (Boolean) -> Unit) {
    val context = LocalContext.current
    var vpnRunning by remember { mutableStateOf(ZeroDefVpnService.isRunning) }
    var isLoading by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    // Update the UI state when the service state changes
    DisposableEffect(Unit) {
        val checkInterval = 1000L // 1 second
        val job = scope.launch(Dispatchers.Default) {
            while (true) {
                val currentVpnState = ZeroDefVpnService.isRunning
                if (vpnRunning != currentVpnState) {
                    withContext(Dispatchers.Main) {
                        vpnRunning = currentVpnState
                        isLoading = false
                    }
                }
                kotlinx.coroutines.delay(checkInterval)
            }
        }
        onDispose {
            job.cancel()
        }
    }

    Column(
        modifier = modifier.fillMaxSize(),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        if (isLoading) {
            CircularProgressIndicator()
            Spacer(modifier = Modifier.height(16.dp))
            Text(text = if (vpnRunning) "Disconnecting..." else "Connecting...")
        } else {
            Text(text = "VPN Status: ${if (vpnRunning) "Running" else "Stopped"}")
            Spacer(modifier = Modifier.height(16.dp))
            Button(
                onClick = {
                    val newState = !vpnRunning
                    isLoading = true
                    scope.launch(Dispatchers.IO) {
                        onVpnToggle(newState)
                    }
                },
                enabled = !isLoading
            ) {
                Text(if (vpnRunning) "Stop VPN" else "Start VPN")
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
fun VpnControlScreenPreview() {
    ZeroDefTheme {
        VpnControlScreen(onVpnToggle = {})
    }
}
