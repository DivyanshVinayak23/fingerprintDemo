package com.example.fingerprintdemo

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    private val PERMISSION_REQUEST_CODE = 100

    private lateinit var btnGenerate: Button
    private lateinit var progressBar: ProgressBar
    private lateinit var tvHashResult: TextView
    private lateinit var tvRawData: TextView
    private lateinit var cardHash: View
    private lateinit var cardRaw: View

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        btnGenerate = findViewById(R.id.btnGenerate)
        progressBar = findViewById(R.id.progressBar)
        tvHashResult = findViewById(R.id.tvHashResult)
        tvRawData = findViewById(R.id.tvRawData)
        cardHash = findViewById(R.id.cardHash)
        cardRaw = findViewById(R.id.cardRaw)

        btnGenerate.setOnClickListener {
            checkPermissionAndGenerate()
        }
    }

    private fun checkPermissionAndGenerate() {
        val permissionsToRequest = mutableListOf<String>()

        if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_PHONE_STATE) != PackageManager.PERMISSION_GRANTED) {
            permissionsToRequest.add(Manifest.permission.READ_PHONE_STATE)
        }
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            permissionsToRequest.add(Manifest.permission.ACCESS_FINE_LOCATION)
        }

        if (permissionsToRequest.isNotEmpty()) {
            ActivityCompat.requestPermissions(
                this,
                permissionsToRequest.toTypedArray(),
                PERMISSION_REQUEST_CODE
            )
        } else {
            generateFingerprint()
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == PERMISSION_REQUEST_CODE) {
            // Proceed even if some permissions are denied, as the generator has fallback mechanisms
            generateFingerprint()
        }
    }

    private fun generateFingerprint() {
        // Show loading state
        progressBar.visibility = View.VISIBLE
        btnGenerate.isEnabled = false
        cardHash.alpha = 0f
        cardRaw.alpha = 0f

        // Launch in background to avoid NetworkOnMainThreadException (from isFridaPortOpen)
        CoroutineScope(Dispatchers.IO).launch {
            try {
                // Call the Java logic
                val results = DeviceFingerprintGenerator.generateDeviceHashAndRaw(this@MainActivity)
                val rawString = results[0]
                val hashResult = results[1]
                val fuzzyHashResult = if (results.size > 2) results[2] else "N/A"

                logLargeString("FingerprintDemo_JSON", rawString)

                // Switch to Main thread to update UI
                withContext(Dispatchers.Main) {
                    tvHashResult.text = "EXACT HASH\n$hashResult\n\nFUZZY HASH\n$fuzzyHashResult"
                    tvRawData.text = rawString
                    progressBar.visibility = View.GONE
                    btnGenerate.isEnabled = true
                    
                    cardHash.animate().alpha(1f).setDuration(500).start()
                    cardRaw.animate().alpha(1f).setDuration(500).setStartDelay(150).start()
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    tvHashResult.text = "ERROR GENERATING FINGERPRINT"
                    tvRawData.text = e.message ?: "Unknown error"
                    progressBar.visibility = View.GONE
                    btnGenerate.isEnabled = true
                    
                    cardHash.animate().alpha(1f).setDuration(500).start()
                    cardRaw.animate().alpha(1f).setDuration(500).setStartDelay(150).start()
                }
            }
        }
    }

    private fun logLargeString(tag: String, content: String) {
        if (content.length > 3000) {
            val chunkCount = content.length / 3000
            for (i in 0..chunkCount) {
                val max = 3000 * (i + 1)
                if (max >= content.length) {
                    android.util.Log.d(tag, "chunk " + i + " of " + chunkCount + ":\n" + content.substring(3000 * i))
                } else {
                    android.util.Log.d(tag, "chunk " + i + " of " + chunkCount + ":\n" + content.substring(3000 * i, max))
                }
            }
        } else {
            android.util.Log.d(tag, content)
        }
    }
}
