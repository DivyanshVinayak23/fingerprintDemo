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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        btnGenerate = findViewById(R.id.btnGenerate)
        progressBar = findViewById(R.id.progressBar)
        tvHashResult = findViewById(R.id.tvHashResult)
        tvRawData = findViewById(R.id.tvRawData)

        btnGenerate.setOnClickListener {
            checkPermissionAndGenerate()
        }
    }

    private fun checkPermissionAndGenerate() {
        if (ContextCompat.checkSelfPermission(
                this,
                Manifest.permission.READ_PHONE_STATE
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            ActivityCompat.requestPermissions(
                this,
                arrayOf(Manifest.permission.READ_PHONE_STATE),
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
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                generateFingerprint()
            } else {
                Toast.makeText(this, "Permission Required to Generate Fingerprint", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun generateFingerprint() {
        // Show loading state
        progressBar.visibility = View.VISIBLE
        btnGenerate.isEnabled = false

        // Launch in background to avoid NetworkOnMainThreadException (from isFridaPortOpen)
        CoroutineScope(Dispatchers.IO).launch {
            try {
                // Call the Java logic
                val results = DeviceFingerprintGenerator.generateDeviceHashAndRaw(this@MainActivity)
                val rawString = results[0]
                val hashResult = results[1]

                // Switch to Main thread to update UI
                withContext(Dispatchers.Main) {
                    tvHashResult.text = "Hash: $hashResult"
                    tvRawData.text = rawString
                    progressBar.visibility = View.GONE
                    btnGenerate.isEnabled = true
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    tvHashResult.text = "Error generating fingerprint"
                    tvRawData.text = e.message ?: "Unknown error"
                    progressBar.visibility = View.GONE
                    btnGenerate.isEnabled = true
                }
            }
        }
    }
}
