# Android Device Fingerprinting & RASP Demo

A professional, high-performance Android demonstration application showcasing advanced device fingerprinting methodologies combined with **Runtime Application Self-Protection (RASP)** security signals. 

This project demonstrates how to generate consistent device identifiers (both exact and fuzzy hashes) and capture critical telemetry signals to assess device integrity, detect security threats, and prevent fraud in real time.

---

## 🚀 Key Features & Capabilities

### 1. Dual-Fingerprint Engine
* **Exact Hash (SHA-256)**: A point-in-time cryptographic digest representing the precise hardware, software, and environment state of the device.
* **Fuzzy Hash (SHA-256)**: A stable, persistent device signature that excludes volatile parameters (such as battery status and charging state) to ensure the identifier remains consistent across boots, charging cycles, and minor environment drift.

### 2. Runtime Application Self-Protection (RASP) Signals
The demo app implements modular security detectors capturing various risk factors:

* **🛡️ Root & Tamper Detection (`RootDetectionManager`)**:
  * Scans for the presence of Magisk files and top-level installer packages.
  * Detects Xposed/EdXposed/LSPosed frameworks.
  * Probes default Frida server ports (`27042`, `27043`) for local socket hook detection.
* **📱 Emulator Detection (`EmulatorDetector`)**:
  * Assesses virtualized hardware build markers (e.g. `goldfish`, `qemu`, `google_sdk`).
  * Checks for standard emulator system paths and sockets (`/dev/socket/qemud`, `/dev/qemu_pipe`).
  * Evaluates sensor lists for characteristic missing physical sensors or mock sensors.
* **🌀 App Cloning & Repackaging (`AppTamperingDetector`)**:
  * Validates the application's runtime signature certificate against original developer certificate hashes.
  * Inspects package installation contexts to determine if the app has been repackaged or cloned within virtual environments (e.g. Dual Space, Parallel Space).
* **🌍 Geo-Spoofing & Mock Location (`GeoSpoofingDetector`)**:
  * Queries Android's Location Provider API to detect active mock location configurations.
  * Compares cellular/Wi-Fi derived GPS coordinates against IP-based geolocation dynamically to flag distance anomalies.
* **🔒 Network & Traffic Integrity (`MitMDetector` & `VpnDetector`)**:
  * Probes network configurations for active proxy servers, custom user-installed CA certificates, or proxy routing.
  * Inspects the active network interface list for TUN/TAP devices to detect active VPN tunnels.
* **⏳ Factory Reset Tracker (`FactoryResetDetector`)**:
  * Estimates when the device was last factory reset by inspecting specific system directory creation dates (e.g. `/data/system/users/0`).
  * Used to mitigate sybil or reset-loop attacks.
* **👾 UI Vulnerability Check (`TapjackingDetector`)**:
  * Checks if overlay permissions or third-party overlays pose a risk of tapjacking/UI spoofing.
* **⚡ Debug Status Tracker (`DebugDetector`)**:
  * Assesses whether developer mode is enabled and whether a debugger is currently attached (`android.os.Debug.isDebuggerConnected()`).

---

## 📁 Repository Structure

```
├── README.md                                 # This documentation file
├── Android_Fingperprint_Signals_V1.xlsx      # Signal telemetry design spreadsheet
├── build.gradle.kts                          # Project-level Gradle build script
├── settings.gradle.kts                       # Settings definition
├── gradlew / gradlew.bat                    # Gradle wrappers
└── app
    ├── build.gradle.kts                      # App-level build configurations
    └── src
        └── main
            ├── AndroidManifest.xml           # Main Android permission declarations
            ├── java/com/example/fingerprintdemo
            │   ├── MainActivity.kt           # UI Controller, animation runner & orchestrator
            │   ├── DeviceFingerprintGenerator.java # Combines all telemetry into exact/fuzzy JSON structure
            │   ├── AppTamperingDetector.java # Detects cloned apps and APK signature changes
            │   ├── DebugDetector.java        # Assesses developer/debugging statuses
            │   ├── DetectionResult.java      # Model representing boolean status with explanatory reasons
            │   ├── EmulatorDetector.java     # Checks environment signatures for virtualized devices
            │   ├── FactoryResetDetector.kt   # Estimates elapsed time since last factory reset
            │   ├── GeoSpoofingDetector.java  # Validates location mock flags and IP-GPS coordinates
            │   ├── MitMDetector.java         # Checks for traffic interception, custom CAs, and proxies
            │   ├── RootDetectionManager.java # Runs system binary, property, and path checks for Root/Su
            │   ├── TapjackingDetector.java   # Evaluates UI overlay permissions and settings
            │   └── VpnDetector.java          # Scans interfaces for active VPN tunnels
            └── res/layout
                └── activity_main.xml         # Modern Material UI interface layout file
```

---

## 🛠️ Getting Started

### Prerequisites
* **Java Development Kit (JDK)**: v17 or higher.
* **Android SDK**: API Level 34 (Android 14) recommended for building.
* **Android Studio**: Jellyfish or newer.

### Build & Run
To compile and generate the debug APK from the command line:

```bash
# Set executable permissions (if not already set)
chmod +x gradlew

# Clean and build the project
./gradlew clean assembleDebug
```

To install directly to a connected Android physical device or emulator:
```bash
./gradlew installDebug
```

---

## 📊 Telephony & Location Permissions
The application leverages fallback mechanisms. While permissions like `READ_PHONE_STATE` and `ACCESS_FINE_LOCATION` will provide richer fingerprinting data (e.g. operator networks, location validation), the fingerprint engine automatically adjusts and falls back to system properties and alternative APIs if permissions are denied.

---

## 📜 License
This project is for educational and demonstrative purposes. All code is provided under standard license terms. Consult the repository owners before deploying any of these RASP modules in production-grade security setups.
