package com.example.fingerprintdemo;

import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.os.Build;
import android.telephony.TelephonyManager;
import java.io.File;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public class DeviceFingerprintGenerator {

    // Returns a String array: [0] is the raw string, [1] is the SHA-256 hash
    public static String[] generateDeviceHashAndRaw(Context context) {
        StringBuilder rawData = new StringBuilder();

        // 1. Build.prop Attributes
        rawData.append("Build_FINGERPRINT:").append(Build.FINGERPRINT).append("\n");
        rawData.append("Build_MODEL:").append(Build.MODEL).append("\n");
        rawData.append("Build_MANUFACTURER:").append(Build.MANUFACTURER).append("\n");
        rawData.append("Build_HARDWARE:").append(Build.HARDWARE).append("\n");
        rawData.append("Build_PRODUCT:").append(Build.PRODUCT).append("\n");
        rawData.append("Build_BRAND:").append(Build.BRAND).append("\n");
        rawData.append("Build_BOARD:").append(Build.BOARD).append("\n");
        rawData.append("Build_DEVICE:").append(Build.DEVICE).append("\n");

        // 2. Telephony
        TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
        if (tm != null && tm.getNetworkOperatorName() != null && !tm.getNetworkOperatorName().isEmpty()) {
            rawData.append("Telephony_OP:").append(tm.getNetworkOperatorName()).append("\n");
        } else {
            rawData.append("Telephony_OP:NONE\n");
        }

        // 3. File-System Artifacts
        String[] knownEmulatorFiles = {
                "/dev/socket/qemud", "/dev/qemu_pipe", "/system/lib/libc_malloc_debug_qemu.so",
                "/sys/qemu_trace", "/system/bin/qemu-props"
        };
        for (String fileName : knownEmulatorFiles) {
            rawData.append("File_").append(fileName).append(":").append(new File(fileName).exists()).append("\n");
        }

        // 4. Sensors
        SensorManager sensorManager = (SensorManager) context.getSystemService(Context.SENSOR_MANAGER);
        if (sensorManager != null) {
            List<Sensor> sensors = sensorManager.getSensorList(Sensor.TYPE_ALL);
            rawData.append("Sensor_Count:").append(sensors.size()).append("\n");
            StringBuilder sensorVendors = new StringBuilder();
            for (Sensor sensor : sensors) {
                sensorVendors.append(sensor.getVendor()).append(",");
            }
            rawData.append("Sensor_Vendors:").append(sensorVendors.toString()).append("\n");
        } else {
            rawData.append("Sensor_Count:0\n");
        }

        // 5. Root & Hook Detection
        rawData.append("Magisk_App:").append(isMagiskAppInstalled(context)).append("\n");
        rawData.append("Magisk_Files:").append(hasMagiskFiles()).append("\n");
        rawData.append("Frida_Port:").append(isFridaPortOpen()).append("\n");

        String rawString = rawData.toString();
        return new String[]{rawString, hashString(rawString)};
    }

    private static boolean isMagiskAppInstalled(Context context) {
        try {
            context.getPackageManager().getPackageInfo("top.johnwu.magisk", 0);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    private static boolean hasMagiskFiles() {
        String[] magiskPaths = {
                "/sbin/.magisk", "/sbin/.core/mirror", "/sbin/.core/img", "/sbin/.core/db-0/magisk.db",
                "/data/adb/magisk", "/data/adb/magisk.img", "/data/adb/magisk.db", "/init.magisk.rc"
        };
        for (String path : magiskPaths) {
            if (new File(path).exists()) return true;
        }
        return false;
    }

    private static boolean isFridaPortOpen() {
        int[] fridaPorts = {27042, 27043};
        for (int port : fridaPorts) {
            try (Socket socket = new Socket("127.0.0.1", port)) {
                return true;
            } catch (Exception e) {
                // Port closed
            }
        }
        return false;
    }

    private static String hashString(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(input.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            return "HASH_ERROR";
        }
    }
}
