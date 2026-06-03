package com.example.fingerprintdemo;

import android.content.Context;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.os.Build;
import android.telephony.TelephonyManager;

import java.io.File;
import java.util.List;

public class EmulatorDetector {

    public static DetectionResult isEmulator(Context context) {
        StringBuilder reason = new StringBuilder();
        boolean detected = false;

        String sensorReason = getSensorsSuspiciousReason(context);
        if (sensorReason != null) {
            detected = true;
            reason.append(sensorReason).append("; ");
        }

        String telephonyReason = getTelephonySuspiciousReason(context);
        if (telephonyReason != null) {
            detected = true;
            reason.append(telephonyReason).append("; ");
        }

        String filesReason = getEmulatorFilesReason();
        if (filesReason != null) {
            detected = true;
            reason.append(filesReason).append("; ");
        }

        String buildReason = getEmulatorBuildPropertiesReason();
        if (buildReason != null) {
            detected = true;
            reason.append(buildReason).append("; ");
        }

        return new DetectionResult(detected, detected ? reason.toString().trim() : null);
    }

    public static String getSensorsSuspiciousReason(Context context) {
        SensorManager sensorManager = (SensorManager) context.getSystemService(Context.SENSOR_SERVICE);
        if (sensorManager != null) {
            List<Sensor> sensorList = sensorManager.getSensorList(Sensor.TYPE_ALL);
            if (sensorList == null || sensorList.size() < 2) {
                return "Missing or fewer than 2 sensors";
            }
            for (Sensor sensor : sensorList) {
                String vendor = sensor.getVendor();
                if (vendor != null) {
                    String vendorLower = vendor.toLowerCase();
                    if (vendorLower.contains("android open source project") || 
                        vendorLower.contains("aosp") || 
                        vendorLower.contains("goldfish")) {
                        return "Emulator sensor vendor detected: " + vendor;
                    }
                }
            }
        } else {
            return "Missing SensorManager entirely";
        }
        return null;
    }

    public static String getTelephonySuspiciousReason(Context context) {
        TelephonyManager telephonyManager = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
        if (telephonyManager != null) {
            String networkOperatorName = telephonyManager.getNetworkOperatorName();
            if (networkOperatorName == null || networkOperatorName.trim().isEmpty() || "Android".equalsIgnoreCase(networkOperatorName)) {
                return "Suspicious Telephony Operator: " + (networkOperatorName == null ? "null" : networkOperatorName);
            }
        }
        return null;
    }

    public static String getEmulatorFilesReason() {
        String[] knownFiles = {
                "/dev/socket/qemud",
                "/dev/qemu_pipe",
                "/system/lib/libc_malloc_debug_qemu.so",
                "/sys/qemu_trace"
        };
        for (String filePath : knownFiles) {
            File file = new File(filePath);
            if (file.exists()) {
                return "QEMU file found: " + filePath;
            }
        }
        return null;
    }

    public static String getEmulatorBuildPropertiesReason() {
        String buildModel = Build.MODEL;
        String buildDevice = Build.DEVICE;

        if (buildModel != null && (buildModel.contains("Emulator") || buildModel.contains("Android SDK built for x86"))) {
            return "Suspicious Build.MODEL: " + buildModel;
        }
        if (buildDevice != null && buildDevice.startsWith("generic")) {
            return "Suspicious Build.DEVICE: " + buildDevice;
        }

        String qemuProperty = getSystemProperty("ro.kernel.qemu");
        if ("1".equals(qemuProperty)) {
            return "ro.kernel.qemu is set to 1";
        }

        return null;
    }

    private static String getSystemProperty(String propertyName) {
        try {
            Class<?> systemPropertiesClass = Class.forName("android.os.SystemProperties");
            return (String) systemPropertiesClass.getMethod("get", String.class).invoke(null, propertyName);
        } catch (Exception e) {
            return null;
        }
    }
}
