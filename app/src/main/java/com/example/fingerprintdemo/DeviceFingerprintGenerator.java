package com.example.fingerprintdemo;

import android.app.ActivityManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ConfigurationInfo;
import android.content.pm.PackageManager;
import android.hardware.Sensor;
import android.hardware.SensorManager;
import android.media.MediaDrm;
import android.os.BatteryManager;
import android.os.Build;
import android.telephony.TelephonyManager;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.UUID;

public class DeviceFingerprintGenerator {

    public static String[] generateDeviceHashAndRaw(Context context) {
        JSONObject rawData = new JSONObject();
        JSONObject fuzzyData = new JSONObject(); 
        
        try {
            JSONObject buildProps = new JSONObject();
            buildProps.put("FINGERPRINT", Build.FINGERPRINT);
            buildProps.put("MODEL", Build.MODEL);
            buildProps.put("MANUFACTURER", Build.MANUFACTURER);
            buildProps.put("HARDWARE", Build.HARDWARE);
            buildProps.put("PRODUCT", Build.PRODUCT);
            buildProps.put("BRAND", Build.BRAND);
            buildProps.put("BOARD", Build.BOARD);
            buildProps.put("DEVICE", Build.DEVICE);
            rawData.put("Build", buildProps);
            
            JSONObject fuzzyBuildProps = new JSONObject();
            fuzzyBuildProps.put("MODEL", Build.MODEL);
            fuzzyBuildProps.put("MANUFACTURER", Build.MANUFACTURER);
            fuzzyBuildProps.put("HARDWARE", Build.HARDWARE);
            fuzzyBuildProps.put("PRODUCT", Build.PRODUCT);
            fuzzyBuildProps.put("BRAND", Build.BRAND);
            fuzzyBuildProps.put("BOARD", Build.BOARD);
            fuzzyBuildProps.put("DEVICE", Build.DEVICE);
            fuzzyData.put("Build", fuzzyBuildProps);

            TelephonyManager tm = (TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
            String operatorName = "NONE";
            if (tm != null && tm.getNetworkOperatorName() != null && !tm.getNetworkOperatorName().isEmpty()) {
                operatorName = tm.getNetworkOperatorName();
            }
            rawData.put("Telephony_OP", operatorName);
            fuzzyData.put("Telephony_OP", operatorName);

            String[] knownEmulatorFiles = {
                    "/dev/socket/qemud", "/dev/qemu_pipe", "/system/lib/libc_malloc_debug_qemu.so",
                    "/sys/qemu_trace", "/system/bin/qemu-props"
            };
            JSONArray emuFilesArray = new JSONArray();
            boolean isEmulatorFileFound = false;
            for (String fileName : knownEmulatorFiles) {
                boolean exists = new File(fileName).exists();
                if (exists) isEmulatorFileFound = true;
                JSONObject fileObj = new JSONObject();
                fileObj.put("file", fileName);
                fileObj.put("exists", exists);
                emuFilesArray.put(fileObj);
            }
            rawData.put("Emulator_Files", emuFilesArray);
            fuzzyData.put("Emulator_Files", emuFilesArray);

            SensorManager sensorManager = (SensorManager) context.getSystemService(Context.SENSOR_SERVICE);
            JSONArray sensorVendorsArray = new JSONArray();
            int sensorCount = 0;
            boolean hasSamsungSensor = false;
            boolean hasAospSensor = false;
            if (sensorManager != null) {
                List<Sensor> sensors = sensorManager.getSensorList(Sensor.TYPE_ALL);
                sensorCount = sensors.size();
                for (Sensor sensor : sensors) {
                    String vendor = sensor.getVendor();
                    sensorVendorsArray.put(vendor);
                    if (vendor != null) {
                        String vendorLower = vendor.toLowerCase();
                        if (vendorLower.contains("samsung") || vendorLower.contains("stm")) {
                            hasSamsungSensor = true;
                        }
                        if (vendorLower.contains("android open source project") || vendorLower.contains("aosp") || vendorLower.contains("goldfish")) {
                            hasAospSensor = true;
                        }
                    }
                }
            }
            JSONObject sensorProps = new JSONObject();
            sensorProps.put("Count", sensorCount);
            sensorProps.put("Vendors", sensorVendorsArray);
            rawData.put("Sensors", sensorProps);
            fuzzyData.put("Sensors", sensorProps);

            boolean magiskApp = isMagiskAppInstalled(context);
            boolean xposedApp = isXposedAppInstalled(context);
            boolean magiskFiles = hasMagiskFiles();
            boolean fridaPort = isFridaPortOpen();
            JSONObject rootProps = new JSONObject();
            rootProps.put("Magisk_App", magiskApp);
            rootProps.put("Xposed_App", xposedApp);
            rootProps.put("Magisk_Files", magiskFiles);
            rootProps.put("Frida_Port", fridaPort);
            rawData.put("Root_Detection", rootProps);
            fuzzyData.put("Root_Detection", rootProps);
            
            
            IntentFilter ifilter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
            Intent batteryStatus = context.registerReceiver(null, ifilter);
            if (batteryStatus != null) {
                int level = batteryStatus.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
                int scale = batteryStatus.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
                int status = batteryStatus.getIntExtra(BatteryManager.EXTRA_STATUS, -1);
                boolean isCharging = status == BatteryManager.BATTERY_STATUS_CHARGING ||
                                     status == BatteryManager.BATTERY_STATUS_FULL;
                float batteryPct = level * 100 / (float)scale;
                
                JSONObject batteryProps = new JSONObject();
                batteryProps.put("Level_Pct", batteryPct);
                batteryProps.put("Is_Charging", isCharging);
                rawData.put("Battery", batteryProps);
            }

            try {
                UUID widevineUuid = new UUID(0xEDEF8BA979D64ACEL, 0xA3C827DCD51D21EDL);
                MediaDrm mediaDrm = new MediaDrm(widevineUuid);
                byte[] widevineId = mediaDrm.getPropertyByteArray(MediaDrm.PROPERTY_DEVICE_UNIQUE_ID);
                StringBuilder sb = new StringBuilder();
                for (byte b : widevineId) {
                    sb.append(String.format("%02x", b));
                }
                rawData.put("Widevine_ID", sb.toString());
                fuzzyData.put("Widevine_ID", sb.toString());
                mediaDrm.close();
            } catch (Exception e) {
                rawData.put("Widevine_ID", "UNAVAILABLE");
                fuzzyData.put("Widevine_ID", "UNAVAILABLE");
            }
            
            ActivityManager activityManager = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
            if (activityManager != null) {
                ConfigurationInfo configurationInfo = activityManager.getDeviceConfigurationInfo();
                String glVersion = configurationInfo.getGlEsVersion();
                rawData.put("OpenGL_Version", glVersion);
                fuzzyData.put("OpenGL_Version", glVersion);
            }

            
            boolean isTampered = magiskApp || magiskFiles || fridaPort;
            
            boolean isHardwareAnomaly = false;
            if (Build.MANUFACTURER.equalsIgnoreCase("samsung") && sensorCount > 0 && !hasSamsungSensor) {
                isHardwareAnomaly = true;
            }
            if ("Android".equalsIgnoreCase(operatorName) && 
               (Build.MANUFACTURER.equalsIgnoreCase("google") || Build.MANUFACTURER.equalsIgnoreCase("samsung"))) {
                isHardwareAnomaly = true;
            }
            DetectionResult isEmulator = EmulatorDetector.isEmulator(context);
            DetectionResult isClonedApp = AppTamperingDetector.isAppCloned(context);
            DetectionResult isAppRepackaged = AppTamperingDetector.isAppRepackaged(context);
            
            RootDetectionManager.Result rootResult = RootDetectionManager.check(context);
            boolean isDeviceRooted = rootResult.state == RootDetectionManager.State.ROOTED || rootResult.state == RootDetectionManager.State.SUSPICIOUS;
            String rootReason = "State: " + rootResult.state.name() + (rootResult.details != null ? " - " + rootResult.details : "");
            DetectionResult isRooted = new DetectionResult(isDeviceRooted, rootReason);
            
            DetectionResult isDebuggingEnabled = DebugDetector.isDebuggingOrDevModeEnabled(context);
            DetectionResult isMitMDetected = MitMDetector.isMitMAttackDetected(context);
            DetectionResult isTapjackingLikely = TapjackingDetector.isTapjackingLikely(context);
            DetectionResult isVpnActive = VpnDetector.isVpnActive(context);

            JSONObject signals = new JSONObject();
            signals.put("Device_Tampered", isTampered);
            signals.put("Hardware_Anomaly", isHardwareAnomaly);
            signals.put("Is_Emulator", isEmulator.toJson());
            signals.put("ClonedApp", isClonedApp.toJson());
            signals.put("AppRepackageDetection", isAppRepackaged.toJson());
            signals.put("isRooted", isRooted.toJson());
            signals.put("isDebuggingEnabled", isDebuggingEnabled.toJson());
            signals.put("isMitMAttack", isMitMDetected.toJson());
            signals.put("isTapjackingLikely", isTapjackingLikely.toJson());
            signals.put("isVpnActive", isVpnActive.toJson());
            
            FactoryResetDetector.FactoryResetResult resetResult = FactoryResetDetector.detect(context);
            JSONObject resetJson = new JSONObject();
            resetJson.put("estimatedResetTime", resetResult.getEstimatedResetTime() != null ? resetResult.getEstimatedResetTime() : JSONObject.NULL);
            resetJson.put("source", resetResult.getSource());
            resetJson.put("confidence", resetResult.getConfidence().name());
            signals.put("FactoryResetDetection", resetJson);
            
            DetectionResult isMockLocationEnabled = GeoSpoofingDetector.checkMockLocationEnabled(context);
            boolean isLocationEnabled = GeoSpoofingDetector.isLocationEnabled(context);
            android.location.Location location = GeoSpoofingDetector.getLastKnownLocationSynchronously(context);
            DetectionResult isLocationMocked = GeoSpoofingDetector.checkLocationMocked(location);
            double[] ipLocation = GeoSpoofingDetector.getIpLocationSynchronously();
            DetectionResult isIpDistanceSuspicious = GeoSpoofingDetector.checkIpDistanceSuspicious(location, ipLocation);

            JSONObject geoSpoofing = new JSONObject();
            geoSpoofing.put("isMockLocationEnabled", isMockLocationEnabled.toJson());
            geoSpoofing.put("isLocationEnabled", isLocationEnabled);
            geoSpoofing.put("isLocationMocked", isLocationMocked.toJson());
            geoSpoofing.put("isIpDistanceSuspicious", isIpDistanceSuspicious.toJson());
            if (location != null) {
                geoSpoofing.put("latitude", location.getLatitude());
                geoSpoofing.put("longitude", location.getLongitude());
            }
            if (ipLocation != null) {
                geoSpoofing.put("ip_latitude", ipLocation[0]);
                geoSpoofing.put("ip_longitude", ipLocation[1]);
            }
            rawData.put("Geo_Spoofing", geoSpoofing);
            fuzzyData.put("Geo_Spoofing", geoSpoofing);

            rawData.put("Smart_Signals", signals);
            fuzzyData.put("Smart_Signals", signals);

        } catch (JSONException e) {
            e.printStackTrace();
        }

        String rawString;
        String fuzzyString;
        try {
            rawString = rawData.toString(2); // Indented formatting
            fuzzyString = fuzzyData.toString(); // Unformatted for hashing
        } catch (JSONException e) {
            rawString = rawData.toString();
            fuzzyString = fuzzyData.toString();
        }

        return new String[]{rawString, hashString(rawData.toString()), hashString(fuzzyString)};
    }

    private static boolean isMagiskAppInstalled(Context context) {
        String[] magiskPackages = {
            "top.johnwu.magisk",
            "com.topjohnwu.magisk"
        };
        for (String pkg : magiskPackages) {
            try {
                context.getPackageManager().getPackageInfo(pkg, 0);
                return true;
            } catch (PackageManager.NameNotFoundException e) {
                // Ignore
            }
        }
        return false;
    }

    private static boolean isXposedAppInstalled(Context context) {
        String[] xposedPackages = {
            "de.robv.android.xposed.installer",
            "org.meowcat.edxposed.manager",
            "org.lsposed.manager"
        };
        for (String pkg : xposedPackages) {
            try {
                context.getPackageManager().getPackageInfo(pkg, 0);
                return true;
            } catch (PackageManager.NameNotFoundException e) {
                // Ignore
            }
        }
        return false;
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
