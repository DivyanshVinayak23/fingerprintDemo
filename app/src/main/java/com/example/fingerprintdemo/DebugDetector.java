package com.example.fingerprintdemo;

import android.content.Context;
import android.provider.Settings;
import android.os.Debug;

import java.io.BufferedReader;
import java.io.FileReader;

public class DebugDetector {

    public static DetectionResult isDebuggingOrDevModeEnabled(Context context) {
        StringBuilder reason = new StringBuilder();
        boolean detected = false;

        if (isAdbEnabled(context)) {
            detected = true;
            reason.append("ADB is enabled; ");
        }

        if (isDevelopmentSettingsEnabled(context)) {
            detected = true;
            reason.append("Development Settings are enabled; ");
        }

        if (isDebuggerConnected()) {
            detected = true;
            reason.append("Java Debugger connected; ");
        }

        int tracerPid = getTracerPid();
        if (tracerPid > 0) {
            detected = true;
            reason.append("Native TracerPid detected: ").append(tracerPid).append("; ");
        }

        return new DetectionResult(detected, detected ? reason.toString().trim() : null);
    }

    public static boolean isAdbEnabled(Context context) {
        try {
            return Settings.Global.getInt(context.getContentResolver(), Settings.Global.ADB_ENABLED, 0) != 0;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean isDevelopmentSettingsEnabled(Context context) {
        try {
            return Settings.Global.getInt(context.getContentResolver(), Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) != 0;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean isDebuggerConnected() {
        return Debug.isDebuggerConnected() || Debug.waitingForDebugger();
    }

    public static int getTracerPid() {
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader("/proc/self/status"));
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("TracerPid:")) {
                    String tracerPidStr = line.substring("TracerPid:".length()).trim();
                    try {
                        return Integer.parseInt(tracerPidStr);
                    } catch (NumberFormatException e) {
                        return 0;
                    }
                }
            }
        } catch (Exception e) {
            // ignore
        } finally {
            try {
                if (reader != null) reader.close();
            } catch (Exception e) {
                // ignore
            }
        }
        return 0;
    }
}
