package com.example.fingerprintdemo;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.provider.Settings;
import android.text.TextUtils;
import android.view.accessibility.AccessibilityManager;

import java.util.List;

public class TapjackingDetector {

    public static DetectionResult isTapjackingLikely(Context context) {
        StringBuilder reason = new StringBuilder();
        boolean detected = false;

        String overlayReason = getOverlayEnabledReason(context);
        if (overlayReason != null) {
            detected = true;
            reason.append(overlayReason).append("; ");
        }

        String accessibilityReason = getAccessibilitySuspiciousReason(context);
        if (accessibilityReason != null) {
            detected = true;
            reason.append(accessibilityReason).append("; ");
        }

        return new DetectionResult(detected, detected ? reason.toString().trim() : null);
    }

    public static String getOverlayEnabledReason(Context context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                if (Settings.canDrawOverlays(context)) {
                    return "SYSTEM_ALERT_WINDOW (Overlay) permission is granted";
                }
            } catch (Exception e) {
                // ignore
            }
        }
        return null;
    }
// Installation source + accessibility priveleges
    public static String getAccessibilitySuspiciousReason(Context context) {
        boolean isAccessibilityEnabled = false;
        try {
            int accessibilityEnabled = Settings.Secure.getInt(
                    context.getContentResolver(),
                    Settings.Secure.ACCESSIBILITY_ENABLED, 0);
            isAccessibilityEnabled = (accessibilityEnabled == 1);
        } catch (Exception e) {
            // ignore
        }

        if (!isAccessibilityEnabled) {
            return null;
        }

        try {
            AccessibilityManager am = (AccessibilityManager) context.getSystemService(Context.ACCESSIBILITY_SERVICE);
            if (am != null) {
                List<AccessibilityServiceInfo> enabledServices = am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK);
                for (AccessibilityServiceInfo service : enabledServices) {
                    if (service.getResolveInfo() != null && service.getResolveInfo().serviceInfo != null) {
                        ApplicationInfo appInfo = service.getResolveInfo().serviceInfo.applicationInfo;
                        if ((appInfo.flags & ApplicationInfo.FLAG_SYSTEM) == 0) {
                            return "Suspicious third-party Accessibility Service running: " + appInfo.packageName;
                        }
                    }
                }
            }
        } catch (Exception e) {
            String services = Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
            if (!TextUtils.isEmpty(services)) {
                return "Unknown Accessibility Services enabled: " + services;
            }
        }

        return null;
    }
}
