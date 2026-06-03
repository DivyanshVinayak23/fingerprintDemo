package com.example.fingerprintdemo;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.os.Process;
import android.os.UserHandle;
import android.os.UserManager;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

public class AppTamperingDetector {

    private static final String EXPECTED_SIGNATURE_HASH = "random_placeholder_hash_string_12345";

    public static DetectionResult isAppCloned(Context context) {
        StringBuilder reason = new StringBuilder();
        boolean detected = false;

        if (isRunningInWorkOrSecondaryProfile(context)) {
            detected = true;
            reason.append("Running in Work or Secondary Profile; ");
        }

        String clonerApp = getKnownClonerApp(context);
        if (clonerApp != null) {
            detected = true;
            reason.append("Known cloner app found: ").append(clonerApp).append("; ");
        }

        if (isSuspiciousProfileCreationTime(context)) {
            detected = true;
            reason.append("Suspicious profile creation time (created at same time as app install); ");
        }

        return new DetectionResult(detected, detected ? reason.toString().trim() : null);
    }

    public static DetectionResult isAppRepackaged(Context context) {
        String currentHash = getAppSignatureHash(context);
        if (currentHash == null) {
            return new DetectionResult(false, null);
        }
        boolean repackaged = !EXPECTED_SIGNATURE_HASH.equalsIgnoreCase(currentHash);
        String reason = repackaged ? "Signature hash mismatch. Expected: " + EXPECTED_SIGNATURE_HASH + ", Got: " + currentHash : null;
        return new DetectionResult(repackaged, reason);
    }

    private static boolean isRunningInWorkOrSecondaryProfile(Context context) {
        UserManager userManager = (UserManager) context.getSystemService(Context.USER_SERVICE);
        if (userManager != null) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                return !userManager.isSystemUser();
            }
        }
        return false;
    }

    private static String getKnownClonerApp(Context context) {
        String[] knownCloners = {
                "com.lbe.parallel", "com.excelliance.multiaccount", "com.lbe.parallel.intl",
                "com.qihoo.magic", "com.qihoo.magic_zhang", "com.dualspace.multispace.clone.app",
                "com.duapps.ad", "com.ludashi.dualspace"
        };
        List<String> clonersList = Arrays.asList(knownCloners);

        PackageManager pm = context.getPackageManager();
        if (pm != null) {
            List<ApplicationInfo> packages = pm.getInstalledApplications(PackageManager.GET_META_DATA);
            for (ApplicationInfo appInfo : packages) {
                if (clonersList.contains(appInfo.packageName)) {
                    return appInfo.packageName;
                }
            }
        }
        return null;
    }

    private static boolean isSuspiciousProfileCreationTime(Context context) {
        UserManager userManager = (UserManager) context.getSystemService(Context.USER_SERVICE);
        if (userManager == null) return false;

        try {
            long installTime = context.getPackageManager().getPackageInfo(context.getPackageName(), 0).firstInstallTime;
            
            long userCreationTime = 0;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                UserHandle myUserHandle = Process.myUserHandle();
                try {
                    java.lang.reflect.Method method = userManager.getClass().getMethod("getUserCreationTime", UserHandle.class);
                    Object timeObj = method.invoke(userManager, myUserHandle);
                    if (timeObj instanceof Long) {
                        userCreationTime = (Long) timeObj;
                    }
                } catch (Exception e) {
                    return false;
                }
            }
            
            if (userCreationTime > 0) {
                long diff = Math.abs(installTime - userCreationTime);
                if (diff < 60000) {
                    return true;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    private static String getAppSignatureHash(Context context) {
        try {
            PackageManager pm = context.getPackageManager();
            String packageName = context.getPackageName();
            Signature[] signatures = null;
            
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageInfo packageInfo = pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES);
                if (packageInfo.signingInfo != null) {
                    if (packageInfo.signingInfo.hasMultipleSigners()) {
                        signatures = packageInfo.signingInfo.getApkContentsSigners();
                    } else {
                        signatures = packageInfo.signingInfo.getSigningCertificateHistory();
                    }
                }
            } else {
                PackageInfo packageInfo = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
                signatures = packageInfo.signatures;
            }

            if (signatures != null && signatures.length > 0) {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                md.update(signatures[0].toByteArray());
                byte[] digest = md.digest();
                
                StringBuilder sb = new StringBuilder();
                for (byte b : digest) {
                    sb.append(String.format("%02x", b));
                }
                return sb.toString();
            }
        } catch (PackageManager.NameNotFoundException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
}
