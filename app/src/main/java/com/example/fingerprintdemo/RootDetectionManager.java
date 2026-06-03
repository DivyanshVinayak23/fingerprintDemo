package com.example.fingerprintdemo;

import android.content.Context;
import android.os.Build;
import android.provider.Settings;

import com.scottyab.rootbeer.RootBeer;

import java.io.*;
import java.util.*;

public class RootDetectionManager {

    public enum State {
        CLEAN,
        SUSPICIOUS,
        ROOTED
    }

    public static class Result {
        public final State state;
        public final String details;

        public Result(State state, String details) {
            this.state = state;
            this.details = details;
        }
    }

    public static Result check(Context context) {
        int score = 0;
        List<String> reasons = new ArrayList<>();
        RootBeer rootBeer = new RootBeer(context);

        if (rootBeer.checkForSuBinary() || rootBeer.checkSuExists() || checkWhichSu()) {
            return new Result(State.ROOTED, "SU binary detected");
        }

        if (rootBeer.checkForMagiskBinary() || hasMagiskOrSuspiciousArtifacts()) {
            return new Result(State.ROOTED, "Magisk/Suspicious artifacts detected");
        }

        if (hasXposedFiles() || hasXposedModules(context)) {
            return new Result(State.ROOTED, "Xposed framework/modules detected");
        }

        if (rootBeer.checkForRootNative()) {
            return new Result(State.ROOTED, "Native root detected");
        }

        if (rootBeer.detectRootManagementApps()) {
            return new Result(State.ROOTED, "Root management apps detected");
        }

        if (rootBeer.detectRootCloakingApps()) {
            return new Result(State.ROOTED, "Root cloaking apps detected");
        }

        if (isSELinuxPermissive()) {
            score += 2;
            reasons.add("SELinux Permissive");
        }

        if (rootBeer.checkForDangerousProps() || hasInsecureProps()) {
            score += 2;
            reasons.add("Insecure system properties");
        }

        if (rootBeer.checkForRWPaths() || hasRwSystemMounts()) {
            score += 2;
            reasons.add("RW system/vendor mounts");
        }

        if (isNonUserBuild()) {
            reasons.add("Non-user build");
        }

        if (rootBeer.detectTestKeys() || hasTestKeys()) {
            reasons.add("Test-keys build");
        }

        if (isAdbEnabled(context)) {
            reasons.add("ADB enabled");
        }

        if (score >= 4) {
            return new Result(State.ROOTED, join(reasons));
        } else if (score >= 2) {
            return new Result(State.SUSPICIOUS, join(reasons));
        } else {
            return new Result(State.CLEAN, null);
        }
    }


    private static boolean hasMagiskOrSuspiciousArtifacts() {
        String[] paths = {
                "/sbin/.magisk/", "/sbin/.core/mirror", "/sbin/.core/img", "/sbin/.core/db-0/magisk.db",
                "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su", "/sbin/su", "/su/bin/su",
                "/system/bin/su", "/system/bin/.ext/su", "/system/bin/failsafe/su", "/system/sd/xbin/su",
                "/system/usr/we-need-root/su", "/system/xbin/su", "/cache/su", "/data/su", "/dev/su",
                "/data/data/moe.shizuku.redirectstorage", "/data/adb/modules/riru_momohider/config/isolated",
                "/data/adb/modules/riru_momohider/config/setns", "/data/adb/modules/riru_momohider/config/app_zygote_magic",
                "/data/adb/modules/riru_momohider/config/initrc", "data/adb/modules/riru-unshare",
                "/data/adb/lspd", "/data/adb/magisk", "/data/adb/riru", "/data/adb/shamiko",
                "/data/adb/storage-isolation", "/data/adb/modules/liboemcryptodisabler",
                "/data/adb/modules/MagiskHidePropsConf", "/data/adb/modules/riru-core",
                "/data/adb/modules/riru_lsposed", "/data/adb/modules/riru_storage_redirect",
                "/data/adb/modules/zygisk_lsposed", "/data/adb/modules/zygisk_shamiko",
                "/init.magisk.rc"
        };
        for (String path : paths) {
            File f = new File(path);
            if (f.exists() || f.isDirectory()) return true;
        }
        return false;
    }

    private static boolean hasXposedFiles() {
        String[] paths = {
                "/xposed.prop",
                "/system/bin/app_process.orig",
                "/system/lib/libxposed_art.so",
                "/system/lib64/libxposed_art.so",
                "/system/bin/app_process32_xposed",
                "/system/bin/app_process64_xposed"
        };
        for (String path : paths) {
            if (new File(path).exists()) return true;
        }
        return false;
    }

    private static boolean hasXposedModules(Context context) {
        android.content.pm.PackageManager pm = context.getPackageManager();
        android.content.Intent intent = new android.content.Intent(android.content.Intent.ACTION_MAIN);
        List<android.content.pm.ResolveInfo> list;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            list = pm.queryIntentActivities(intent, android.content.pm.PackageManager.ResolveInfoFlags.of(android.content.pm.PackageManager.GET_META_DATA));
        } else {
            list = pm.queryIntentActivities(intent, android.content.pm.PackageManager.GET_META_DATA);
        }
        for (android.content.pm.ResolveInfo info : list) {
            if (info.activityInfo != null && info.activityInfo.applicationInfo != null && info.activityInfo.applicationInfo.metaData != null) {
                if (info.activityInfo.applicationInfo.metaData.containsKey("xposedminversion")) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean checkWhichSu() {
        Process process = null;
        try {
            process = Runtime.getRuntime().exec(new String[]{"/system/xbin/which", "su"});
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            return in.readLine() != null;
        } catch (Throwable t) {
            return false;
        } finally {
            if (process != null) process.destroy();
        }
    }

    private static boolean hasRwSystemMounts() {
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/mounts"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if ((line.contains("/system") || line.contains("/vendor"))
                        && line.contains(" rw,")) {
                    return true;
                }
            }
        } catch (Exception ignored) {}
        return false;
    }

    private static boolean isSELinuxPermissive() {
        try {
            Process p = Runtime.getRuntime().exec("getenforce");
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String out = r.readLine();
            return "Permissive".equalsIgnoreCase(out);
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean hasInsecureProps() {
        String debuggable = getProp("ro.debuggable");
        String secure = getProp("ro.secure");

        return "1".equals(debuggable) || "0".equals(secure);
    }

    private static String getProp(String key) {
        try {
            Process p = Runtime.getRuntime().exec("getprop " + key);
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            return r.readLine();
        } catch (Exception e) {
            return null;
        }
    }

    private static boolean isNonUserBuild() {
        return "eng".equals(Build.TYPE) || "userdebug".equals(Build.TYPE);
    }

    private static boolean hasTestKeys() {
        return Build.TAGS != null && Build.TAGS.contains("test-keys");
    }

    private static boolean isAdbEnabled(Context context) {
        try {
            return Settings.Global.getInt(
                    context.getContentResolver(),
                    Settings.Global.ADB_ENABLED, 0) == 1;
        } catch (Exception e) {
            return false;
        }
    }

    private static String join(List<String> list) {
        return list.isEmpty() ? null : android.text.TextUtils.join(", ", list);
    }
}
