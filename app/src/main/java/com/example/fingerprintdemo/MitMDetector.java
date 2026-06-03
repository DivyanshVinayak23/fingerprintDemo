package com.example.fingerprintdemo;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.ProxyInfo;
import android.os.Build;
import android.provider.Settings;
import android.text.TextUtils;

public class MitMDetector {

    public static DetectionResult isMitMAttackDetected(Context context) {
        StringBuilder reason = new StringBuilder();
        boolean detected = false;

        String globalProxy = getGlobalProxyConfiguredReason(context);
        if (globalProxy != null) {
            detected = true;
            reason.append(globalProxy).append("; ");
        }

        String defaultProxy = getDefaultProxyConfiguredReason(context);
        if (defaultProxy != null) {
            detected = true;
            reason.append(defaultProxy).append("; ");
        }

        return new DetectionResult(detected, detected ? reason.toString().trim() : null);
    }

    public static String getGlobalProxyConfiguredReason(Context context) {
        try {
            String globalProxy = Settings.Global.getString(context.getContentResolver(), Settings.Global.HTTP_PROXY);
            if (!TextUtils.isEmpty(globalProxy)) {
                return "Global HTTP Proxy configured: " + globalProxy;
            }
        } catch (Exception e) {
            // ignore
        }
        return null;
    }

    @SuppressWarnings("deprecation")
    public static String getDefaultProxyConfiguredReason(Context context) {
        try {
            ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm != null) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    ProxyInfo proxyInfo = cm.getDefaultProxy();
                    if (proxyInfo != null) {
                        String host = proxyInfo.getHost();
                        int port = proxyInfo.getPort();
                        if (!TextUtils.isEmpty(host) && port != 0) {
                            return "Default Network Proxy configured: " + host + ":" + port;
                        }
                    }
                } else {
                    String proxyHost = android.net.Proxy.getHost(context);
                    int proxyPort = android.net.Proxy.getPort(context);
                    if (!TextUtils.isEmpty(proxyHost) && proxyPort != -1) {
                        return "Legacy Network Proxy configured: " + proxyHost + ":" + proxyPort;
                    }
                }
            }
        } catch (Exception e) {
            // ignore
        }
        return null;
    }
}
