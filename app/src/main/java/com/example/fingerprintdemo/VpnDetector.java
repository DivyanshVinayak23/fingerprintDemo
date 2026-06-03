package com.example.fingerprintdemo;

import android.content.Context;

import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collections;
import java.util.List;

public class VpnDetector {

    public static DetectionResult isVpnActive(Context context) {
        try {
            java.util.Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            if (interfaces == null) {
                return new DetectionResult(false, null);
            }
            List<NetworkInterface> networkInterfaces = Collections.list(interfaces);
            if (networkInterfaces != null) {
                for (NetworkInterface networkInterface : networkInterfaces) {
                    String name = networkInterface.getName();
                    if (name != null) {
                        String lowerName = name.toLowerCase();
                        if (networkInterface.isUp() && 
                            (lowerName.contains("tun") || 
                             lowerName.contains("tap") || 
                             lowerName.contains("ppp") || 
                             lowerName.contains("pptp") || 
                             lowerName.contains("ipsec"))) {
                            
                            List<InterfaceAddress> interfaceAddresses = networkInterface.getInterfaceAddresses();
                            if (interfaceAddresses != null && !interfaceAddresses.isEmpty()) {
                                return new DetectionResult(true, "Active VPN interface found (InterfaceAddress): " + name);
                            }

                            List<InetAddress> inetAddresses = Collections.list(networkInterface.getInetAddresses());
                            if (inetAddresses != null && !inetAddresses.isEmpty()) {
                                return new DetectionResult(true, "Active VPN interface found (InetAddress): " + name);
                            }
                        }
                    }
                }
            }
        } catch (SocketException e) {
            e.printStackTrace();
        }
        return new DetectionResult(false, null);
    }
}
