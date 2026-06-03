package com.example.fingerprintdemo;

import android.Manifest;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.location.Location;
import android.location.LocationManager;
import android.os.Build;
import android.provider.Settings;
import androidx.core.content.ContextCompat;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;

public class GeoSpoofingDetector {

    /**
     * Equivalent to JailMonkey.canMockLocation().
     * Checks global mock location settings or if apps have the mock location permission.
     */
    public static DetectionResult checkMockLocationEnabled(Context context) {
        try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
                String allowMockLocation = Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ALLOW_MOCK_LOCATION);
                boolean isMockLocation = allowMockLocation != null && !allowMockLocation.equals("0");
                return new DetectionResult(isMockLocation, isMockLocation ? "Settings.Secure.ALLOW_MOCK_LOCATION is enabled" : null);
            } else {
                PackageManager pm = context.getPackageManager();
                android.app.AppOpsManager opsManager = (android.app.AppOpsManager) context.getSystemService(Context.APP_OPS_SERVICE);
                List<android.content.pm.ApplicationInfo> packages = pm.getInstalledApplications(PackageManager.GET_META_DATA);
                String installedAppWithPermission = null;
                for (android.content.pm.ApplicationInfo applicationInfo : packages) {
                    try {
                        PackageInfo packageInfo = pm.getPackageInfo(applicationInfo.packageName, PackageManager.GET_PERMISSIONS);
                        String[] requestedPermissions = packageInfo.requestedPermissions;
                        if (requestedPermissions != null) {
                            for (String permission : requestedPermissions) {
                                if (permission.equals("android.permission.ACCESS_MOCK_LOCATION")
                                        && !applicationInfo.packageName.equals(context.getPackageName())) {
                                    
                                    installedAppWithPermission = applicationInfo.packageName;
                                    
                                    int mode = opsManager.checkOpNoThrow(
                                            android.app.AppOpsManager.OPSTR_MOCK_LOCATION,
                                            applicationInfo.uid,
                                            applicationInfo.packageName
                                    );
                                    if (mode == android.app.AppOpsManager.MODE_ALLOWED) {
                                        return new DetectionResult(true, "Mock location app actively selected in Developer Options: " + applicationInfo.packageName);
                                    }
                                }
                            }
                        }
                    } catch (PackageManager.NameNotFoundException e) {
                        // Ignore
                    }
                }
                if (installedAppWithPermission != null) {
                    return new DetectionResult(true, "App with mock location permission installed: " + installedAppWithPermission);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return new DetectionResult(false, null);
    }

    /**
     * Checks if the specific Location object came from a mock provider.
     */
    public static DetectionResult checkLocationMocked(Location location) {
        if (location == null) return new DetectionResult(false, "No location available to check");
        boolean isMocked = false;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            isMocked = location.isMock();
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            isMocked = location.isFromMockProvider();
        }
        return new DetectionResult(isMocked, isMocked ? "Location.isMock() or isFromMockProvider() returned true" : null);
    }

    /**
     * Checks if Location services are currently enabled.
     */
    public static boolean isLocationEnabled(Context context) {
        LocationManager locationManager = (LocationManager) context.getSystemService(Context.LOCATION_SERVICE);
        if (locationManager == null) return false;

        boolean isGpsEnabled = false;
        boolean isNetworkEnabled = false;

        try {
            isGpsEnabled = locationManager.isProviderEnabled(LocationManager.GPS_PROVIDER);
            isNetworkEnabled = locationManager.isProviderEnabled(LocationManager.NETWORK_PROVIDER);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return isGpsEnabled || isNetworkEnabled;
    }

    /**
     * Synchronously fetches the last known location.
     */
    public static Location getLastKnownLocationSynchronously(Context context) {
        LocationManager locationManager = (LocationManager) context.getSystemService(Context.LOCATION_SERVICE);
        if (locationManager == null) return null;

        if (ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_COARSE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            return null; // Permissions missing
        }

        Location bestLocation = null;
        try {
            List<String> providers = locationManager.getProviders(true);
            for (String provider : providers) {
                Location l = locationManager.getLastKnownLocation(provider);
                if (l == null) continue;
                if (bestLocation == null || l.getAccuracy() < bestLocation.getAccuracy()) {
                    bestLocation = l;
                }
            }
        } catch (SecurityException e) {
            e.printStackTrace();
        }
        return bestLocation;
    }

    /**
     * Synchronously fetches the IP-based location from a free API.
     * Note: Executing this on the main thread will cause a NetworkOnMainThreadException, 
     * but since DeviceFingerprintGenerator runs in the background (or should be wrapped), it is executed synchronously.
     */
    public static double[] getIpLocationSynchronously() {
        try {
            URL url = new URL("https://get.geojs.io/v1/ip/geo.json");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(3000);
            connection.setReadTimeout(3000);

            if (connection.getResponseCode() == 200) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();

                JSONObject json = new JSONObject(response.toString());
                double lat = json.optDouble("latitude", Double.NaN);
                double lon = json.optDouble("longitude", Double.NaN);
                if (!Double.isNaN(lat) && !Double.isNaN(lon)) {
                    return new double[]{lat, lon};
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Checks if the distance between the device's GPS location and IP-based location is > 100km.
     */
    public static DetectionResult checkIpDistanceSuspicious(Location deviceLocation, double[] ipLocation) {
        if (deviceLocation == null || ipLocation == null || ipLocation.length < 2) {
            return new DetectionResult(false, "Missing GPS or IP location data for comparison");
        }

        double distanceKm = calculateHaversineDistance(
                deviceLocation.getLatitude(), deviceLocation.getLongitude(),
                ipLocation[0], ipLocation[1]
        );

        boolean suspicious = distanceKm > 100.0;
        return new DetectionResult(suspicious, suspicious ? "IP distance > 100km (" + Math.round(distanceKm) + "km)" : null);
    }

    /**
     * Haversine formula to calculate distance between two coordinates in kilometers.
     */
    private static double calculateHaversineDistance(double lat1, double lon1, double lat2, double lon2) {
        final int R = 6371; // Earth radius in kilometers
        double latDistance = Math.toRadians(lat2 - lat1);
        double lonDistance = Math.toRadians(lon2 - lon1);
        double a = Math.sin(latDistance / 2) * Math.sin(latDistance / 2)
                + Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2))
                * Math.sin(lonDistance / 2) * Math.sin(lonDistance / 2);
        double c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        return R * c;
    }
}
