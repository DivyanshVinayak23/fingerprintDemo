package com.example.fingerprintdemo;

import org.json.JSONException;
import org.json.JSONObject;

public class DetectionResult {
    private final boolean detected;
    private final String reason;

    public DetectionResult(boolean detected, String reason) {
        this.detected = detected;
        this.reason = reason;
    }

    public boolean isDetected() {
        return detected;
    }

    public String getReason() {
        return reason;
    }

    public JSONObject toJson() {
        JSONObject json = new JSONObject();
        try {
            json.put("detected", detected);
            if (detected && reason != null && !reason.isEmpty()) {
                json.put("reason", reason);
            }
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return json;
    }
}
