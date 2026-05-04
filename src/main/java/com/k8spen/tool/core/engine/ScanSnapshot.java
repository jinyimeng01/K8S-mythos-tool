package com.k8spen.tool.core.engine;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.k8spen.tool.core.client.ApiResponse;
import com.k8spen.tool.core.model.ScanModule;

import java.util.LinkedHashMap;
import java.util.Map;

public class ScanSnapshot {

    private final Map<String, ApiResponse> responses = new LinkedHashMap<>();
    private final Map<String, JsonElement> json = new LinkedHashMap<>();
    private final Map<String, String> profile = new LinkedHashMap<>();

    public void put(String key, ApiResponse response) {
        responses.put(key, response);
        if (response != null && response.body() != null && !response.body().isBlank()) {
            try {
                json.put(key, JsonParser.parseString(response.body()));
            } catch (Exception ignored) {
                // Not every Kubernetes endpoint returns JSON when access is denied.
            }
        }
    }

    public ApiResponse response(String key) {
        return responses.get(key);
    }

    public JsonObject object(String key) {
        JsonElement element = json.get(key);
        return element != null && element.isJsonObject() ? element.getAsJsonObject() : new JsonObject();
    }

    public Map<String, String> profile() {
        return profile;
    }

    public void profile(String key, String value) {
        if (key != null && value != null && !value.isBlank()) {
            profile.put(key, value);
        }
    }

    public boolean hasModule(ScanModule module, java.util.Set<ScanModule> enabled) {
        return enabled.contains(module);
    }
}
