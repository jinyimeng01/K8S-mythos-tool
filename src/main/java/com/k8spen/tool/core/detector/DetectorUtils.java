package com.k8spen.tool.core.detector;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Locale;

final class DetectorUtils {
    private DetectorUtils() {}

    static JsonObject obj(JsonObject parent, String key) {
        if (parent == null || !parent.has(key) || !parent.get(key).isJsonObject()) return new JsonObject();
        return parent.getAsJsonObject(key);
    }

    static JsonArray arr(JsonObject parent, String key) {
        if (parent == null || !parent.has(key) || !parent.get(key).isJsonArray()) return new JsonArray();
        return parent.getAsJsonArray(key);
    }

    static JsonArray items(JsonObject root) {
        return arr(root, "items");
    }

    static String str(JsonObject parent, String key) {
        if (parent == null || !parent.has(key) || parent.get(key).isJsonNull()) return "";
        try {
            return parent.get(key).getAsString();
        } catch (Exception e) {
            return "";
        }
    }

    static boolean bool(JsonObject parent, String key) {
        if (parent == null || !parent.has(key) || parent.get(key).isJsonNull()) return false;
        try {
            return parent.get(key).getAsBoolean();
        } catch (Exception e) {
            return false;
        }
    }

    static String namespacedName(JsonObject item) {
        JsonObject meta = obj(item, "metadata");
        String ns = str(meta, "namespace");
        String name = str(meta, "name");
        return ns == null || ns.isBlank() ? name : ns + "/" + name;
    }

    static boolean containsAny(String value, String... needles) {
        if (value == null) return false;
        String lower = value.toLowerCase(Locale.ROOT);
        for (String needle : needles) {
            if (needle != null && lower.contains(needle.toLowerCase(Locale.ROOT))) return true;
        }
        return false;
    }

    static boolean arrayContains(JsonArray values, String expected) {
        if (values == null) return false;
        for (JsonElement e : values) {
            if (e != null && !e.isJsonNull() && expected.equals(e.getAsString())) return true;
        }
        return false;
    }

    static boolean arrayHasWildcardOr(JsonArray values, String expected) {
        return arrayContains(values, "*") || arrayContains(values, expected);
    }

    static String sha256Short(String value) {
        if (value == null || value.isEmpty()) return "";
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash).substring(0, 16);
        } catch (Exception e) {
            return "hash-error";
        }
    }

    static String join(JsonArray array) {
        StringBuilder sb = new StringBuilder();
        if (array == null) return "";
        for (JsonElement e : array) {
            if (sb.length() > 0) sb.append(", ");
            if (e != null && !e.isJsonNull()) sb.append(e.getAsString());
        }
        return sb.toString();
    }
}
