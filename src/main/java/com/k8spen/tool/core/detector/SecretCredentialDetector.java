package com.k8spen.tool.core.detector;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.k8spen.tool.core.engine.ScanSnapshot;
import com.k8spen.tool.core.model.Evidence;
import com.k8spen.tool.core.model.Finding;
import com.k8spen.tool.core.model.RiskLevel;
import com.k8spen.tool.core.model.ScanModule;
import com.k8spen.tool.core.model.ScanRequest;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;

public class SecretCredentialDetector implements ScanDetector {
    private static final Set<String> HIGH_VALUE_KEYS = Set.of(
            "token", "password", "passwd", "secret", "client-secret", "client_secret",
            "access-key", "access_key", "aws_access_key_id", "aws_secret_access_key",
            "kubeconfig", "config", "id_rsa", "ssh-privatekey", "tls.key", "ca.crt");

    @Override
    public List<Finding> detect(ScanRequest request, ScanSnapshot snapshot) {
        List<Finding> findings = new ArrayList<>();
        JsonArray items = DetectorUtils.items(snapshot.object("secrets"));
        for (JsonElement e : items) {
            JsonObject secret = e.getAsJsonObject();
            String resource = DetectorUtils.namespacedName(secret);
            String type = DetectorUtils.str(secret, "type");
            JsonObject data = DetectorUtils.obj(secret, "data");
            JsonObject stringData = DetectorUtils.obj(secret, "stringData");
            List<String> keys = new ArrayList<>(data.keySet());
            for (String key : stringData.keySet()) {
                if (!keys.contains(key)) keys.add(key);
            }

            RiskLevel level = levelFor(type, keys);
            if (level == RiskLevel.INFO && keys.isEmpty()) continue;
            String title = titleFor(type, keys);
            Finding.Builder builder = Finding.builder("secret.exposure." + safe(resource), ScanModule.SECRET_CREDENTIAL,
                            level, title)
                    .summary("Secret " + resource + " contains credential-like data keys. Full Evidence mode includes raw values in exported reports.")
                    .resource(resource)
                    .category("secret-exposure")
                    .standard("OWASP Kubernetes Top 10: Secrets Management")
                    .remediation("Reduce Secret access, rotate exposed credentials if needed, and prefer workload identity or short-lived credentials.")
                    .evidence(Evidence.of("secrets", resource, "type", type))
                    .evidence(Evidence.of("secrets", resource, "data.keys", String.join(", ", keys)));
            addFullEvidence(builder, "data", data, resource, true);
            addFullEvidence(builder, "stringData", stringData, resource, false);
            findings.add(builder.build());
        }
        return findings;
    }

    private static RiskLevel levelFor(String type, List<String> keys) {
        if (type == null) type = "";
        if (type.contains("service-account-token") || type.contains("dockerconfigjson") || type.contains("ssh-auth")) {
            return RiskLevel.HIGH;
        }
        if (type.contains("tls") || keys.stream().anyMatch(SecretCredentialDetector::isHighValueKey)) {
            return RiskLevel.MEDIUM;
        }
        return keys.isEmpty() ? RiskLevel.INFO : RiskLevel.LOW;
    }

    private static String titleFor(String type, List<String> keys) {
        if (type != null && type.contains("service-account-token")) return "ServiceAccount token Secret is visible";
        if (type != null && type.contains("dockerconfigjson")) return "Container registry credential Secret is visible";
        if (type != null && type.contains("tls")) return "TLS material Secret is visible";
        if (type != null && type.contains("ssh-auth")) return "SSH credential Secret is visible";
        if (keys.stream().anyMatch(SecretCredentialDetector::isHighValueKey)) return "Opaque Secret contains high-value key names";
        return "Secret metadata is visible";
    }

    public static boolean isHighValueKey(String key) {
        if (key == null) return false;
        String lower = key.toLowerCase();
        return HIGH_VALUE_KEYS.contains(lower) || DetectorUtils.containsAny(lower, "token", "password", "secret", "private", "access_key", "kubeconfig");
    }

    public static String redactedValue(String value) {
        if (value == null || value.isEmpty()) return "(empty)";
        return "redacted:sha256:" + DetectorUtils.sha256Short(value);
    }

    private static void addFullEvidence(Finding.Builder builder, String section, JsonObject data,
                                        String resource, boolean decodeBase64) {
        for (String key : data.keySet()) {
            String value = data.get(key).isJsonNull() ? "" : data.get(key).getAsString();
            builder.evidence(Evidence.of("secrets", resource, section + "." + key, value));
            if (decodeBase64) {
                String decoded = decodeBase64Text(value);
                if (!decoded.isBlank()) {
                    builder.evidence(Evidence.of("secrets", resource, section + "." + key + ".decoded", decoded));
                }
            }
        }
    }

    private static String decodeBase64Text(String value) {
        if (value == null || value.isBlank()) return "";
        try {
            byte[] decoded = Base64.getDecoder().decode(value);
            if (!isLikelyText(decoded)) return "(binary data, " + decoded.length + " bytes)";
            return new String(decoded, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return "";
        }
    }

    private static boolean isLikelyText(byte[] data) {
        if (data.length == 0) return true;
        int printable = 0;
        for (byte b : data) {
            int c = b & 0xff;
            if (c == 9 || c == 10 || c == 13 || (c >= 32 && c < 127)) printable++;
        }
        return printable >= Math.max(1, data.length * 0.85);
    }

    private static String safe(String value) {
        return value == null ? "unknown" : value.replaceAll("[^A-Za-z0-9_.-]", ".");
    }
}
