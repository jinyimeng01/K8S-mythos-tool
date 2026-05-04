package com.k8spen.tool.core.detector;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.k8spen.tool.core.engine.ScanSnapshot;
import com.k8spen.tool.core.model.Evidence;
import com.k8spen.tool.core.model.Finding;
import com.k8spen.tool.core.model.RiskLevel;
import com.k8spen.tool.core.model.ScanModule;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

final class CloudDetectorSupport {
    private CloudDetectorSupport() {}

    record CloudSignal(String resource, String field, String value) {}

    static boolean anyPodAnnotationContains(ScanSnapshot snapshot, String... needles) {
        return !podAnnotationSignals(snapshot, needles).isEmpty();
    }

    static boolean anyServiceAccountAnnotationContains(ScanSnapshot snapshot, String... needles) {
        return !serviceAccountAnnotationSignals(snapshot, needles).isEmpty();
    }

    static boolean anyNodeProviderContains(ScanSnapshot snapshot, String... needles) {
        for (JsonElement e : DetectorUtils.items(snapshot.object("nodes"))) {
            JsonObject spec = DetectorUtils.obj(e.getAsJsonObject(), "spec");
            JsonObject labels = DetectorUtils.obj(DetectorUtils.obj(e.getAsJsonObject(), "metadata"), "labels");
            if (DetectorUtils.containsAny(DetectorUtils.str(spec, "providerID"), needles)) return true;
            for (String key : labels.keySet()) {
                if (DetectorUtils.containsAny(key, needles) || DetectorUtils.containsAny(jsonValue(labels.get(key)), needles)) {
                    return true;
                }
            }
        }
        return false;
    }

    static Finding providerFinding(String id, RiskLevel risk, String title, String provider, String summary,
                                   String resource, String field, String value, String remediation) {
        return providerFinding(id, risk, title, provider, summary, resource, field, value, remediation,
                "cloud-identity-" + provider.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-"));
    }

    static Finding providerFinding(String id, RiskLevel risk, String title, String provider, String summary,
                                   String resource, String field, String value, String remediation, String category) {
        return Finding.builder(id, ScanModule.CLOUD_CONTEXT, risk, title)
                .summary(summary)
                .resource(resource)
                .category(category)
                .standard("Cloud workload identity and Kubernetes credential isolation")
                .remediation(remediation)
                .evidence(Evidence.of(provider, resource, field, value))
                .build();
    }

    static List<CloudSignal> serviceAccountAnnotationSignals(ScanSnapshot snapshot, String... needles) {
        List<CloudSignal> signals = new ArrayList<>();
        for (JsonElement e : DetectorUtils.items(snapshot.object("serviceAccounts"))) {
            JsonObject serviceAccount = e.getAsJsonObject();
            addAnnotationSignals(signals, DetectorUtils.namespacedName(serviceAccount), "metadata.annotations",
                    DetectorUtils.obj(DetectorUtils.obj(serviceAccount, "metadata"), "annotations"), needles);
        }
        return signals;
    }

    static List<CloudSignal> podAnnotationSignals(ScanSnapshot snapshot, String... needles) {
        List<CloudSignal> signals = new ArrayList<>();
        for (JsonElement e : DetectorUtils.items(snapshot.object("pods"))) {
            JsonObject pod = e.getAsJsonObject();
            addAnnotationSignals(signals, DetectorUtils.namespacedName(pod), "metadata.annotations",
                    DetectorUtils.obj(DetectorUtils.obj(pod, "metadata"), "annotations"), needles);
        }
        return signals;
    }

    static List<CloudSignal> podLabelSignals(ScanSnapshot snapshot, String... needles) {
        List<CloudSignal> signals = new ArrayList<>();
        for (JsonElement e : DetectorUtils.items(snapshot.object("pods"))) {
            JsonObject pod = e.getAsJsonObject();
            addAnnotationSignals(signals, DetectorUtils.namespacedName(pod), "metadata.labels",
                    DetectorUtils.obj(DetectorUtils.obj(pod, "metadata"), "labels"), needles);
        }
        return signals;
    }

    static List<CloudSignal> namespaceLabelSignals(ScanSnapshot snapshot, String... needles) {
        List<CloudSignal> signals = new ArrayList<>();
        for (JsonElement e : DetectorUtils.items(snapshot.object("namespaces"))) {
            JsonObject namespace = e.getAsJsonObject();
            String name = DetectorUtils.str(DetectorUtils.obj(namespace, "metadata"), "name");
            addAnnotationSignals(signals, name, "metadata.labels",
                    DetectorUtils.obj(DetectorUtils.obj(namespace, "metadata"), "labels"), needles);
        }
        return signals;
    }

    static List<CloudSignal> podEnvSignals(ScanSnapshot snapshot, String... namesOrPrefixes) {
        List<CloudSignal> signals = new ArrayList<>();
        for (JsonElement e : DetectorUtils.items(snapshot.object("pods"))) {
            JsonObject pod = e.getAsJsonObject();
            JsonObject spec = DetectorUtils.obj(pod, "spec");
            String podName = DetectorUtils.namespacedName(pod);
            addContainerEnvSignals(signals, podName, "containers", DetectorUtils.arr(spec, "containers"), namesOrPrefixes);
            addContainerEnvSignals(signals, podName, "initContainers", DetectorUtils.arr(spec, "initContainers"), namesOrPrefixes);
        }
        return signals;
    }

    static List<CloudSignal> projectedTokenVolumeSignals(ScanSnapshot snapshot, String... audienceNeedles) {
        List<CloudSignal> signals = new ArrayList<>();
        for (JsonElement e : DetectorUtils.items(snapshot.object("pods"))) {
            JsonObject pod = e.getAsJsonObject();
            String podName = DetectorUtils.namespacedName(pod);
            JsonArray volumes = DetectorUtils.arr(DetectorUtils.obj(pod, "spec"), "volumes");
            for (JsonElement volumeEl : volumes) {
                JsonObject volume = volumeEl.getAsJsonObject();
                String volumeName = DetectorUtils.str(volume, "name");
                JsonObject projected = DetectorUtils.obj(volume, "projected");
                for (JsonElement sourceEl : DetectorUtils.arr(projected, "sources")) {
                    JsonObject token = DetectorUtils.obj(sourceEl.getAsJsonObject(), "serviceAccountToken");
                    if (token.size() == 0) continue;
                    String audience = DetectorUtils.str(token, "audience");
                    String path = DetectorUtils.str(token, "path");
                    if (audienceNeedles.length == 0 || DetectorUtils.containsAny(audience, audienceNeedles)
                            || DetectorUtils.containsAny(path, audienceNeedles)) {
                        String field = "spec.volumes[" + volumeName + "].projected.serviceAccountToken";
                        String value = "audience=" + emptyToUnknown(audience) + ", path=" + emptyToUnknown(path);
                        signals.add(new CloudSignal(podName, field, value));
                    }
                }
            }
        }
        return signals;
    }

    static List<CloudSignal> hostNetworkPodSignals(ScanSnapshot snapshot) {
        List<CloudSignal> signals = new ArrayList<>();
        JsonArray pods = DetectorUtils.items(snapshot.object("pods"));
        for (JsonElement e : pods) {
            JsonObject pod = e.getAsJsonObject();
            if (DetectorUtils.bool(DetectorUtils.obj(pod, "spec"), "hostNetwork")) {
                signals.add(new CloudSignal(DetectorUtils.namespacedName(pod), "spec.hostNetwork", "true"));
            }
        }
        return signals;
    }

    static List<CloudSignal> defaultServiceAccountCloudSignals(ScanSnapshot snapshot, String... annotationNeedles) {
        List<CloudSignal> signals = new ArrayList<>();
        for (CloudSignal signal : serviceAccountAnnotationSignals(snapshot, annotationNeedles)) {
            if (signal.resource().endsWith("/default") || "default".equals(signal.resource())) {
                signals.add(signal);
            }
        }
        return signals;
    }

    static int hostNetworkPodCount(ScanSnapshot snapshot) {
        return hostNetworkPodSignals(snapshot).size();
    }

    static String compactSignals(List<CloudSignal> signals, int max) {
        StringBuilder sb = new StringBuilder();
        int limit = Math.min(max, signals.size());
        for (int i = 0; i < limit; i++) {
            CloudSignal signal = signals.get(i);
            if (sb.length() > 0) sb.append("; ");
            sb.append(signal.resource()).append(" ").append(signal.field()).append("=").append(signal.value());
        }
        if (signals.size() > limit) sb.append("; +").append(signals.size() - limit).append(" more");
        return sb.toString();
    }

    private static void addAnnotationSignals(List<CloudSignal> signals, String resource, String fieldPrefix,
                                             JsonObject values, String... needles) {
        for (String key : values.keySet()) {
            String value = jsonValue(values.get(key));
            if (matches(key, value, needles)) {
                signals.add(new CloudSignal(resource, fieldPrefix + "." + key, value));
            }
        }
    }

    private static void addContainerEnvSignals(List<CloudSignal> signals, String podName, String containerField,
                                               JsonArray containers, String... namesOrPrefixes) {
        for (JsonElement containerEl : containers) {
            JsonObject container = containerEl.getAsJsonObject();
            String containerName = DetectorUtils.str(container, "name");
            for (JsonElement envEl : DetectorUtils.arr(container, "env")) {
                JsonObject env = envEl.getAsJsonObject();
                String envName = DetectorUtils.str(env, "name");
                if (!matchesName(envName, namesOrPrefixes)) continue;
                String field = "spec." + containerField + "[" + containerName + "].env." + envName;
                signals.add(new CloudSignal(podName + "/" + containerName, field, envEvidenceValue(envName, env)));
            }
        }
    }

    private static boolean matches(String key, String value, String... needles) {
        if (needles == null || needles.length == 0) return true;
        return DetectorUtils.containsAny(key, needles) || DetectorUtils.containsAny(value, needles);
    }

    private static boolean matchesName(String name, String... namesOrPrefixes) {
        if (name == null || name.isBlank()) return false;
        if (namesOrPrefixes == null || namesOrPrefixes.length == 0) return true;
        String lower = name.toLowerCase(Locale.ROOT);
        for (String item : namesOrPrefixes) {
            if (item != null && lower.startsWith(item.toLowerCase(Locale.ROOT))) return true;
        }
        return false;
    }

    private static String envEvidenceValue(String envName, JsonObject env) {
        if (env.has("valueFrom")) return valueFromSummary(DetectorUtils.obj(env, "valueFrom"));
        return DetectorUtils.str(env, "value");
    }

    private static String valueFromSummary(JsonObject valueFrom) {
        JsonObject secret = DetectorUtils.obj(valueFrom, "secretKeyRef");
        if (secret.size() > 0) {
            return "valueFrom.secretKeyRef:" + DetectorUtils.str(secret, "name") + "/" + DetectorUtils.str(secret, "key");
        }
        JsonObject configMap = DetectorUtils.obj(valueFrom, "configMapKeyRef");
        if (configMap.size() > 0) {
            return "valueFrom.configMapKeyRef:" + DetectorUtils.str(configMap, "name") + "/" + DetectorUtils.str(configMap, "key");
        }
        JsonObject field = DetectorUtils.obj(valueFrom, "fieldRef");
        if (field.size() > 0) return "valueFrom.fieldRef:" + DetectorUtils.str(field, "fieldPath");
        JsonObject resource = DetectorUtils.obj(valueFrom, "resourceFieldRef");
        if (resource.size() > 0) return "valueFrom.resourceFieldRef:" + DetectorUtils.str(resource, "resource");
        return "valueFrom";
    }

    private static String jsonValue(JsonElement element) {
        if (element == null || element.isJsonNull()) return "";
        try {
            return element.getAsString();
        } catch (Exception e) {
            return element.toString();
        }
    }

    private static String emptyToUnknown(String value) {
        return value == null || value.isBlank() ? "(unknown)" : value;
    }
}
