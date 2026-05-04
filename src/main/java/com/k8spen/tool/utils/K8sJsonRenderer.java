package com.k8spen.tool.utils;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class K8sJsonRenderer {

    private static final Logger LOGGER = LoggerFactory.getLogger(K8sJsonRenderer.class);
    private static final Gson PRETTY = new GsonBuilder().setPrettyPrinting().create();

    public static String render(String raw) {
        if (raw == null || raw.isEmpty()) return raw;
        String trimmed = raw.trim();

        String prefix = "";
        String json = trimmed;
        if (trimmed.startsWith("[HTTP")) {
            int nl = trimmed.indexOf('\n');
            if (nl > 0) {
                prefix = trimmed.substring(0, nl + 1);
                json = trimmed.substring(nl + 1).trim();
            }
        }

        if (!((json.startsWith("{") && json.endsWith("}")) || (json.startsWith("[") && json.endsWith("]")))) {
            return raw;
        }

        try {
            JsonElement el = JsonParser.parseString(json);
            if (!el.isJsonObject()) return prefix + PRETTY.toJson(el);

            JsonObject root = el.getAsJsonObject();
            String kind = str(root, "kind");

            if (kind.isEmpty()) return prefix + PRETTY.toJson(root);

            StringBuilder sb = new StringBuilder();
            sb.append(prefix);

            switch (kind) {
                case "PodList":        sb.append(renderPodList(root)); break;
                case "NodeList":       sb.append(renderNodeList(root)); break;
                case "ServiceList":    sb.append(renderServiceList(root)); break;
                case "SecretList":     sb.append(renderSecretList(root)); break;
                case "DeploymentList": sb.append(renderDeploymentList(root)); break;
                case "NamespaceList":  sb.append(renderNamespaceList(root)); break;
                case "ServiceAccountList": sb.append(renderSAList(root)); break;
                case "ClusterRoleBindingList": sb.append(renderCRBList(root)); break;
                case "SelfSubjectRulesReview": sb.append(renderRulesReview(root)); break;
                case "Status":         sb.append(renderStatus(root)); break;
                default:
                    if (kind.endsWith("List") && root.has("items")) {
                        sb.append(renderGenericList(root));
                    } else {
                        sb.append(renderSingleResource(root));
                    }
                    break;
            }

            return sb.toString();
        } catch (Exception e) {
            LOGGER.error("Failed to render JSON", e);
            return raw;
        }
    }

    // ===== PodList =====
    private static String renderPodList(JsonObject root) {
        JsonArray items = arr(root, "items");
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("===== Pod List (Total: %d) =====\n\n", items.size()));
        sb.append(String.format("%-40s %-16s %-10s %-16s %-18s %s\n",
                "Name", "Namespace", "Status", "Node", "PodIP", "Image"));
        sb.append(repeat("-", 140)).append("\n");

        for (JsonElement e : items) {
            JsonObject pod = e.getAsJsonObject();
            JsonObject meta = obj(pod, "metadata");
            JsonObject spec = obj(pod, "spec");
            JsonObject status = obj(pod, "status");

            String name = str(meta, "name");
            String ns = str(meta, "namespace");
            String phase = str(status, "phase");
            String node = str(spec, "nodeName");
            String podIp = str(status, "podIP");

            JsonArray containers = arr(spec, "containers");

            // Status marker
            String statusIcon = "Running".equals(phase) ? "[✓]" : "Pending".equals(phase) ? "[~]" : "[✗]";

            sb.append(String.format("%-40s %-16s %-10s %-16s %-18s\n",
                    name, ns, statusIcon + phase, node, podIp));

            // Container list
            for (JsonElement c : containers) {
                JsonObject co = c.getAsJsonObject();
                String cName = str(co, "name");
                String cImage = str(co, "image");
                sb.append(String.format("  Container: %-25s Image: %s\n", cName, cImage));
            }

            // Mount info (security concern)
            JsonArray volumes = arr(spec, "volumes");
            for (JsonElement v : volumes) {
                JsonObject vol = v.getAsJsonObject();
                if (vol.has("hostPath")) {
                    String hp = str(obj(vol, "hostPath"), "path");
                    String vn = str(vol, "name");
                    sb.append(String.format("  ⚠ hostPath mount: %s -> %s\n", vn, hp));
                }
            }

            // Privileged container detection
            for (JsonElement c : containers) {
                JsonObject co = c.getAsJsonObject();
                JsonObject sc = obj(co, "securityContext");
                if (sc.has("privileged") && sc.get("privileged").getAsBoolean()) {
                    sb.append(String.format("  ⚠ Privileged container: %s\n", str(co, "name")));
                }
            }
        }
        return sb.toString();
    }

    // ===== NodeList =====
    private static String renderNodeList(JsonObject root) {
        JsonArray items = arr(root, "items");
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("===== Node List (Total: %d) =====\n\n", items.size()));
        sb.append(String.format("%-20s %-14s %-18s %-16s %-14s %s\n",
                "Name", "Role", "InternalIP", "OS", "Kernel Version", "Container Runtime"));
        sb.append(repeat("-", 120)).append("\n");

        for (JsonElement e : items) {
            JsonObject node = e.getAsJsonObject();
            JsonObject meta = obj(node, "metadata");
            JsonObject status = obj(node, "status");
            JsonObject nodeInfo = obj(status, "nodeInfo");

            String name = str(meta, "name");

            // Role
            JsonObject labels = obj(meta, "labels");
            String role = "worker";
            if (labels.has("node-role.kubernetes.io/master") || labels.has("node-role.kubernetes.io/control-plane")) {
                role = "master";
            }

            // Ready status
            String ready = "Unknown";
            JsonArray conditions = arr(status, "conditions");
            for (JsonElement c : conditions) {
                JsonObject cond = c.getAsJsonObject();
                if ("Ready".equals(str(cond, "type"))) {
                    ready = "True".equals(str(cond, "status")) ? "Ready" : "NotReady";
                }
            }

            // Internal IP
            String ip = "";
            JsonArray addresses = arr(status, "addresses");
            for (JsonElement a : addresses) {
                JsonObject addr = a.getAsJsonObject();
                if ("InternalIP".equals(str(addr, "type"))) {
                    ip = str(addr, "address");
                }
            }

            String os = str(nodeInfo, "osImage");
            String kernel = str(nodeInfo, "kernelVersion");
            String runtime = str(nodeInfo, "containerRuntimeVersion");

            sb.append(String.format("%-20s %-14s %-18s %s\n",
                    name, role + "/" + ready, ip, os));
            sb.append(String.format("%-20s %-14s %-18s %s\n",
                    "", "", "kernel: " + kernel, "runtime: " + runtime));
        }
        return sb.toString();
    }

    // ===== ServiceList =====
    private static String renderServiceList(JsonObject root) {
        JsonArray items = arr(root, "items");
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("===== Service List (Total: %d) =====\n\n", items.size()));
        sb.append(String.format("%-30s %-16s %-12s %-18s %s\n",
                "Name", "Namespace", "Type", "ClusterIP", "Ports"));
        sb.append(repeat("-", 110)).append("\n");

        for (JsonElement e : items) {
            JsonObject svc = e.getAsJsonObject();
            JsonObject meta = obj(svc, "metadata");
            JsonObject spec = obj(svc, "spec");

            String name = str(meta, "name");
            String ns = str(meta, "namespace");
            String type = str(spec, "type");
            String clusterIp = str(spec, "clusterIP");

            StringBuilder ports = new StringBuilder();
            JsonArray portArr = arr(spec, "ports");
            for (JsonElement p : portArr) {
                JsonObject po = p.getAsJsonObject();
                if (ports.length() > 0) ports.append(", ");
                ports.append(intVal(po, "port")).append("/").append(str(po, "protocol"));
                if (po.has("nodePort")) ports.append("->").append(intVal(po, "nodePort"));
            }

            sb.append(String.format("%-30s %-16s %-12s %-18s %s\n",
                    trunc(name, 28), trunc(ns, 14), type, clusterIp, ports));
        }
        return sb.toString();
    }

    // ===== SecretList =====
    private static String renderSecretList(JsonObject root) {
        JsonArray items = arr(root, "items");
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("===== Secret List (Total: %d) =====\n\n", items.size()));

        for (int i = 0; i < items.size(); i++) {
            JsonObject secret = items.get(i).getAsJsonObject();
            JsonObject meta = obj(secret, "metadata");

            String name = str(meta, "name");
            String ns = str(meta, "namespace");
            String type = str(secret, "type");

            sb.append(String.format("[%d] %s\n", i + 1, name));
            sb.append("    Namespace: ").append(ns).append("\n");
            sb.append("    Type: ").append(type).append("\n");

            JsonObject data = obj(secret, "data");
            if (data.size() > 0) {
                sb.append("    Data:\n");
                for (String k : data.keySet()) {
                    String val = data.get(k).getAsString();
                    sb.append("      ").append(k).append(": ").append(val).append("\n");
                }
            }

            // SA Token decode hint
            if (type.contains("service-account-token") && data.has("token")) {
                sb.append("    🔑 This Secret contains a ServiceAccount Token, can be base64 decoded and used as a Bearer Token\n");
            }
            sb.append("\n");
        }
        return sb.toString();
    }

    // ===== DeploymentList =====
    private static String renderDeploymentList(JsonObject root) {
        JsonArray items = arr(root, "items");
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("===== Deployment List (Total: %d) =====\n\n", items.size()));
        sb.append(String.format("%-30s %-16s %-10s %-10s %s\n",
                "Name", "Namespace", "Desired", "Ready", "Image"));
        sb.append(repeat("-", 110)).append("\n");

        for (JsonElement e : items) {
            JsonObject dep = e.getAsJsonObject();
            JsonObject meta = obj(dep, "metadata");
            JsonObject spec = obj(dep, "spec");
            JsonObject status = obj(dep, "status");

            String name = str(meta, "name");
            String ns = str(meta, "namespace");
            int replicas = intVal(spec, "replicas");
            int ready = intVal(status, "readyReplicas");

            String image = "";
            JsonObject template = obj(spec, "template");
            JsonObject tSpec = obj(template, "spec");
            JsonArray containers = arr(tSpec, "containers");
            if (containers.size() > 0) {
                image = str(containers.get(0).getAsJsonObject(), "image");
            }

            sb.append(String.format("%-30s %-16s %-10d %-10d %s\n",
                    trunc(name, 28), trunc(ns, 14), replicas, ready, trunc(image, 50)));
        }
        return sb.toString();
    }

    // ===== NamespaceList =====
    private static String renderNamespaceList(JsonObject root) {
        JsonArray items = arr(root, "items");
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("===== Namespace List (Total: %d) =====\n\n", items.size()));
        sb.append(String.format("%-30s %-12s %s\n", "Name", "Status", "Creation Time"));
        sb.append(repeat("-", 80)).append("\n");

        for (JsonElement e : items) {
            JsonObject ns = e.getAsJsonObject();
            JsonObject meta = obj(ns, "metadata");
            JsonObject status = obj(ns, "status");
            sb.append(String.format("%-30s %-12s %s\n",
                    str(meta, "name"), str(status, "phase"), str(meta, "creationTimestamp")));
        }
        return sb.toString();
    }

    // ===== ServiceAccountList =====
    private static String renderSAList(JsonObject root) {
        JsonArray items = arr(root, "items");
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("===== ServiceAccount List (Total: %d) =====\n\n", items.size()));
        sb.append(String.format("%-30s %-16s %s\n", "Name", "Namespace", "Related Secrets"));
        sb.append(repeat("-", 90)).append("\n");

        for (JsonElement e : items) {
            JsonObject sa = e.getAsJsonObject();
            JsonObject meta = obj(sa, "metadata");
            StringBuilder secrets = new StringBuilder();
            JsonArray sArr = arr(sa, "secrets");
            for (JsonElement s : sArr) {
                if (secrets.length() > 0) secrets.append(", ");
                secrets.append(str(s.getAsJsonObject(), "name"));
            }
            sb.append(String.format("%-30s %-16s %s\n",
                    str(meta, "name"), str(meta, "namespace"), secrets));
        }
        return sb.toString();
    }

    // ===== ClusterRoleBindingList =====
    private static String renderCRBList(JsonObject root) {
        JsonArray items = arr(root, "items");
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("===== ClusterRoleBinding List (Total: %d) =====\n\n", items.size()));
        sb.append(String.format("%-40s %-25s %s\n", "Name", "Role", "Subjects"));
        sb.append(repeat("-", 120)).append("\n");

        for (JsonElement e : items) {
            JsonObject crb = e.getAsJsonObject();
            JsonObject meta = obj(crb, "metadata");
            JsonObject roleRef = obj(crb, "roleRef");

            String name = str(meta, "name");
            String role = str(roleRef, "kind") + "/" + str(roleRef, "name");

            StringBuilder subjects = new StringBuilder();
            JsonArray subArr = arr(crb, "subjects");
            for (JsonElement s : subArr) {
                JsonObject sub = s.getAsJsonObject();
                if (subjects.length() > 0) subjects.append(", ");
                String subKind = str(sub, "kind");
                String subName = str(sub, "name");
                String subNs = str(sub, "namespace");
                subjects.append(subKind).append(":").append(subName);
                if (!subNs.isEmpty()) subjects.append("(").append(subNs).append(")");
            }

            sb.append(String.format("%-40s %-25s %s\n",
                    name, role, subjects.toString()));

            // Highlight high-risk binding
            if ("cluster-admin".equals(str(roleRef, "name"))) {
                sb.append("  ⚠ Binds to high-privilege cluster-admin role!\n");
            }
        }
        return sb.toString();
    }

    // ===== SelfSubjectRulesReview =====
    private static String renderRulesReview(JsonObject root) {
        JsonObject status = obj(root, "status");
        StringBuilder sb = new StringBuilder();

        // Risk assessment
        JsonArray resourceRules = arr(status, "resourceRules");
        JsonArray nonResourceRules = arr(status, "nonResourceRules");
        boolean isAdmin = false;
        boolean canCreatePods = false;
        boolean canGetSecrets = false;
        boolean canExecPods = false;

        for (JsonElement e : resourceRules) {
            JsonObject rule = e.getAsJsonObject();
            String verbs = joinArr(arr(rule, "verbs"));
            String resources = joinArr(arr(rule, "resources"));
            if (verbs.contains("*") && resources.contains("*")) isAdmin = true;
            if ((verbs.contains("create") || verbs.contains("*")) &&
                (resources.contains("pods") || resources.contains("*"))) canCreatePods = true;
            if ((verbs.contains("get") || verbs.contains("list") || verbs.contains("*")) &&
                (resources.contains("secrets") || resources.contains("*"))) canGetSecrets = true;
            if ((verbs.contains("create") || verbs.contains("*")) &&
                (resources.contains("pods/exec") || resources.contains("*"))) canExecPods = true;
        }

        sb.append("╔══════════════════════════════════════════════════════╗\n");
        sb.append("║           Current Service Account Permission Analysis Report                   ║\n");
        sb.append("╚══════════════════════════════════════════════════════╝\n\n");

        // Risk level
        sb.append("[Permission Risk Level]: ");
        if (isAdmin) {
            sb.append("⚠⚠⚠ Critical - Cluster admin privileges (full cluster control)\n");
        } else if (canCreatePods && canGetSecrets) {
            sb.append("⚠⚠ High - Can create Pods + read Secrets (escape / lateral movement)\n");
        } else if (canCreatePods || canGetSecrets || canExecPods) {
            sb.append("⚠ Medium - Sensitive permissions present\n");
        } else {
            sb.append("Low - Basic permissions only\n");
        }
        sb.append("\n");

        // Key capability quick check
        sb.append("[Key Capability Quick Check]\n");
        sb.append("  Create Pod:       ").append(canCreatePods ? "✓ Yes (can deploy backdoor Pod)" : "✗ No").append("\n");
        sb.append("  Read Secrets:   ").append(canGetSecrets ? "✓ Yes (can steal other SA Tokens)" : "✗ No").append("\n");
        sb.append("  Exec Pod Command:   ").append(canExecPods ? "✓ Yes (can enter container shell)" : "✗ No").append("\n");
        sb.append("  Cluster Admin:    ").append(isAdmin ? "✓ Yes (full control)" : "✗ No").append("\n");
        sb.append("\n");

        // Exploitation suggestions
        sb.append("[Exploitation Suggestions]\n");
        if (isAdmin) {
            sb.append("  1. Use kubectl to operate the cluster directly (token has full privileges)\n");
            sb.append("  2. Create backdoor Pod mounting host root directory to escape\n");
            sb.append("  3. Read Secrets from all namespaces to obtain more credentials\n");
            sb.append("  4. Deploy DaemonSet for cluster-wide persistence\n");
        } else if (canCreatePods) {
            sb.append("  1. Create privileged Pod mounting host directory to escape to Node\n");
            sb.append("  2. Read high-privilege SA Token from Pod to escalate privileges\n");
        } else if (canGetSecrets) {
            sb.append("  1. Read SA Tokens from Secrets to find high-privilege accounts\n");
            sb.append("  2. Search for kubeconfig/TLS certificates and other sensitive data\n");
        } else if (canExecPods) {
            sb.append("  1. Enter existing Pod to execute commands\n");
            sb.append("  2. Read SA Token inside Pod to attempt privilege escalation\n");
        } else {
            sb.append("  1. Current permissions are limited, try other attack surfaces\n");
            sb.append("  2. Try anonymous access (clear Token and retry)\n");
        }
        sb.append("\n");

        // Detailed resource permission table
        if (resourceRules.size() > 0) {
            sb.append(repeat("=", 80)).append("\n");
            sb.append("[Resource Operation Permission Details]\n\n");

            int idx = 1;
            for (JsonElement e : resourceRules) {
                JsonObject rule = e.getAsJsonObject();
                JsonArray verbs = arr(rule, "verbs");
                JsonArray groups = arr(rule, "apiGroups");
                JsonArray resources = arr(rule, "resources");

                sb.append(String.format("  Rule %d:\n", idx++));
                sb.append("    Operations (verbs):    ");
                for (int i = 0; i < verbs.size(); i++) {
                    String v = verbs.get(i).getAsString();
                    if (i > 0) sb.append(", ");
                    // Highlight dangerous operations
                    if ("*".equals(v) || "create".equals(v) || "delete".equals(v)) {
                        sb.append("[!").append(v).append("]");
                    } else {
                        sb.append(v);
                    }
                }
                sb.append("\n");

                sb.append("    API Groups (groups):  ");
                if (groups.size() == 0) {
                    sb.append("(empty = core API)");
                } else {
                    for (int i = 0; i < groups.size(); i++) {
                        if (i > 0) sb.append(", ");
                        String g = groups.get(i).getAsString();
                        sb.append(g.isEmpty() ? "core" : g);
                    }
                }
                sb.append("\n");

                sb.append("    Resources (resources): ");
                for (int i = 0; i < resources.size(); i++) {
                    if (i > 0) sb.append(", ");
                    String r = resources.get(i).getAsString();
                    // Highlight sensitive resources
                    if ("secrets".equals(r) || "pods".equals(r) || "pods/exec".equals(r) || "*".equals(r)) {
                        sb.append("[!").append(r).append("]");
                    } else {
                        sb.append(r);
                    }
                }
                sb.append("\n\n");
            }
        }

        // Non-resource URL permissions
        if (nonResourceRules.size() > 0) {
            sb.append(repeat("=", 80)).append("\n");
            sb.append("[Accessible Non-Resource URLs]\n\n");

            for (JsonElement e : nonResourceRules) {
                JsonObject rule = e.getAsJsonObject();
                String verbs = joinArr(arr(rule, "verbs"));
                JsonArray urls = arr(rule, "nonResourceURLs");

                sb.append("  [").append(verbs.toUpperCase()).append("] ");
                for (int i = 0; i < urls.size(); i++) {
                    if (i > 0) sb.append(", ");
                    sb.append(urls.get(i).getAsString());
                }
                sb.append("\n");
            }
        }

        return sb.toString();
    }

    // ===== Status (error) =====
    private static String renderStatus(JsonObject root) {
        StringBuilder sb = new StringBuilder();
        String status = str(root, "status");
        int code = intVal(root, "code");
        String message = str(root, "message");
        String reason = str(root, "reason");

        if ("Failure".equals(status)) {
            sb.append(String.format("===== Request Failed [%d %s] =====\n\n", code, reason));
            sb.append("Error Message: ").append(message).append("\n");
        } else {
            sb.append(PRETTY.toJson(root));
        }
        return sb.toString();
    }

    // ===== Generic List =====
    private static String renderGenericList(JsonObject root) {
        String kind = str(root, "kind");
        JsonArray items = arr(root, "items");
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("===== %s (Total: %d items) =====\n\n", kind, items.size()));

        for (int i = 0; i < items.size(); i++) {
            JsonObject item = items.get(i).getAsJsonObject();
            JsonObject meta = obj(item, "metadata");
            sb.append(String.format("[%d] %s/%s\n", i + 1, str(meta, "namespace"), str(meta, "name")));
        }
        sb.append("\n").append(PRETTY.toJson(root));
        return sb.toString();
    }

    // ===== Single Resource =====
    private static String renderSingleResource(JsonObject root) {
        String kind = str(root, "kind");
        JsonObject meta = obj(root, "metadata");
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("===== %s: %s =====\n", kind, str(meta, "name")));
        if (!str(meta, "namespace").isEmpty()) sb.append("Namespace: ").append(str(meta, "namespace")).append("\n");
        sb.append("Creation Time: ").append(str(meta, "creationTimestamp")).append("\n\n");
        sb.append(PRETTY.toJson(root));
        return sb.toString();
    }

    // ===== Helper methods =====
    private static String str(JsonObject o, String key) {
        if (o == null || !o.has(key) || o.get(key).isJsonNull()) return "";
        return o.get(key).getAsString();
    }

    private static int intVal(JsonObject o, String key) {
        if (o == null || !o.has(key) || o.get(key).isJsonNull()) return 0;
        try { return o.get(key).getAsInt(); } catch (Exception e) { return 0; }
    }

    private static JsonObject obj(JsonObject o, String key) {
        if (o == null || !o.has(key) || !o.get(key).isJsonObject()) return new JsonObject();
        return o.get(key).getAsJsonObject();
    }

    private static JsonArray arr(JsonObject o, String key) {
        if (o == null || !o.has(key) || !o.get(key).isJsonArray()) return new JsonArray();
        return o.get(key).getAsJsonArray();
    }

    private static String joinArr(JsonArray a) {
        StringBuilder sb = new StringBuilder();
        for (JsonElement e : a) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(e.getAsString());
        }
        return sb.toString();
    }

    private static String trunc(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max - 2) + "..";
    }

    private static String repeat(String s, int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) sb.append(s);
        return sb.toString();
    }
}
