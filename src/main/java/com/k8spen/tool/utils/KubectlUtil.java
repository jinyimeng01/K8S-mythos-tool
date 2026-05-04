package com.k8spen.tool.utils;

import java.io.*;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class KubectlUtil {

    private static Path kubectlPath;
    private static boolean initialized = false;

    public static synchronized void init() throws IOException {
        if (initialized && kubectlPath != null && Files.exists(kubectlPath)) {
            return;
        }
        Path tempDir = Files.createTempDirectory("k8spen_kubectl");
        kubectlPath = tempDir.resolve("kubectl.exe");
        try (InputStream is = KubectlUtil.class.getResourceAsStream("/kubectl.exe")) {
            if (is == null) {
                throw new IOException("kubectl.exe not found in resources");
            }
            Files.copy(is, kubectlPath, StandardCopyOption.REPLACE_EXISTING);
        }
        kubectlPath.toFile().setExecutable(true);
        kubectlPath.toFile().deleteOnExit();
        tempDir.toFile().deleteOnExit();
        initialized = true;
    }

    public static String getPath() {
        return kubectlPath != null ? kubectlPath.toString() : "kubectl";
    }

    public static String exec(String server, String token, boolean skipTls, int timeoutSec, String... args) throws IOException {
        return exec(server, token, null, null, skipTls, timeoutSec, args);
    }

    public static String exec(String server, String token, String username, String password, boolean skipTls, int timeoutSec, String... args) throws IOException {
        init();
        List<String> cmd = new ArrayList<>();
        cmd.add(kubectlPath.toString());
        if (server != null && !server.isEmpty()) {
            cmd.add("--server=" + server);
        }
        if (token != null && !token.isEmpty()) {
            cmd.add("--token=" + token);
        } else if (username != null && !username.isEmpty()) {
            cmd.add("--username=" + username);
            cmd.add("--password=" + (password != null ? password : ""));
        }
        if (skipTls) {
            cmd.add("--insecure-skip-tls-verify=true");
        }
        for (String arg : args) {
            cmd.add(arg);
        }
        return runProcess(cmd, timeoutSec);
    }

    public static String execWithKubeconfig(String kubeconfigPath, int timeoutSec, String... args) throws IOException {
        init();
        List<String> cmd = new ArrayList<>();
        cmd.add(kubectlPath.toString());
        if (kubeconfigPath != null && !kubeconfigPath.isEmpty()) {
            cmd.add("--kubeconfig=" + kubeconfigPath);
        }
        for (String arg : args) {
            cmd.add(arg);
        }
        return runProcess(cmd, timeoutSec);
    }

    public static String execRaw(int timeoutSec, String... args) throws IOException {
        init();
        List<String> cmd = new ArrayList<>();
        cmd.add(kubectlPath.toString());
        boolean hasAuth = false;
        for (String arg : args) {
            cmd.add(arg);
            if (arg.startsWith("--token=") || arg.startsWith("--username=") || arg.startsWith("--kubeconfig=")) hasAuth = true;
        }
        return runProcess(cmd, timeoutSec);
    }

    public static String lastCommand = "";

    private static String runProcess(List<String> cmd, int timeoutSec) throws IOException {
        // \u8bb0\u5f55\u5b8c\u6574\u547d\u4ee4(\u9690\u85cfkubectl\u5b8c\u6574\u8def\u5f84)
        StringBuilder cmdStr = new StringBuilder("kubectl");
        for (int i = 1; i < cmd.size(); i++) {
            String arg = cmd.get(i);
            if (arg.startsWith("--token=") && arg.length() > 28) {
                cmdStr.append(" --token=").append(arg.substring(8, 28)).append("...");
            } else {
                cmdStr.append(" ").append(arg);
            }
        }
        lastCommand = cmdStr.toString();

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        // \u91cd\u5b9a\u5411stdin\u5230\u7a7a\u6587\u4ef6\u9632\u6b62kubectl\u63d0\u793a\u8f93\u5165\u7528\u6237\u540d
        Path nullInput = Files.createTempFile("k8spen_null_", ".tmp");
        Files.writeString(nullInput, "");
        nullInput.toFile().deleteOnExit();
        pb.redirectInput(nullInput.toFile());
        Process process = pb.start();
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        }
        try {
            if (!process.waitFor(timeoutSec, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                output.append("\n[!] Command timed out after ").append(timeoutSec).append("s\n");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            output.append("\n[!] Command interrupted\n");
        }
        int exitCode = process.isAlive() ? -1 : process.exitValue();
        if (exitCode != 0) {
            output.insert(0, "[Exit code: " + exitCode + "]\n");
        }
        return output.toString();
    }

    public static String saveKubeconfig(String content) throws IOException {
        Path tempFile = Files.createTempFile("k8spen_kubeconfig_", ".yaml");
        Files.writeString(tempFile, content);
        tempFile.toFile().deleteOnExit();
        return tempFile.toString();
    }

    public static String saveYaml(String content) throws IOException {
        Path tempFile = Files.createTempFile("k8spen_yaml_", ".yaml");
        Files.writeString(tempFile, content);
        tempFile.toFile().deleteOnExit();
        return tempFile.toString();
    }
}
