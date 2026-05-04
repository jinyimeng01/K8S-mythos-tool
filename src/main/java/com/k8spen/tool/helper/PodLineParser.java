package com.k8spen.tool.helper;

/**
 * 解析kubectl get pods输出行，提取Namespace/Pod/Node等信息
 */
public class PodLineParser {

    public static class PodInfo {
        public final String namespace;
        public final String name;
        public final String status;
        public final String node;

        public PodInfo(String namespace, String name, String status, String node) {
            this.namespace = namespace;
            this.name = name;
            this.status = status;
            this.node = node;
        }
    }

    private static final String[] STATUS_KEYWORDS = {
            "Running", "Completed", "CrashLoopBackOff", "Error", "Pending",
            "Terminating", "ContainerCreating", "ImagePullBackOff", "ErrImagePull",
            "Init:", "OOMKilled", "Evicted", "Unknown", "Succeeded", "Failed"
    };

    /**
     * 解析kubectl get pods -o wide的一行输出
     * 支持 --all-namespaces (有NAMESPACE列) 和单namespace (无NAMESPACE列) 两种格式
     * @return PodInfo or null if not a valid pod line
     */
    public static PodInfo parse(String line, boolean allNamespaces) {
        if (line == null || line.trim().isEmpty()) return null;
        line = line.trim();

        // 跳过表头
        if (line.startsWith("NAMESPACE") || line.startsWith("NAME")) return null;

        // 检查是否包含状态关键字
        boolean hasStatus = false;
        for (String kw : STATUS_KEYWORDS) {
            if (line.contains(kw)) { hasStatus = true; break; }
        }
        if (!hasStatus) return null;

        String[] parts = line.split("\\s+");
        if (allNamespaces) {
            // NAMESPACE  NAME  READY  STATUS  RESTARTS  AGE  IP  NODE ...
            if (parts.length < 6) return null;
            String ns = parts[0];
            String name = parts[1];
            String status = parts[3];
            String node = parts.length >= 8 ? parts[7] : "";
            return new PodInfo(ns, name, status, node);
        } else {
            // NAME  READY  STATUS  RESTARTS  AGE  IP  NODE ...
            if (parts.length < 5) return null;
            String name = parts[0];
            String status = parts[2];
            String node = parts.length >= 7 ? parts[6] : "";
            return new PodInfo("", name, status, node);
        }
    }

    /**
     * 自动检测是否为allNamespaces格式并解析
     */
    public static PodInfo autoParse(String line) {
        if (line == null || line.trim().isEmpty()) return null;
        // 如果第一列看起来像namespace (包含字母且不包含/)
        String[] parts = line.trim().split("\\s+");
        if (parts.length < 5) return null;

        // 尝试allNamespaces格式 (status在index 3)
        PodInfo info = parse(line, true);
        if (info != null && !info.namespace.isEmpty()) return info;

        // 尝试单namespace格式 (status在index 2)
        return parse(line, false);
    }
}
