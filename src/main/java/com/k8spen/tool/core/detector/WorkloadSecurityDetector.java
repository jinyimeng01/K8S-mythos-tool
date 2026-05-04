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

import java.util.ArrayList;
import java.util.List;

public class WorkloadSecurityDetector implements ScanDetector {
    @Override
    public List<Finding> detect(ScanRequest request, ScanSnapshot snapshot) {
        List<Finding> findings = new ArrayList<>();
        JsonArray pods = DetectorUtils.items(snapshot.object("pods"));
        for (JsonElement e : pods) {
            JsonObject pod = e.getAsJsonObject();
            String podName = DetectorUtils.namespacedName(pod);
            JsonObject spec = DetectorUtils.obj(pod, "spec");

            addPodLevelFindings(findings, podName, spec);
            addVolumeFindings(findings, podName, spec);
            addContainerFindings(findings, podName, spec);
        }
        return findings;
    }

    private void addPodLevelFindings(List<Finding> findings, String podName, JsonObject spec) {
        if (DetectorUtils.bool(spec, "hostNetwork")) {
            findings.add(base("workload.host-network." + safe(podName), RiskLevel.MEDIUM, "Pod uses hostNetwork", podName, "host-network")
                    .summary("hostNetwork places the workload on the node network namespace and can expand lateral reach.")
                    .remediation("Use pod networking unless the workload has a specific, reviewed host network requirement.")
                    .evidence(Evidence.of("pods", podName, "spec.hostNetwork", "true"))
                    .build());
        }
        if (DetectorUtils.bool(spec, "hostPID")) {
            findings.add(base("workload.host-pid." + safe(podName), RiskLevel.HIGH, "Pod uses hostPID", podName, "host-namespace")
                    .summary("hostPID exposes host process visibility to the workload.")
                    .remediation("Disable hostPID for application workloads and isolate node maintenance workloads.")
                    .evidence(Evidence.of("pods", podName, "spec.hostPID", "true"))
                    .build());
        }
        if (DetectorUtils.bool(spec, "hostIPC")) {
            findings.add(base("workload.host-ipc." + safe(podName), RiskLevel.MEDIUM, "Pod uses hostIPC", podName, "host-namespace")
                    .summary("hostIPC shares host IPC namespace with the workload.")
                    .remediation("Disable hostIPC unless explicitly required and reviewed.")
                    .evidence(Evidence.of("pods", podName, "spec.hostIPC", "true"))
                    .build());
        }
        if (spec.has("nodeName") && !DetectorUtils.str(spec, "nodeName").isBlank()) {
            findings.add(base("workload.node-pinned." + safe(podName), RiskLevel.LOW, "Pod is pinned to a specific node", podName, "node-binding")
                    .summary("nodeName bypasses normal scheduler placement decisions and can hide node targeting assumptions.")
                    .remediation("Prefer selectors/affinity with policy controls instead of direct nodeName binding.")
                    .evidence(Evidence.of("pods", podName, "spec.nodeName", DetectorUtils.str(spec, "nodeName")))
                    .build());
        }
        JsonArray tolerations = DetectorUtils.arr(spec, "tolerations");
        for (JsonElement t : tolerations) {
            JsonObject toleration = t.getAsJsonObject();
            if ("Exists".equals(DetectorUtils.str(toleration, "operator")) && DetectorUtils.str(toleration, "key").isBlank()) {
                findings.add(base("workload.tolerates-all-taints." + safe(podName), RiskLevel.MEDIUM, "Pod tolerates all taints", podName, "scheduling")
                        .summary("A blanket toleration allows scheduling onto tainted nodes, including control-plane nodes in permissive environments.")
                        .remediation("Use narrowly scoped tolerations tied to a clear workload requirement.")
                        .evidence(Evidence.of("pods", podName, "spec.tolerations", "operator=Exists"))
                        .build());
            }
        }
        if (!spec.has("automountServiceAccountToken")) {
            findings.add(base("workload.sa-token-automount-default." + safe(podName), RiskLevel.LOW, "Pod relies on default ServiceAccount token mounting behavior", podName, "service-account")
                    .summary("The pod does not explicitly disable ServiceAccount token automounting.")
                    .remediation("Set automountServiceAccountToken=false for workloads that do not need Kubernetes API access.")
                    .evidence(Evidence.of("pods", podName, "spec.automountServiceAccountToken", "(not set)"))
                    .build());
        }
    }

    private void addVolumeFindings(List<Finding> findings, String podName, JsonObject spec) {
        JsonArray volumes = DetectorUtils.arr(spec, "volumes");
        for (JsonElement v : volumes) {
            JsonObject volume = v.getAsJsonObject();
            JsonObject hostPath = DetectorUtils.obj(volume, "hostPath");
            if (hostPath.size() == 0) continue;
            String volumeName = DetectorUtils.str(volume, "name");
            String path = DetectorUtils.str(hostPath, "path");
            RiskLevel level = isRuntimeSocket(path) || "/".equals(path) ? RiskLevel.CRITICAL : RiskLevel.HIGH;
            String category = isRuntimeSocket(path) ? "runtime-socket" : "hostpath";
            findings.add(base("workload.hostpath." + safe(podName) + "." + safe(volumeName), level, "Pod mounts hostPath", podName, category)
                    .summary("hostPath mount " + path + " exposes node filesystem or runtime surface to the workload.")
                    .remediation("Replace hostPath with safer volume types and block sensitive host paths with admission policy.")
                    .evidence(Evidence.of("pods", podName, "spec.volumes[" + volumeName + "].hostPath.path", path))
                    .build());
        }
    }

    private void addContainerFindings(List<Finding> findings, String podName, JsonObject spec) {
        JsonArray containers = DetectorUtils.arr(spec, "containers");
        for (JsonElement c : containers) {
            JsonObject container = c.getAsJsonObject();
            String name = DetectorUtils.str(container, "name");
            String resource = podName + "/" + name;
            JsonObject securityContext = DetectorUtils.obj(container, "securityContext");
            if (DetectorUtils.bool(securityContext, "privileged")) {
                findings.add(base("workload.privileged." + safe(resource), RiskLevel.CRITICAL, "Container runs privileged", resource, "privileged-container")
                        .summary("Privileged containers bypass many container isolation controls and can lead to node compromise when combined with mounts or capabilities.")
                        .remediation("Remove privileged=true and grant only the minimal capabilities required.")
                        .evidence(Evidence.of("pods", resource, "securityContext.privileged", "true"))
                        .build());
            }
            JsonObject capabilities = DetectorUtils.obj(securityContext, "capabilities");
            JsonArray add = DetectorUtils.arr(capabilities, "add");
            for (JsonElement cap : add) {
                String value = cap.getAsString();
                if ("SYS_ADMIN".equals(value) || "CAP_SYS_ADMIN".equals(value)) {
                    findings.add(base("workload.cap-sys-admin." + safe(resource), RiskLevel.HIGH, "Container adds CAP_SYS_ADMIN", resource, "dangerous-capability")
                            .summary("CAP_SYS_ADMIN is a broad Linux capability frequently involved in container escape prerequisites.")
                            .remediation("Remove CAP_SYS_ADMIN and use targeted capabilities only after review.")
                            .evidence(Evidence.of("pods", resource, "securityContext.capabilities.add", value))
                            .build());
                }
            }
        }
    }

    private Finding.Builder base(String id, RiskLevel level, String title, String resource, String category) {
        return Finding.builder(id, ScanModule.WORKLOAD_SECURITY, level, title)
                .resource(resource)
                .category(category)
                .standard("Pod Security Standards / OWASP Kubernetes Top 10");
    }

    private static boolean isRuntimeSocket(String path) {
        return DetectorUtils.containsAny(path, "docker.sock", "containerd.sock", "cri-dockerd.sock", "crio.sock");
    }

    private static String safe(String value) {
        return value == null ? "unknown" : value.replaceAll("[^A-Za-z0-9_.-]", ".");
    }
}
