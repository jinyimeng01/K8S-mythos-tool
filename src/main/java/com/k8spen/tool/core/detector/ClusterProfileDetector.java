package com.k8spen.tool.core.detector;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.k8spen.tool.core.client.ApiResponse;
import com.k8spen.tool.core.engine.ScanSnapshot;
import com.k8spen.tool.core.model.Evidence;
import com.k8spen.tool.core.model.Finding;
import com.k8spen.tool.core.model.RiskLevel;
import com.k8spen.tool.core.model.ScanModule;
import com.k8spen.tool.core.model.ScanRequest;

import java.util.ArrayList;
import java.util.List;

public class ClusterProfileDetector implements ScanDetector {
    @Override
    public List<Finding> detect(ScanRequest request, ScanSnapshot snapshot) {
        List<Finding> findings = new ArrayList<>();
        JsonObject version = snapshot.object("version");
        snapshot.profile("Kubernetes Version", DetectorUtils.str(version, "gitVersion"));

        JsonArray nodes = DetectorUtils.items(snapshot.object("nodes"));
        snapshot.profile("Node Count", String.valueOf(nodes.size()));
        for (JsonElement item : nodes) {
            JsonObject node = item.getAsJsonObject();
            String name = DetectorUtils.str(DetectorUtils.obj(node, "metadata"), "name");
            JsonObject nodeInfo = DetectorUtils.obj(DetectorUtils.obj(node, "status"), "nodeInfo");
            String runtime = DetectorUtils.str(nodeInfo, "containerRuntimeVersion");
            String kernel = DetectorUtils.str(nodeInfo, "kernelVersion");
            if (!runtime.isBlank()) snapshot.profile("Runtime " + name, runtime);
            if (!kernel.isBlank()) snapshot.profile("Kernel " + name, kernel);
            if (DetectorUtils.containsAny(runtime, "docker://")) {
                findings.add(Finding.builder("cluster.node.docker-runtime." + name, ScanModule.CLUSTER_PROFILE,
                                RiskLevel.MEDIUM, "Node uses Docker runtime")
                        .summary("Docker runtime increases exposure to docker.sock based escape paths when workloads can mount host paths.")
                        .resource(name)
                        .category("runtime")
                        .standard("Kubernetes Security Checklist: runtime and node hardening")
                        .remediation("Prefer a supported CRI runtime and restrict hostPath/runtime socket mounts.")
                        .evidence(Evidence.of("nodes", name, "status.nodeInfo.containerRuntimeVersion", runtime))
                        .build());
            }
        }

        JsonArray namespaces = DetectorUtils.items(snapshot.object("namespaces"));
        snapshot.profile("Namespace Count", String.valueOf(namespaces.size()));
        JsonArray pods = DetectorUtils.items(snapshot.object("pods"));
        snapshot.profile("Pod Count", String.valueOf(pods.size()));

        ApiResponse anonymousApi = snapshot.response("anonymousApi");
        if (anonymousApi != null && anonymousApi.isSuccess()) {
            findings.add(Finding.builder("cluster.anonymous.api-access", ScanModule.CLUSTER_PROFILE,
                            RiskLevel.HIGH, "Anonymous API discovery is available")
                    .summary("The API discovery endpoint responded without a bearer token. This can expose cluster shape and may combine with other anonymous permissions.")
                    .resource(request.target().apiServerUrl())
                    .category("anonymous-api")
                    .standard("Kubernetes Security Checklist: API server access control")
                    .remediation("Disable anonymous access where possible and verify API server authorization modes.")
                    .evidence(Evidence.of("anonymous:/api", request.target().apiServerUrl(), "http.status", String.valueOf(anonymousApi.statusCode())))
                    .build());
        }

        ApiResponse ssrr = snapshot.response("selfSubjectRules");
        if (ssrr != null && ssrr.isForbiddenOrUnauthorized()) {
            findings.add(Finding.builder("cluster.auth.rules-review-denied", ScanModule.CLUSTER_PROFILE,
                            RiskLevel.INFO, "Current identity cannot self-review permissions")
                    .summary("SelfSubjectRulesReview returned " + ssrr.statusCode() + ". The scan continues with resource evidence that is available.")
                    .resource(request.auth().maskedIdentity())
                    .category("permission-review")
                    .standard("Kubernetes authorization API")
                    .remediation("Run the scan with an identity allowed to create SelfSubjectRulesReview for deeper permission analysis.")
                    .evidence(Evidence.of("selfsubjectrulesreviews", request.auth().maskedIdentity(), "http.status", String.valueOf(ssrr.statusCode())))
                    .build());
        }
        return findings;
    }
}
