package com.k8spen.tool.core.detector;

import com.k8spen.tool.core.engine.ScanSnapshot;
import com.k8spen.tool.core.model.Finding;
import com.k8spen.tool.core.model.RiskLevel;
import com.k8spen.tool.core.model.ScanRequest;

import java.util.ArrayList;
import java.util.List;

public class GenericCloudContextDetector implements CloudContextDetector {
    @Override
    public String providerName() { return "Generic"; }

    @Override
    public List<Finding> detect(ScanRequest request, ScanSnapshot snapshot) {
        List<Finding> findings = new ArrayList<>();
        List<CloudDetectorSupport.CloudSignal> hostNetworkPods = CloudDetectorSupport.hostNetworkPodSignals(snapshot);
        if (!hostNetworkPods.isEmpty()) {
            findings.add(CloudDetectorSupport.providerFinding("cloud.generic.hostnetwork-metadata-reach", RiskLevel.MEDIUM,
                    "Host-network pods may reach node metadata services", "GenericCloud",
                    hostNetworkPods.size() + " hostNetwork pod(s) were observed. In cloud clusters, this can make instance metadata reachable unless blocked.",
                    "pods", "spec.hostNetwork", CloudDetectorSupport.compactSignals(hostNetworkPods, 8),
                    "Block cloud metadata endpoints from pods unless workload identity design requires access.",
                    "cloud-metadata-reach-generic"));
        }
        List<CloudDetectorSupport.CloudSignal> workloadIdentityAnnotations =
                CloudDetectorSupport.serviceAccountAnnotationSignals(snapshot, "role", "identity", "iam", "sts", "oidc", "workload");
        if (!workloadIdentityAnnotations.isEmpty()) {
            findings.add(CloudDetectorSupport.providerFinding("cloud.generic.identity-annotations", RiskLevel.LOW,
                    "Workload identity-like annotations are present", "GenericCloud",
                    "ServiceAccount annotations contain cloud identity keywords. Provider-specific review is recommended.",
                    "serviceaccounts", "metadata.annotations", CloudDetectorSupport.compactSignals(workloadIdentityAnnotations, 8),
                    "Audit mapped cloud roles and trust policies.",
                    "cloud-workload-identity-generic"));
        }
        List<CloudDetectorSupport.CloudSignal> genericEnv =
                CloudDetectorSupport.podEnvSignals(snapshot, "CLOUD_", "OIDC_", "STS_", "ROLE_");
        if (!genericEnv.isEmpty()) {
            findings.add(CloudDetectorSupport.providerFinding("cloud.generic.identity-env-present", RiskLevel.LOW,
                    "Generic cloud identity environment variables are present", "GenericCloud",
                    "Pods contain cloud/STS/OIDC environment variable names that may indicate credential delivery paths.",
                    "pods", "spec.containers.env", CloudDetectorSupport.compactSignals(genericEnv, 8),
                    "Confirm whether these variables are required and avoid long-lived credentials in workload environment variables.",
                    "cloud-credential-env-generic"));
        }
        return findings;
    }
}
