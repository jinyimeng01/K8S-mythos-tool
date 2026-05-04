package com.k8spen.tool.core.detector;

import com.k8spen.tool.core.engine.ScanSnapshot;
import com.k8spen.tool.core.model.Finding;
import com.k8spen.tool.core.model.RiskLevel;
import com.k8spen.tool.core.model.ScanRequest;

import java.util.ArrayList;
import java.util.List;

public class GcpCloudContextDetector implements CloudContextDetector {
    @Override
    public String providerName() { return "GCP"; }

    @Override
    public List<Finding> detect(ScanRequest request, ScanSnapshot snapshot) {
        List<Finding> findings = new ArrayList<>();
        boolean gke = CloudDetectorSupport.anyNodeProviderContains(snapshot, "gce", "gke", "cloud.google.com");
        List<CloudDetectorSupport.CloudSignal> workloadIdentity =
                CloudDetectorSupport.serviceAccountAnnotationSignals(snapshot, "iam.gke.io/gcp-service-account");
        List<CloudDetectorSupport.CloudSignal> defaultWorkloadIdentity =
                CloudDetectorSupport.defaultServiceAccountCloudSignals(snapshot, "iam.gke.io/gcp-service-account");
        List<CloudDetectorSupport.CloudSignal> googleEnv =
                CloudDetectorSupport.podEnvSignals(snapshot, "GOOGLE_", "GCP_");
        List<CloudDetectorSupport.CloudSignal> metadataReach =
                CloudDetectorSupport.hostNetworkPodSignals(snapshot);

        if (gke) {
            findings.add(CloudDetectorSupport.providerFinding("cloud.gcp.gke-detected", RiskLevel.INFO,
                    "GCP/GKE node identity indicators detected", "GCP",
                    "Node provider or labels indicate a GCP/GKE-style cluster.",
                    request.target().host(), "node.providerID/labels", "gcp/gke",
                    "Review metadata access controls and Workload Identity configuration."));
        }
        if (!workloadIdentity.isEmpty()) {
            findings.add(CloudDetectorSupport.providerFinding("cloud.gcp.workload-identity-present", RiskLevel.MEDIUM,
                    "GKE Workload Identity annotations are present", "GCP",
                    "Kubernetes ServiceAccounts map to Google service accounts. Pod compromise can become cloud identity compromise if IAM is broad.",
                    "serviceaccounts", "metadata.annotations.iam.gke.io/gcp-service-account",
                    CloudDetectorSupport.compactSignals(workloadIdentity, 6),
                    "Review IAM allow policies and restrict Kubernetes ServiceAccount usage.",
                    "cloud-workload-identity-gcp"));
        }
        if (!defaultWorkloadIdentity.isEmpty()) {
            findings.add(CloudDetectorSupport.providerFinding("cloud.gcp.default-sa-workload-identity", RiskLevel.HIGH,
                    "Default ServiceAccount is mapped to a Google service account", "GCP",
                    "A default Kubernetes ServiceAccount has a GKE Workload Identity annotation. Pods that omit serviceAccountName may inherit cloud access.",
                    "serviceaccounts/default", "metadata.annotations.iam.gke.io/gcp-service-account",
                    CloudDetectorSupport.compactSignals(defaultWorkloadIdentity, 4),
                    "Use dedicated ServiceAccounts for cloud access and disable automatic token mounting for workloads that do not need it.",
                    "cloud-workload-identity-default-sa"));
        }
        if (!googleEnv.isEmpty()) {
            findings.add(CloudDetectorSupport.providerFinding("cloud.gcp.sdk-env-present", RiskLevel.MEDIUM,
                    "Google Cloud SDK environment variables are present", "GCP",
                    "Pods contain Google/GCP environment variables that can reveal credential file paths, project targeting, or cloud SDK behavior.",
                    "pods", "spec.containers.env.GOOGLE_*/GCP_*",
                    CloudDetectorSupport.compactSignals(googleEnv, 8),
                    "Avoid mounting long-lived service account keys and prefer Workload Identity with least-privilege IAM.",
                    "cloud-credential-env-gcp"));
        }
        if (gke && !metadataReach.isEmpty()) {
            findings.add(CloudDetectorSupport.providerFinding("cloud.gcp.hostnetwork-metadata", RiskLevel.MEDIUM,
                    "hostNetwork pods may bypass GKE metadata isolation assumptions", "GCP",
                    "hostNetwork pods were observed in a GKE-like cluster. Google documents hostNetwork as a case where pods can access the Compute Engine metadata server.",
                    "pods", "spec.hostNetwork", CloudDetectorSupport.compactSignals(metadataReach, 8),
                    "Block metadata access from workloads unless explicitly required and keep Workload Identity policies narrow.",
                    "cloud-metadata-reach-gcp"));
        }
        return findings;
    }
}
