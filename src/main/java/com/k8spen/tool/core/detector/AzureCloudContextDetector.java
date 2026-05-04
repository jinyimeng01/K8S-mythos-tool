package com.k8spen.tool.core.detector;

import com.k8spen.tool.core.engine.ScanSnapshot;
import com.k8spen.tool.core.model.Finding;
import com.k8spen.tool.core.model.RiskLevel;
import com.k8spen.tool.core.model.ScanRequest;

import java.util.ArrayList;
import java.util.List;

public class AzureCloudContextDetector implements CloudContextDetector {
    @Override
    public String providerName() { return "Azure"; }

    @Override
    public List<Finding> detect(ScanRequest request, ScanSnapshot snapshot) {
        List<Finding> findings = new ArrayList<>();
        boolean aks = CloudDetectorSupport.anyNodeProviderContains(snapshot, "azure", "aks", "kubernetes.azure.com");
        List<CloudDetectorSupport.CloudSignal> saAnnotations =
                CloudDetectorSupport.serviceAccountAnnotationSignals(snapshot, "azure.workload.identity");
        List<CloudDetectorSupport.CloudSignal> defaultAzureIdentity =
                CloudDetectorSupport.defaultServiceAccountCloudSignals(snapshot, "azure.workload.identity");
        List<CloudDetectorSupport.CloudSignal> podLabels =
                CloudDetectorSupport.podLabelSignals(snapshot, "azure.workload.identity/use");
        List<CloudDetectorSupport.CloudSignal> podAnnotations =
                CloudDetectorSupport.podAnnotationSignals(snapshot, "azure.workload.identity");
        List<CloudDetectorSupport.CloudSignal> azureEnv =
                CloudDetectorSupport.podEnvSignals(snapshot, "AZURE_", "MSI_");
        List<CloudDetectorSupport.CloudSignal> federatedTokens =
                CloudDetectorSupport.projectedTokenVolumeSignals(snapshot, "api://AzureADTokenExchange", "azure");

        if (aks) {
            findings.add(CloudDetectorSupport.providerFinding("cloud.azure.aks-detected", RiskLevel.INFO,
                    "Azure/AKS node identity indicators detected", "Azure",
                    "Node provider or labels indicate an Azure/AKS-style cluster.",
                    request.target().host(), "node.providerID/labels", "azure/aks",
                    "Review managed identity scope and metadata endpoint restrictions."));
        }
        if (!saAnnotations.isEmpty() || !podLabels.isEmpty() || !podAnnotations.isEmpty()) {
            findings.add(CloudDetectorSupport.providerFinding("cloud.azure.workload-identity-present", RiskLevel.MEDIUM,
                    "Azure Workload Identity markers are present", "Azure",
                    "ServiceAccounts or Pods include Azure Workload Identity annotations/labels. Compromised workloads may exchange projected tokens for Azure access.",
                    "workloads", "metadata.annotations/labels.azure.workload.identity",
                    CloudDetectorSupport.compactSignals(combine(saAnnotations, podLabels, podAnnotations), 8),
                    "Scope federated credentials and Azure role assignments to least privilege.",
                    "cloud-workload-identity-azure"));
        }
        if (!defaultAzureIdentity.isEmpty()) {
            findings.add(CloudDetectorSupport.providerFinding("cloud.azure.default-sa-workload-identity", RiskLevel.HIGH,
                    "Default ServiceAccount is configured for Azure Workload Identity", "Azure",
                    "A default ServiceAccount carries Azure Workload Identity annotations. Pods that omit serviceAccountName may inherit Azure access.",
                    "serviceaccounts/default", "metadata.annotations.azure.workload.identity",
                    CloudDetectorSupport.compactSignals(defaultAzureIdentity, 4),
                    "Move Azure identity annotations to dedicated ServiceAccounts and restrict namespace-level use.",
                    "cloud-workload-identity-default-sa"));
        }
        if (!azureEnv.isEmpty()) {
            findings.add(CloudDetectorSupport.providerFinding("cloud.azure.sdk-env-present", RiskLevel.MEDIUM,
                    "Azure SDK identity environment variables are present", "Azure",
                    "Pods expose Azure SDK or managed identity environment variables that can reveal client IDs, tenant IDs, or token file paths.",
                    "pods", "spec.containers.env.AZURE_*/MSI_*",
                    CloudDetectorSupport.compactSignals(azureEnv, 8),
                    "Prefer workload identity with scoped federated credentials and avoid long-lived client secrets in env vars.",
                    "cloud-credential-env-azure"));
        }
        if (!federatedTokens.isEmpty()) {
            findings.add(CloudDetectorSupport.providerFinding("cloud.azure.projected-federated-token", RiskLevel.MEDIUM,
                    "Azure federated token projection is present", "Azure",
                    "Pods mount ServiceAccount token projections with Azure token-exchange audience/path signals.",
                    "pods", "spec.volumes.projected.serviceAccountToken",
                    CloudDetectorSupport.compactSignals(federatedTokens, 6),
                    "Constrain federated identity credentials to exact service account subjects and namespaces.",
                    "cloud-workload-identity-token"));
        }
        return findings;
    }

    @SafeVarargs
    private static List<CloudDetectorSupport.CloudSignal> combine(List<CloudDetectorSupport.CloudSignal>... lists) {
        List<CloudDetectorSupport.CloudSignal> combined = new ArrayList<>();
        for (List<CloudDetectorSupport.CloudSignal> list : lists) combined.addAll(list);
        return combined;
    }
}
