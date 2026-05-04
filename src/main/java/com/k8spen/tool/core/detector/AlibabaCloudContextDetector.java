package com.k8spen.tool.core.detector;

import com.k8spen.tool.core.engine.ScanSnapshot;
import com.k8spen.tool.core.model.Finding;
import com.k8spen.tool.core.model.RiskLevel;
import com.k8spen.tool.core.model.ScanRequest;

import java.util.ArrayList;
import java.util.List;

public class AlibabaCloudContextDetector implements CloudContextDetector {
    @Override
    public String providerName() { return "Alibaba Cloud"; }

    @Override
    public List<Finding> detect(ScanRequest request, ScanSnapshot snapshot) {
        List<Finding> findings = new ArrayList<>();
        boolean ack = CloudDetectorSupport.anyNodeProviderContains(snapshot, "aliyun", "alibaba", "ack")
                || CloudDetectorSupport.anyServiceAccountAnnotationContains(snapshot, "pod-identity.alibabacloud.com", "ack.aliyun.com", "alibabacloud.com");
        List<CloudDetectorSupport.CloudSignal> rrsa =
                CloudDetectorSupport.serviceAccountAnnotationSignals(snapshot,
                        "pod-identity.alibabacloud.com/role-name",
                        "pod-identity.alibabacloud.com/oidc-provider-arn",
                        "pod-identity.alibabacloud.com/service-account-token-expiration",
                        "oidc-provider-arn", "rolearn", "role-arn", "alibabacloud.com/role");
        List<CloudDetectorSupport.CloudSignal> namespaceInjection =
                CloudDetectorSupport.namespaceLabelSignals(snapshot, "pod-identity.alibabacloud.com/injection");
        List<CloudDetectorSupport.CloudSignal> defaultRrsa =
                CloudDetectorSupport.defaultServiceAccountCloudSignals(snapshot,
                        "pod-identity.alibabacloud.com/role-name", "rolearn", "role-arn", "alibabacloud.com/role");
        List<CloudDetectorSupport.CloudSignal> aliyunEnv =
                CloudDetectorSupport.podEnvSignals(snapshot, "ALIBABA_CLOUD_", "ALICLOUD_", "ALIYUN_");
        List<CloudDetectorSupport.CloudSignal> stsTokens =
                CloudDetectorSupport.projectedTokenVolumeSignals(snapshot, "sts.aliyuncs.com", "alibabacloud", "aliyun");

        if (ack) {
            findings.add(CloudDetectorSupport.providerFinding("cloud.alicloud.ack-detected", RiskLevel.INFO,
                    "Alibaba Cloud ACK indicators detected", "AlibabaCloud",
                    "Node provider, labels, or workload identity annotations indicate an ACK-style cluster.",
                    request.target().host(), "node.providerID/labels/annotations", "ack/aliyun",
                    "Review RAM role usage and metadata endpoint exposure."));
        }
        if (!rrsa.isEmpty() || !namespaceInjection.isEmpty()) {
            findings.add(CloudDetectorSupport.providerFinding("cloud.alicloud.rrsa-present", RiskLevel.MEDIUM,
                    "ACK RRSA-style role annotations are present", "AlibabaCloud",
                    "ServiceAccounts or namespaces include ACK RRSA markers. Pod compromise can inherit RAM role permissions when trust is broad.",
                    "workloads", "metadata.annotations/labels.pod-identity.alibabacloud.com",
                    CloudDetectorSupport.compactSignals(combine(rrsa, namespaceInjection), 8),
                    "Audit RAM role policies, OIDC trust conditions, and namespace-level identity injection.",
                    "cloud-workload-identity-alicloud"));
        }
        if (!defaultRrsa.isEmpty()) {
            findings.add(CloudDetectorSupport.providerFinding("cloud.alicloud.default-sa-rrsa", RiskLevel.HIGH,
                    "Default ServiceAccount is mapped to an Alibaba Cloud RAM role", "AlibabaCloud",
                    "A default ServiceAccount carries RRSA-style annotations. Pods that omit serviceAccountName may inherit RAM role access.",
                    "serviceaccounts/default", "metadata.annotations.pod-identity.alibabacloud.com",
                    CloudDetectorSupport.compactSignals(defaultRrsa, 4),
                    "Use dedicated ServiceAccounts for RAM role mappings and avoid identity injection on default accounts.",
                    "cloud-workload-identity-default-sa"));
        }
        if (!aliyunEnv.isEmpty()) {
            findings.add(CloudDetectorSupport.providerFinding("cloud.alicloud.sdk-env-present", RiskLevel.MEDIUM,
                    "Alibaba Cloud SDK identity environment variables are present", "AlibabaCloud",
                    "Pods expose Alibaba Cloud SDK or STS-related environment variables that can reveal role, token, or credential delivery paths.",
                    "pods", "spec.containers.env.ALIBABA_CLOUD_*/ALICLOUD_*/ALIYUN_*",
                    CloudDetectorSupport.compactSignals(aliyunEnv, 8),
                    "Prefer RRSA with narrow RAM roles and avoid long-lived AccessKey values in environment variables.",
                    "cloud-credential-env-alicloud"));
        }
        if (!stsTokens.isEmpty()) {
            findings.add(CloudDetectorSupport.providerFinding("cloud.alicloud.projected-sts-token", RiskLevel.MEDIUM,
                    "Alibaba Cloud STS projected token is present", "AlibabaCloud",
                    "Pods mount projected ServiceAccount tokens with Alibaba Cloud STS-style audience/path signals.",
                    "pods", "spec.volumes.projected.serviceAccountToken",
                    CloudDetectorSupport.compactSignals(stsTokens, 6),
                    "Constrain RAM trust conditions to exact ServiceAccount subjects and keep token audiences scoped.",
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
