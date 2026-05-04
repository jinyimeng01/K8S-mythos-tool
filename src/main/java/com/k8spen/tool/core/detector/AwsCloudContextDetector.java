package com.k8spen.tool.core.detector;

import com.k8spen.tool.core.engine.ScanSnapshot;
import com.k8spen.tool.core.model.Finding;
import com.k8spen.tool.core.model.RiskLevel;
import com.k8spen.tool.core.model.ScanRequest;

import java.util.ArrayList;
import java.util.List;

public class AwsCloudContextDetector implements CloudContextDetector {
    @Override
    public String providerName() { return "AWS"; }

    @Override
    public List<Finding> detect(ScanRequest request, ScanSnapshot snapshot) {
        List<Finding> findings = new ArrayList<>();
        boolean eks = CloudDetectorSupport.anyNodeProviderContains(snapshot, "aws", "eks.amazonaws.com", "ec2");
        List<CloudDetectorSupport.CloudSignal> irsa =
                CloudDetectorSupport.serviceAccountAnnotationSignals(snapshot, "eks.amazonaws.com/role-arn");
        List<CloudDetectorSupport.CloudSignal> defaultIrsa =
                CloudDetectorSupport.defaultServiceAccountCloudSignals(snapshot, "eks.amazonaws.com/role-arn");
        List<CloudDetectorSupport.CloudSignal> awsEnv =
                CloudDetectorSupport.podEnvSignals(snapshot, "AWS_");
        List<CloudDetectorSupport.CloudSignal> webIdentityTokens =
                CloudDetectorSupport.projectedTokenVolumeSignals(snapshot, "sts.amazonaws.com", "eks.amazonaws.com");

        if (eks) {
            findings.add(CloudDetectorSupport.providerFinding("cloud.aws.eks-detected", RiskLevel.INFO,
                    "AWS/EKS node identity indicators detected", "AWS",
                    "Node provider or labels indicate an AWS/EKS-style cluster. Metadata and IAM role boundaries should be reviewed.",
                    request.target().host(), "node.providerID/labels", "aws/eks",
                    "Restrict node metadata access and prefer IRSA with least-privilege roles."));
        }
        if (!irsa.isEmpty()) {
            findings.add(CloudDetectorSupport.providerFinding("cloud.aws.irsa-present", RiskLevel.MEDIUM,
                    "AWS IRSA role annotations are present", "AWS",
                    "ServiceAccounts reference AWS IAM roles through IRSA. Compromised pods using these accounts can inherit cloud permissions.",
                    "serviceaccounts", "metadata.annotations.eks.amazonaws.com/role-arn",
                    CloudDetectorSupport.compactSignals(irsa, 6),
                    "Audit IAM policies attached to annotated ServiceAccounts and scope trust policies tightly.",
                    "cloud-workload-identity-aws"));
        }
        if (!defaultIrsa.isEmpty()) {
            findings.add(CloudDetectorSupport.providerFinding("cloud.aws.default-sa-irsa", RiskLevel.HIGH,
                    "Default ServiceAccount is mapped to an AWS IAM role", "AWS",
                    "A default ServiceAccount carries an IRSA role annotation. Any pod that omits serviceAccountName in that namespace may inherit cloud access.",
                    "serviceaccounts/default", "metadata.annotations.eks.amazonaws.com/role-arn",
                    CloudDetectorSupport.compactSignals(defaultIrsa, 4),
                    "Move cloud role annotations to dedicated ServiceAccounts and set automountServiceAccountToken=false where API access is not required.",
                    "cloud-workload-identity-default-sa"));
        }
        if (!awsEnv.isEmpty()) {
            findings.add(CloudDetectorSupport.providerFinding("cloud.aws.sdk-env-present", riskForAwsEnv(awsEnv),
                    "AWS SDK credential environment variables are present", "AWS",
                    "Pods expose AWS SDK environment variables. Static keys, session tokens, or web identity variables can become cloud pivot material after pod compromise.",
                    "pods", "spec.containers.env.AWS_*", CloudDetectorSupport.compactSignals(awsEnv, 8),
                    "Prefer IRSA with narrow roles over static environment credentials and rotate any exposed long-lived keys.",
                    "cloud-credential-env-aws"));
        }
        if (!webIdentityTokens.isEmpty()) {
            findings.add(CloudDetectorSupport.providerFinding("cloud.aws.projected-web-identity-token", RiskLevel.MEDIUM,
                    "AWS web identity projected tokens are mounted", "AWS",
                    "Pods mount projected ServiceAccount tokens with AWS STS-style audience/path signals, indicating cloud role exchange capability.",
                    "pods", "spec.volumes.projected.serviceAccountToken",
                    CloudDetectorSupport.compactSignals(webIdentityTokens, 6),
                    "Constrain trust policies to exact namespace/serviceAccount subjects and keep token audiences scoped.",
                    "cloud-workload-identity-token"));
        }
        return findings;
    }

    private static RiskLevel riskForAwsEnv(List<CloudDetectorSupport.CloudSignal> signals) {
        for (CloudDetectorSupport.CloudSignal signal : signals) {
            if (DetectorUtils.containsAny(signal.field(), "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")) {
                return RiskLevel.HIGH;
            }
        }
        return RiskLevel.MEDIUM;
    }
}
