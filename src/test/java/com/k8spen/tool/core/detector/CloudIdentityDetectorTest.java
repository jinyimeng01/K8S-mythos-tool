package com.k8spen.tool.core.detector;

import com.k8spen.tool.core.client.ApiResponse;
import com.k8spen.tool.core.engine.ScanSnapshot;
import com.k8spen.tool.core.model.AuthProfile;
import com.k8spen.tool.core.model.Finding;
import com.k8spen.tool.core.model.ScanModule;
import com.k8spen.tool.core.model.ScanRequest;
import com.k8spen.tool.core.model.TargetProfile;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CloudIdentityDetectorTest {
    @Test
    void detectsAwsIrsaAndPreservesSessionTokenEnvInFullEvidenceMode() {
        ScanSnapshot snapshot = snapshot("""
                {
                  "items": [{
                    "metadata": {
                      "name": "app",
                      "namespace": "default",
                      "annotations": {
                        "eks.amazonaws.com/role-arn": "arn:aws:iam::123456789012:role/app"
                      }
                    }
                  }]
                }
                """, podsWithEnv("AWS_SESSION_TOKEN", "very-secret-session-token"), emptyList(), emptyList());

        List<Finding> findings = detect(snapshot);

        assertTrue(hasId(findings, "cloud.aws.irsa-present"));
        assertTrue(hasId(findings, "cloud.aws.sdk-env-present"));
        String evidence = findings.toString();
        assertFalse(evidence.contains("redacted:sha256:"));
        assertTrue(evidence.contains("very-secret-session-token"));
    }

    @Test
    void detectsGkeWorkloadIdentityAndHostNetworkMetadataRisk() {
        ScanSnapshot snapshot = snapshot("""
                {
                  "items": [{
                    "metadata": {
                      "name": "app",
                      "namespace": "prod",
                      "annotations": {
                        "iam.gke.io/gcp-service-account": "app@project.iam.gserviceaccount.com"
                      }
                    }
                  }]
                }
                """, """
                {
                  "items": [{
                    "metadata": {"name": "agent", "namespace": "prod"},
                    "spec": {"hostNetwork": true, "containers": [{"name": "agent"}]}
                  }]
                }
                """, """
                {
                  "items": [{
                    "metadata": {"name": "gke-node", "labels": {"cloud.google.com/gke-nodepool": "default"}},
                    "spec": {"providerID": "gce://project/zone/gke-node"}
                  }]
                }
                """, emptyList());

        List<Finding> findings = detect(snapshot);

        assertTrue(hasId(findings, "cloud.gcp.workload-identity-present"));
        assertTrue(hasId(findings, "cloud.gcp.hostnetwork-metadata"));
    }

    @Test
    void detectsAzureWorkloadIdentityMarkers() {
        ScanSnapshot snapshot = snapshot("""
                {
                  "items": [{
                    "metadata": {
                      "name": "api",
                      "namespace": "prod",
                      "annotations": {
                        "azure.workload.identity/client-id": "11111111-1111-1111-1111-111111111111"
                      }
                    }
                  }]
                }
                """, """
                {
                  "items": [{
                    "metadata": {
                      "name": "api",
                      "namespace": "prod",
                      "labels": {"azure.workload.identity/use": "true"}
                    },
                    "spec": {
                      "volumes": [{
                        "name": "azure-token",
                        "projected": {"sources": [{"serviceAccountToken": {"audience": "api://AzureADTokenExchange", "path": "azure-identity-token"}}]}
                      }],
                      "containers": [{"name": "api", "env": [{"name": "AZURE_FEDERATED_TOKEN_FILE", "value": "/var/run/secrets/azure/tokens/azure-identity-token"}]}]
                    }
                  }]
                }
                """, emptyList(), emptyList());

        List<Finding> findings = detect(snapshot);

        assertTrue(hasId(findings, "cloud.azure.workload-identity-present"));
        assertTrue(hasId(findings, "cloud.azure.projected-federated-token"));
        assertTrue(hasId(findings, "cloud.azure.sdk-env-present"));
    }

    @Test
    void detectsAckRrsaAndNamespaceInjection() {
        ScanSnapshot snapshot = snapshot("""
                {
                  "items": [{
                    "metadata": {
                      "name": "worker",
                      "namespace": "prod",
                      "annotations": {
                        "pod-identity.alibabacloud.com/role-name": "ack-app-role"
                      }
                    }
                  }]
                }
                """, podsWithEnv("ALIBABA_CLOUD_ROLE_ARN", "acs:ram::123456789012:role/ack-app-role"), emptyList(), """
                {
                  "items": [{
                    "metadata": {
                      "name": "prod",
                      "labels": {"pod-identity.alibabacloud.com/injection": "on"}
                    }
                  }]
                }
                """);

        List<Finding> findings = detect(snapshot);

        assertTrue(hasId(findings, "cloud.alicloud.rrsa-present"));
        assertTrue(hasId(findings, "cloud.alicloud.sdk-env-present"));
    }

    @Test
    void cloudDetectorsCanBeDisabled() {
        ScanSnapshot snapshot = snapshot("""
                {"items": [{"metadata": {"name": "app", "namespace": "default", "annotations": {"eks.amazonaws.com/role-arn": "role"}}}]}
                """, emptyList(), emptyList(), emptyList());
        ScanRequest request = ScanRequest.create(TargetProfile.fromHost("127.0.0.1", 5, true),
                AuthProfile.bearer("token"), EnumSet.of(ScanModule.CLOUD_CONTEXT), "", false, true);

        assertTrue(new CloudIdentityDetector().detect(request, snapshot).isEmpty());
    }

    private static List<Finding> detect(ScanSnapshot snapshot) {
        ScanRequest request = ScanRequest.create(TargetProfile.fromHost("127.0.0.1", 5, true),
                AuthProfile.bearer("token"), EnumSet.of(ScanModule.CLOUD_CONTEXT), "", true, true);
        return new CloudIdentityDetector().detect(request, snapshot);
    }

    private static ScanSnapshot snapshot(String serviceAccounts, String pods, String nodes, String namespaces) {
        ScanSnapshot snapshot = new ScanSnapshot();
        snapshot.put("serviceAccounts", ApiResponse.fromRaw("/api/v1/serviceaccounts", "[HTTP 200]\n" + serviceAccounts, false));
        snapshot.put("pods", ApiResponse.fromRaw("/api/v1/pods", "[HTTP 200]\n" + pods, false));
        snapshot.put("nodes", ApiResponse.fromRaw("/api/v1/nodes", "[HTTP 200]\n" + nodes, false));
        snapshot.put("namespaces", ApiResponse.fromRaw("/api/v1/namespaces", "[HTTP 200]\n" + namespaces, false));
        return snapshot;
    }

    private static boolean hasId(List<Finding> findings, String id) {
        return findings.stream().anyMatch(f -> f.id().equals(id));
    }

    private static String podsWithEnv(String name, String value) {
        return """
                {
                  "items": [{
                    "metadata": {"name": "pod", "namespace": "default"},
                    "spec": {"containers": [{"name": "app", "env": [{"name": "%s", "value": "%s"}]}]}
                  }]
                }
                """.formatted(name, value);
    }

    private static String emptyList() {
        return "{\"items\":[]}";
    }
}
