package com.k8spen.tool.core.detector;

import com.k8spen.tool.core.model.Finding;
import com.k8spen.tool.core.model.ScanModule;
import com.k8spen.tool.test.DetectorFixtureRunner;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

class DetectorFixtureFrameworkTest {
    @Test
    void runsRbacDetectorFromReusableFixtures() {
        List<Finding> findings = DetectorFixtureRunner.run(new IdentityRbacDetector(), ScanModule.IDENTITY_RBAC, Map.of(
                "selfSubjectRules", "fixtures/rbac/selfsubjectrules-admin.json",
                "clusterRoleBindings", "fixtures/rbac/clusterrolebindings-admin.json",
                "serviceAccounts", "fixtures/rbac/serviceaccounts-default.json"));

        assertTrue(findings.stream().anyMatch(f -> f.id().contains("current-identity.cluster-admin")));
        assertTrue(findings.stream().anyMatch(f -> f.id().contains("rbac.cluster-admin")));
    }

    @Test
    void runsWorkloadDetectorFromReusableFixtures() {
        List<Finding> findings = DetectorFixtureRunner.run(new WorkloadSecurityDetector(), ScanModule.WORKLOAD_SECURITY, Map.of(
                "pods", "fixtures/workloads/privileged-hostpath-pod.json"));

        assertTrue(findings.stream().anyMatch(f -> f.category().contains("privileged-container")));
        assertTrue(findings.stream().anyMatch(f -> f.category().contains("hostpath")));
    }

    @Test
    void runsNetworkDetectorFromReusableFixtures() {
        List<Finding> findings = DetectorFixtureRunner.run(new NetworkExposureDetector(), ScanModule.NETWORK_EXPOSURE, Map.of(
                "services", "fixtures/network/nodeport-public-endpoint.json",
                "endpoints", "fixtures/network/endpoints-public-ip.json",
                "networkPolicies", "fixtures/network/empty-list.json",
                "pods", "fixtures/workloads/privileged-hostpath-pod.json"));

        assertTrue(findings.stream().anyMatch(f -> f.category().contains("service-exposure")));
        assertTrue(findings.stream().anyMatch(f -> f.category().contains("endpoint-public-ip")));
    }

    @Test
    void runsCloudDetectorFromReusableFixturesWithFullEvidence() {
        List<Finding> findings = DetectorFixtureRunner.run(new CloudIdentityDetector(), ScanModule.CLOUD_CONTEXT, Map.of(
                "serviceAccounts", "fixtures/cloud/aws-irsa-serviceaccount.json",
                "pods", "fixtures/cloud/aws-irsa-pod.json",
                "nodes", "fixtures/cloud/aws-node.json",
                "namespaces", "fixtures/network/empty-list.json"));

        assertTrue(findings.stream().anyMatch(f -> f.id().equals("cloud.aws.irsa-present")));
        assertTrue(findings.toString().contains("live-aws-session-token"));
    }
}
