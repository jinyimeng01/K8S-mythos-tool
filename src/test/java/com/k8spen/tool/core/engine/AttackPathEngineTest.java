package com.k8spen.tool.core.engine;

import com.k8spen.tool.core.model.Finding;
import com.k8spen.tool.core.model.RiskLevel;
import com.k8spen.tool.core.model.ScanModule;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AttackPathEngineTest {
    @Test
    void buildsNodeContactPathFromPrivilegedFinding() {
        Finding finding = Finding.builder("workload.privileged.ns.pod", ScanModule.WORKLOAD_SECURITY,
                        RiskLevel.CRITICAL, "Container runs privileged")
                .category("privileged-container")
                .resource("default/pwn")
                .build();

        List<?> paths = new AttackPathEngine().build(List.of(finding));

        assertEquals(1, paths.size());
        assertTrue(paths.get(0).toString().contains("node contact"));
    }

    @Test
    void buildsProviderSpecificCloudPaths() {
        Finding workloadIdentity = Finding.builder("cloud.aws.irsa-present", ScanModule.CLOUD_CONTEXT,
                        RiskLevel.MEDIUM, "AWS IRSA role annotations are present")
                .category("cloud-workload-identity-aws")
                .resource("serviceaccounts")
                .build();
        Finding metadata = Finding.builder("cloud.generic.hostnetwork-metadata-reach", ScanModule.CLOUD_CONTEXT,
                        RiskLevel.MEDIUM, "Host-network pods may reach node metadata services")
                .category("cloud-metadata-reach-generic")
                .resource("pods")
                .build();
        Finding env = Finding.builder("cloud.aws.sdk-env-present", ScanModule.CLOUD_CONTEXT,
                        RiskLevel.HIGH, "AWS SDK credential environment variables are present")
                .category("cloud-credential-env-aws")
                .resource("pods")
                .build();

        List<?> paths = new AttackPathEngine().build(List.of(workloadIdentity, metadata, env));

        assertTrue(paths.toString().contains("workload identity"));
        assertTrue(paths.toString().contains("metadata identity"));
        assertTrue(paths.toString().contains("environment variables"));
    }
}
