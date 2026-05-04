package com.k8spen.tool.core.report;

import com.k8spen.tool.core.model.AuthProfile;
import com.k8spen.tool.core.model.Evidence;
import com.k8spen.tool.core.model.Finding;
import com.k8spen.tool.core.model.ReportBundle;
import com.k8spen.tool.core.model.RiskLevel;
import com.k8spen.tool.core.model.ScanModule;
import com.k8spen.tool.core.model.ScanRequest;
import com.k8spen.tool.core.model.TargetProfile;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReportRendererTest {
    @Test
    void serializesMarkdownHtmlAndJson() {
        ScanRequest request = ScanRequest.create(TargetProfile.fromHost("127.0.0.1", 5, true),
                AuthProfile.bearer("super-secret-token-value"), EnumSet.allOf(ScanModule.class), "", true, true);
        Finding finding = Finding.builder("id", ScanModule.WORKLOAD_SECURITY, RiskLevel.HIGH, "HostPath")
                .summary("summary")
                .resource("default/pod")
                .remediation("fix")
                .build();
        Finding cloud = Finding.builder("cloud.aws.irsa-present", ScanModule.CLOUD_CONTEXT, RiskLevel.MEDIUM,
                        "AWS IRSA role annotations are present")
                .summary("cloud summary")
                .resource("serviceaccounts")
                .category("cloud-workload-identity-aws")
                .remediation("review IAM role trust")
                .evidence(Evidence.of("AWS", "serviceaccounts", "metadata.annotations.eks.amazonaws.com/role-arn",
                        "arn:aws:iam::123456789012:role/app"))
                .evidence(Evidence.of("AWS", "pods", "env.AWS_SESSION_TOKEN",
                        "<script>alert('token')</script>"))
                .build();
        ReportBundle bundle = new ReportBundle(request, Instant.now(), Map.of("Pod Count", "1"),
                List.of(finding, cloud), List.of(), "");
        ReportRenderer renderer = new ReportRenderer();

        assertTrue(renderer.toMarkdown(bundle).contains("HostPath"));
        assertTrue(renderer.toMarkdown(bundle).contains("Cloud Identity Context"));
        assertTrue(renderer.toHtml(bundle).contains("K8S-mythos-tool Advanced Detection Report"));
        assertTrue(renderer.toMarkdown(bundle).contains("super-secret-token-value"));
        assertTrue(renderer.toMarkdown(bundle).contains("<script>alert('token')</script>"));
        assertTrue(renderer.toHtml(bundle).contains("&lt;script&gt;alert(&#39;token&#39;)&lt;/script&gt;"));
        String json = renderer.toJson(bundle);
        assertTrue(json.contains("\"findings\""));
        assertTrue(json.contains("\"cloudIdentityContext\""));
        assertTrue(json.contains("\"evidenceExposureMode\": \"FULL\""));
        assertTrue(json.contains("super-secret-token-value"));
        assertFalse(renderer.toHtml(bundle).contains("<script>alert('token')</script>"));
    }
}
