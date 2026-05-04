package com.k8spen.tool;

import com.k8spen.tool.core.model.AuthProfile;
import com.k8spen.tool.core.model.ReportBundle;
import com.k8spen.tool.core.model.ScanModule;
import com.k8spen.tool.core.model.ScanRequest;
import com.k8spen.tool.core.model.TargetProfile;
import com.k8spen.tool.core.report.ReportRenderer;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

class BrandingSmokeTest {
    @Test
    void mavenArtifactAndStartScriptUseMythosName() throws Exception {
        String pom = Files.readString(Path.of("pom.xml"));
        String start = Files.readString(Path.of("start.bat"));

        assertTrue(pom.contains("<artifactId>k8s-mythos-tool</artifactId>"));
        assertTrue(start.contains("target\\k8s-mythos-tool-1.0.0.jar"));
        assertTrue(start.contains("Starting K8S-mythos-tool"));
    }

    @Test
    void reportBrandingUsesMythosName() {
        ScanRequest request = ScanRequest.create(TargetProfile.fromHost("127.0.0.1", 5, true),
                AuthProfile.bearer("token"), EnumSet.of(ScanModule.CLUSTER_PROFILE), "", true, true);
        ReportBundle bundle = new ReportBundle(request, Instant.now(), Map.of(), List.of(), List.of(), "");

        String html = new ReportRenderer().toHtml(bundle);

        assertTrue(html.contains("K8S-mythos-tool Advanced Detection Report"));
    }
}
