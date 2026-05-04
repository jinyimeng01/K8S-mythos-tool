package com.k8spen.tool.core.model;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record ReportBundle(
        ScanRequest request,
        Instant completedAt,
        Map<String, String> clusterProfile,
        List<Finding> findings,
        List<AttackPath> attackPaths,
        String graphText) {

    public ReportBundle {
        clusterProfile = clusterProfile == null ? Map.of() : Map.copyOf(clusterProfile);
        findings = findings == null ? List.of() : List.copyOf(findings);
        attackPaths = attackPaths == null ? List.of() : List.copyOf(attackPaths);
        graphText = graphText == null ? "" : graphText;
    }
}
