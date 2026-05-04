package com.k8spen.tool.core.model;

import java.util.List;

public record AttackPath(
        String id,
        String title,
        RiskLevel riskLevel,
        List<AttackPrerequisite> prerequisites,
        String reachableAction,
        String impact,
        String remediation,
        List<GraphNode> nodes,
        List<GraphEdge> edges) {

    public AttackPath {
        prerequisites = prerequisites == null ? List.of() : List.copyOf(prerequisites);
        nodes = nodes == null ? List.of() : List.copyOf(nodes);
        edges = edges == null ? List.of() : List.copyOf(edges);
    }
}
