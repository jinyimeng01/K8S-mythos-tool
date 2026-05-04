package com.k8spen.tool.core.engine;

import com.k8spen.tool.core.model.AttackPath;
import com.k8spen.tool.core.model.AttackPrerequisite;
import com.k8spen.tool.core.model.Finding;
import com.k8spen.tool.core.model.GraphEdge;
import com.k8spen.tool.core.model.GraphNode;
import com.k8spen.tool.core.model.RiskLevel;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

public class AttackPathEngine {

    public List<AttackPath> build(List<Finding> findings) {
        List<AttackPath> paths = new ArrayList<>();
        if (any(findings, f -> f.id().contains("anonymous") && f.riskLevel().rank() >= RiskLevel.HIGH.rank())) {
            paths.add(path("path.anonymous.api", "Anonymous API access can seed cluster enumeration", RiskLevel.HIGH,
                    "Anonymous API discovery", "anonymous API response",
                    "Enumerate cluster resources available to anonymous users",
                    "Cluster shape disclosure can accelerate credential and workload targeting.",
                    "Disable anonymous API access and verify RBAC authorizer behavior.",
                    "Identity:anonymous", "Permission:api-discovery", "Resource:apiserver"));
        }
        if (any(findings, f -> f.category().contains("rbac-create-pods-read-secrets"))
                || (any(findings, f -> f.category().contains("rbac-current-admin")))) {
            paths.add(path("path.rbac.workload-to-secret", "Current identity can bridge workload control and credentials", RiskLevel.CRITICAL,
                    "Sensitive RBAC combination", "SelfSubjectRulesReview",
                    "Create or enter workloads, then access Secrets or mounted credentials",
                    "This can become credential expansion across namespaces or node-facing workloads.",
                    "Split permissions, remove wildcard access, and enforce least privilege.",
                    "Identity:current", "Permission:pods+secrets", "Resource:secrets"));
        }
        if (any(findings, f -> f.category().contains("privileged-container") || f.category().contains("hostpath") || f.category().contains("runtime-socket"))) {
            paths.add(path("path.workload.node-contact", "Workload configuration enables node contact", RiskLevel.CRITICAL,
                    "Privileged, hostPath, or runtime socket exposure", "Pod spec",
                    "Use compromised workload context to reach node filesystem or runtime surfaces",
                    "Node contact can lead to host credential exposure and control-plane pivoting in permissive environments.",
                    "Enforce Pod Security restricted/baseline policy and block sensitive host paths.",
                    "Identity:workload", "Permission:host-surface", "Resource:node"));
        }
        if (any(findings, f -> f.category().contains("secret-exposure"))) {
            paths.add(path("path.secret.credential-reuse", "Visible Secrets can enable credential reuse", RiskLevel.HIGH,
                    "Secret metadata or key access", "Secret list/get response",
                    "Use exposed credential material if read permission expands to data values",
                    "Credentials can unlock registries, service accounts, TLS identities, or external systems.",
                    "Reduce Secret read access, rotate sensitive values, and use short-lived workload identity where possible.",
                    "Identity:reader", "Permission:secret-read", "Resource:credential"));
        }
        if (any(findings, f -> f.category().contains("cloud-workload-identity"))) {
            paths.add(path("path.cloud.workload-identity", "Annotated Kubernetes identities can exchange into cloud roles", RiskLevel.HIGH,
                    "ServiceAccount or pod workload identity markers", "provider-specific annotations, labels, or projected tokens",
                    "Use a compromised workload identity to request provider cloud credentials",
                    "Cloud role permissions may affect storage, registry, IAM, managed Kubernetes, or other external resources.",
                    "Scope cloud trust policies to exact namespace/serviceAccount subjects and remove identity annotations from default accounts.",
                    "Identity:serviceaccount", "Permission:workload-identity-token", "Cloud Context:cloud-role"));
        }
        if (any(findings, f -> f.category().contains("cloud-metadata-reach"))) {
            paths.add(path("path.cloud.metadata-role", "hostNetwork workloads may reach cloud metadata identity", RiskLevel.HIGH,
                    "hostNetwork pod in cloud-like cluster", "pod spec and provider metadata indicators",
                    "Reach node or instance metadata from workload network context",
                    "Metadata credentials can expose node role permissions and expand impact beyond Kubernetes.",
                    "Block metadata endpoints from pods and avoid hostNetwork except for reviewed infrastructure workloads.",
                    "Identity:workload-network", "Permission:metadata-service", "Cloud Context:node-role"));
        }
        if (any(findings, f -> f.category().contains("cloud-credential-env"))) {
            paths.add(path("path.cloud.credential-env", "Cloud credential environment variables can seed external API access", RiskLevel.HIGH,
                    "Cloud SDK environment variables in Pod spec", "container env names and redacted values/valueFrom references",
                    "Recover or abuse cloud credential delivery paths after workload compromise",
                    "Environment-delivered cloud credentials can unlock external APIs or help pivot into cloud control planes.",
                    "Use workload identity instead of static keys, rotate exposed credentials, and remove secrets from environment variables.",
                    "Identity:pod", "Permission:env-credential", "Cloud Context:external-api"));
        }
        if (any(findings, f -> f.module().name().equals("CLOUD_CONTEXT") && f.riskLevel().rank() >= RiskLevel.MEDIUM.rank())) {
            paths.add(path("path.cloud.identity-inheritance", "Kubernetes workload context can inherit cloud permissions", RiskLevel.HIGH,
                    "Cloud identity indicators", "Node labels or ServiceAccount annotations",
                    "Pivot from pod or ServiceAccount context into cloud identity permissions",
                    "Cloud role permissions may affect storage, registry, IAM, or managed Kubernetes resources outside the cluster.",
                    "Scope cloud roles, harden metadata access, and review workload identity trust policies.",
                    "Identity:workload", "Permission:cloud-role", "Cloud Context:provider"));
        }
        return paths;
    }

    public String renderGraph(List<AttackPath> paths) {
        StringBuilder sb = new StringBuilder();
        for (AttackPath path : paths) {
            sb.append("[").append(path.riskLevel().label()).append("] ").append(path.title()).append("\n");
            for (GraphEdge edge : path.edges()) {
                sb.append("  ").append(edge.from()).append(" --").append(edge.label()).append("--> ").append(edge.to()).append("\n");
            }
            sb.append("\n");
        }
        return sb.toString();
    }

    private static AttackPath path(String id, String title, RiskLevel risk, String prerequisite, String evidence,
                                   String action, String impact, String remediation,
                                   String nodeA, String nodeB, String nodeC) {
        List<GraphNode> nodes = List.of(
                new GraphNode(nodeA, nodeA, nodeA.contains("Cloud") ? "Cloud Context" : "Identity", risk),
                new GraphNode(nodeB, nodeB, "Permission", risk),
                new GraphNode(nodeC, nodeC, nodeC.contains("Cloud") ? "Cloud Context" : "Resource", risk));
        List<GraphEdge> edges = List.of(
                new GraphEdge(nodeA, nodeB, "has"),
                new GraphEdge(nodeB, nodeC, "reaches"));
        return new AttackPath(id, title, risk, List.of(new AttackPrerequisite(prerequisite, evidence)),
                action, impact, remediation, nodes, edges);
    }

    private static boolean any(List<Finding> findings, Predicate<Finding> predicate) {
        if (findings == null) return false;
        for (Finding finding : findings) {
            if (predicate.test(finding)) return true;
        }
        return false;
    }
}
