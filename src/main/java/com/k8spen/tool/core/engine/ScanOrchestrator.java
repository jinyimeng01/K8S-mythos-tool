package com.k8spen.tool.core.engine;

import com.k8spen.tool.core.client.K8sApiClient;
import com.k8spen.tool.core.detector.CloudIdentityDetector;
import com.k8spen.tool.core.detector.ClusterProfileDetector;
import com.k8spen.tool.core.detector.IdentityRbacDetector;
import com.k8spen.tool.core.detector.NetworkExposureDetector;
import com.k8spen.tool.core.detector.ScanDetector;
import com.k8spen.tool.core.detector.SecretCredentialDetector;
import com.k8spen.tool.core.detector.WorkloadSecurityDetector;
import com.k8spen.tool.core.model.AttackPath;
import com.k8spen.tool.core.model.Finding;
import com.k8spen.tool.core.model.ReportBundle;
import com.k8spen.tool.core.model.ScanModule;
import com.k8spen.tool.core.model.ScanRequest;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class ScanOrchestrator {
    private final List<ScanDetector> detectors;
    private final AttackPathEngine attackPathEngine;

    public ScanOrchestrator() {
        this(List.of(
                new ClusterProfileDetector(),
                new IdentityRbacDetector(),
                new WorkloadSecurityDetector(),
                new SecretCredentialDetector(),
                new NetworkExposureDetector(),
                new CloudIdentityDetector()), new AttackPathEngine());
    }

    public ScanOrchestrator(List<ScanDetector> detectors, AttackPathEngine attackPathEngine) {
        this.detectors = detectors == null ? List.of() : List.copyOf(detectors);
        this.attackPathEngine = attackPathEngine == null ? new AttackPathEngine() : attackPathEngine;
    }

    public ReportBundle scan(ScanRequest request) {
        K8sApiClient client = new K8sApiClient(request.target(), request.auth());
        ScanSnapshot snapshot = collectSnapshot(request, client);
        List<Finding> findings = new ArrayList<>();
        for (ScanDetector detector : detectors) {
            findings.addAll(detector.detect(request, snapshot));
        }
        findings.sort(Comparator.comparing((Finding f) -> f.riskLevel().rank()).reversed()
                .thenComparing(Finding::module)
                .thenComparing(Finding::title));
        List<AttackPath> paths = request.enableAttackPath() ? attackPathEngine.build(findings) : List.of();
        String graphText = attackPathEngine.renderGraph(paths);
        return new ReportBundle(request, Instant.now(), snapshot.profile(), findings, paths, graphText);
    }

    private ScanSnapshot collectSnapshot(ScanRequest request, K8sApiClient client) {
        ScanSnapshot snapshot = new ScanSnapshot();
        snapshot.put("version", client.getVersion());
        snapshot.put("api", client.getApiRoot());
        snapshot.put("apis", client.getApiGroups());
        snapshot.put("anonymousApi", client.getAnonymous("/api"));

        if (request.isEnabled(ScanModule.CLUSTER_PROFILE) || request.isEnabled(ScanModule.CLOUD_CONTEXT)) {
            snapshot.put("nodes", client.listNodes());
            snapshot.put("namespaces", client.listNamespaces());
        }
        if (request.isEnabled(ScanModule.WORKLOAD_SECURITY)
                || request.isEnabled(ScanModule.CLUSTER_PROFILE)
                || request.isEnabled(ScanModule.CLOUD_CONTEXT)
                || request.isEnabled(ScanModule.NETWORK_EXPOSURE)) {
            snapshot.put("pods", client.listPods(request.namespaceScope()));
        }
        if (request.isEnabled(ScanModule.IDENTITY_RBAC)) {
            snapshot.put("selfSubjectRules", client.selfSubjectRulesReview(request.namespaceScope()));
            snapshot.put("clusterRoleBindings", client.listClusterRoleBindings());
            snapshot.put("serviceAccounts", client.listServiceAccounts());
        } else if (request.isEnabled(ScanModule.CLOUD_CONTEXT)) {
            snapshot.put("serviceAccounts", client.listServiceAccounts());
        }
        if (request.isEnabled(ScanModule.SECRET_CREDENTIAL)) {
            snapshot.put("secrets", client.listSecrets(request.namespaceScope()));
        }
        if (request.isEnabled(ScanModule.NETWORK_EXPOSURE)) {
            snapshot.put("services", client.listServices());
            snapshot.put("endpoints", client.listEndpoints());
            snapshot.put("networkPolicies", client.listNetworkPolicies());
        }
        return snapshot;
    }
}
