package com.k8spen.tool.core.detector;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.k8spen.tool.core.engine.ScanSnapshot;
import com.k8spen.tool.core.model.Evidence;
import com.k8spen.tool.core.model.Finding;
import com.k8spen.tool.core.model.RiskLevel;
import com.k8spen.tool.core.model.ScanModule;
import com.k8spen.tool.core.model.ScanRequest;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class NetworkExposureDetector implements ScanDetector {
    @Override
    public List<Finding> detect(ScanRequest request, ScanSnapshot snapshot) {
        List<Finding> findings = new ArrayList<>();
        findings.addAll(serviceFindings(snapshot));
        findings.addAll(networkPolicyFindings(snapshot));
        findings.addAll(endpointFindings(snapshot));
        return findings;
    }

    private List<Finding> serviceFindings(ScanSnapshot snapshot) {
        List<Finding> findings = new ArrayList<>();
        JsonArray services = DetectorUtils.items(snapshot.object("services"));
        for (JsonElement e : services) {
            JsonObject service = e.getAsJsonObject();
            String resource = DetectorUtils.namespacedName(service);
            JsonObject spec = DetectorUtils.obj(service, "spec");
            String type = DetectorUtils.str(spec, "type");
            if ("NodePort".equals(type) || "LoadBalancer".equals(type)) {
                RiskLevel level = "LoadBalancer".equals(type) ? RiskLevel.HIGH : RiskLevel.MEDIUM;
                findings.add(Finding.builder("network.service.exposed." + safe(resource), ScanModule.NETWORK_EXPOSURE,
                                level, "Service exposes workload outside cluster network")
                        .summary("Service " + resource + " uses type " + type + ", expanding externally reachable surface.")
                        .resource(resource)
                        .category("service-exposure")
                        .standard("Kubernetes Security Checklist: network exposure")
                        .remediation("Restrict exposed services to explicit ingress paths and validate firewall/source restrictions.")
                        .evidence(Evidence.of("services", resource, "spec.type", type))
                        .evidence(Evidence.of("services", resource, "spec.ports", portSummary(DetectorUtils.arr(spec, "ports"))))
                        .build());
            }
        }
        return findings;
    }

    private List<Finding> networkPolicyFindings(ScanSnapshot snapshot) {
        List<Finding> findings = new ArrayList<>();
        Set<String> podNamespaces = new HashSet<>();
        for (JsonElement e : DetectorUtils.items(snapshot.object("pods"))) {
            String ns = DetectorUtils.str(DetectorUtils.obj(e.getAsJsonObject(), "metadata"), "namespace");
            if (!ns.isBlank()) podNamespaces.add(ns);
        }
        Set<String> policyNamespaces = new HashSet<>();
        for (JsonElement e : DetectorUtils.items(snapshot.object("networkPolicies"))) {
            String ns = DetectorUtils.str(DetectorUtils.obj(e.getAsJsonObject(), "metadata"), "namespace");
            if (!ns.isBlank()) policyNamespaces.add(ns);
        }
        for (String ns : podNamespaces) {
            if (!policyNamespaces.contains(ns)) {
                findings.add(Finding.builder("network.policy.missing." + ns, ScanModule.NETWORK_EXPOSURE,
                                RiskLevel.MEDIUM, "Namespace has workloads but no NetworkPolicy")
                        .summary("Namespace " + ns + " contains pods and no NetworkPolicy objects were observed.")
                        .resource(ns)
                        .category("networkpolicy-missing")
                        .standard("Kubernetes Security Checklist: network segmentation")
                        .remediation("Add default-deny NetworkPolicy and explicit allow rules for required traffic.")
                        .evidence(Evidence.of("networkpolicies", ns, "policy.count", "0"))
                        .build());
            }
        }
        return findings;
    }

    private List<Finding> endpointFindings(ScanSnapshot snapshot) {
        List<Finding> findings = new ArrayList<>();
        JsonArray endpoints = DetectorUtils.items(snapshot.object("endpoints"));
        for (JsonElement e : endpoints) {
            JsonObject endpoint = e.getAsJsonObject();
            String resource = DetectorUtils.namespacedName(endpoint);
            for (JsonElement subsetEl : DetectorUtils.arr(endpoint, "subsets")) {
                JsonObject subset = subsetEl.getAsJsonObject();
                for (JsonElement addrEl : DetectorUtils.arr(subset, "addresses")) {
                    String ip = DetectorUtils.str(addrEl.getAsJsonObject(), "ip");
                    if (!ip.isBlank() && !isPrivateIp(ip)) {
                        findings.add(Finding.builder("network.endpoint.public-ip." + safe(resource) + "." + safe(ip),
                                        ScanModule.NETWORK_EXPOSURE, RiskLevel.MEDIUM, "Endpoint points to a public IP")
                                .summary("Endpoint " + resource + " includes " + ip + ", which is outside common private ranges.")
                                .resource(resource)
                                .category("endpoint-public-ip")
                                .standard("Kubernetes Security Checklist: network exposure")
                                .remediation("Verify this endpoint is intentional and restrict egress/ingress paths around it.")
                                .evidence(Evidence.of("endpoints", resource, "subsets.addresses.ip", ip))
                                .build());
                    }
                }
            }
        }
        return findings;
    }

    private static String portSummary(JsonArray ports) {
        StringBuilder sb = new StringBuilder();
        for (JsonElement e : ports) {
            JsonObject port = e.getAsJsonObject();
            if (sb.length() > 0) sb.append(", ");
            sb.append(DetectorUtils.str(port, "protocol")).append("/").append(DetectorUtils.str(port, "port"));
            if (port.has("nodePort")) sb.append("->").append(DetectorUtils.str(port, "nodePort"));
        }
        return sb.toString();
    }

    private static boolean isPrivateIp(String ip) {
        return ip.startsWith("10.") || ip.startsWith("192.168.") || ip.matches("^172\\.(1[6-9]|2[0-9]|3[0-1])\\..*")
                || ip.startsWith("127.") || ip.startsWith("169.254.") || ip.equals("::1");
    }

    private static String safe(String value) {
        return value == null ? "unknown" : value.replaceAll("[^A-Za-z0-9_.-]", ".");
    }
}
