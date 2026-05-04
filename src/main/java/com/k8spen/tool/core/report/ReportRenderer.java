package com.k8spen.tool.core.report;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonPrimitive;
import com.k8spen.tool.core.model.AttackPath;
import com.k8spen.tool.core.model.EvidenceExposureMode;
import com.k8spen.tool.core.model.Evidence;
import com.k8spen.tool.core.model.Finding;
import com.k8spen.tool.core.model.ReportBundle;
import com.k8spen.tool.core.model.RiskLevel;

import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class ReportRenderer {
    private static final String PRODUCT_NAME = "K8S-mythos-tool";
    private static final EvidenceExposureMode EVIDENCE_EXPOSURE_MODE = EvidenceExposureMode.FULL;
    private static final Gson GSON = new GsonBuilder()
            .registerTypeAdapter(java.time.Instant.class,
                    (com.google.gson.JsonSerializer<java.time.Instant>) (src, typeOfSrc, context) -> new JsonPrimitive(src.toString()))
            .setPrettyPrinting()
            .create();

    public String toJson(ReportBundle bundle) {
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("product", PRODUCT_NAME);
        report.put("evidenceExposureMode", EVIDENCE_EXPOSURE_MODE.name());
        report.put("fullEvidenceWarning", "This report may contain live secrets, tokens, certificates, passwords, and cloud credentials.");
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("target", bundle.request().target().apiServerUrl());
        request.put("timeoutSec", bundle.request().target().timeoutSec());
        request.put("skipTls", bundle.request().target().skipTls());
        Map<String, Object> auth = new LinkedHashMap<>();
        auth.put("bearerToken", bundle.request().auth().bearerToken());
        auth.put("username", bundle.request().auth().username());
        auth.put("password", bundle.request().auth().password());
        request.put("auth", auth);
        request.put("modules", bundle.request().modules());
        request.put("namespaceScope", bundle.request().namespaceScope());
        request.put("enableCloudDetectors", bundle.request().enableCloudDetectors());
        request.put("enableAttackPath", bundle.request().enableAttackPath());
        request.put("requestedAt", bundle.request().requestedAt());
        report.put("request", request);
        report.put("completedAt", bundle.completedAt());
        report.put("clusterProfile", bundle.clusterProfile());
        report.put("findings", bundle.findings());
        report.put("cloudIdentityContext", cloudFindingsByProvider(bundle));
        report.put("attackPaths", bundle.attackPaths());
        report.put("graphText", bundle.graphText());
        return GSON.toJson(report);
    }

    public String toMarkdown(ReportBundle bundle) {
        StringBuilder sb = new StringBuilder();
        sb.append("# K8S-mythos-tool Advanced Detection Report\n\n");
        sb.append("> FULL EVIDENCE MODE: this report may contain live secrets, tokens, certificates, passwords, and cloud credentials.\n\n");
        sb.append("- Target: `").append(bundle.request().target().apiServerUrl()).append("`\n");
        sb.append("- Evidence Exposure: `").append(EVIDENCE_EXPOSURE_MODE.name()).append("`\n");
        sb.append("- Bearer Token: `").append(nullToEmpty(bundle.request().auth().bearerToken())).append("`\n");
        sb.append("- Username: `").append(nullToEmpty(bundle.request().auth().username())).append("`\n");
        sb.append("- Password: `").append(nullToEmpty(bundle.request().auth().password())).append("`\n");
        sb.append("- Completed: `").append(bundle.completedAt()).append("`\n");
        sb.append("- Findings: `").append(bundle.findings().size()).append("`\n");
        sb.append("- Attack Paths: `").append(bundle.attackPaths().size()).append("`\n\n");
        sb.append("## Summary\n\n");
        for (Map.Entry<RiskLevel, Integer> entry : countByRisk(bundle).entrySet()) {
            sb.append("- ").append(entry.getKey().label()).append(": ").append(entry.getValue()).append("\n");
        }
        sb.append("\n## Findings\n\n");
        for (Finding finding : bundle.findings()) {
            sb.append("### [").append(finding.riskLevel().label()).append("] ").append(finding.title()).append("\n\n");
            sb.append("- Resource: `").append(finding.resource()).append("`\n");
            sb.append("- Module: `").append(finding.module().displayName()).append("`\n");
            sb.append("- Standard: ").append(finding.standard()).append("\n");
            sb.append("- Summary: ").append(finding.summary()).append("\n");
            sb.append("- Remediation: ").append(finding.remediation()).append("\n\n");
            if (!finding.evidence().isEmpty()) {
                sb.append("Evidence:\n");
                for (Evidence evidence : finding.evidence()) {
                    sb.append("- `").append(evidence.source()).append("` `").append(evidence.resource()).append("` `")
                            .append(evidence.field()).append("` = `").append(evidence.value()).append("`\n");
                }
                sb.append("\n");
            }
        }
        appendCloudContextMarkdown(sb, bundle);
        sb.append("## Attack Paths\n\n");
        for (AttackPath path : bundle.attackPaths()) {
            sb.append("### [").append(path.riskLevel().label()).append("] ").append(path.title()).append("\n\n");
            sb.append("- Reachable action: ").append(path.reachableAction()).append("\n");
            sb.append("- Impact: ").append(path.impact()).append("\n");
            sb.append("- Remediation: ").append(path.remediation()).append("\n\n");
        }
        return sb.toString();
    }

    public String toHtml(ReportBundle bundle) {
        StringBuilder sb = new StringBuilder();
        sb.append("<!doctype html><html><head><meta charset=\"utf-8\"><title>K8S-mythos-tool Report</title>");
        sb.append("<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#081118;color:#e2e8f0}");
        sb.append("h1,h2{margin:0 0 12px}.meta,.card,.warning{background:#101b25;border:1px solid #294154;border-radius:10px;padding:14px;margin:12px 0}");
        sb.append(".warning{border-color:#f59e0b;color:#fde68a}.risk{font-weight:800}.CRITICAL{color:#fb7185}.HIGH{color:#f97316}.MEDIUM{color:#facc15}.LOW{color:#38bdf8}.INFO{color:#94a3b8}");
        sb.append("code{background:#172536;color:#dbeafe;padding:2px 5px;border-radius:4px}pre{white-space:pre-wrap;background:#030712;color:#e2e8f0;padding:12px;border-radius:8px}</style></head><body>");
        sb.append("<h1>K8S-mythos-tool Advanced Detection Report</h1>");
        sb.append("<div class=\"warning\"><b>FULL EVIDENCE MODE:</b> this report may contain live secrets, tokens, certificates, passwords, and cloud credentials.</div>");
        sb.append("<div class=\"meta\">Target: <code>").append(escape(bundle.request().target().apiServerUrl())).append("</code><br>");
        sb.append("Evidence Exposure: <code>").append(EVIDENCE_EXPOSURE_MODE.name()).append("</code><br>");
        sb.append("Bearer Token: <code>").append(escape(nullToEmpty(bundle.request().auth().bearerToken()))).append("</code><br>");
        sb.append("Username: <code>").append(escape(nullToEmpty(bundle.request().auth().username()))).append("</code><br>");
        sb.append("Password: <code>").append(escape(nullToEmpty(bundle.request().auth().password()))).append("</code><br>");
        sb.append("Completed: <code>").append(bundle.completedAt()).append("</code><br>");
        sb.append("Findings: <code>").append(bundle.findings().size()).append("</code> Attack Paths: <code>").append(bundle.attackPaths().size()).append("</code></div>");
        sb.append("<h2>Findings</h2>");
        for (Finding finding : bundle.findings()) {
            sb.append("<div class=\"card\"><div class=\"risk ").append(finding.riskLevel().name()).append("\">")
                    .append(finding.riskLevel().label()).append("</div><h3>").append(escape(finding.title())).append("</h3>");
            sb.append("<p>").append(escape(finding.summary())).append("</p><p><b>Resource:</b> <code>")
                    .append(escape(finding.resource())).append("</code></p><p><b>Remediation:</b> ")
                    .append(escape(finding.remediation())).append("</p>");
            if (!finding.evidence().isEmpty()) {
                sb.append("<ul>");
                for (Evidence evidence : finding.evidence()) {
                    sb.append("<li><code>").append(escape(evidence.source())).append("</code> ")
                            .append(escape(evidence.resource())).append(" ")
                            .append(escape(evidence.field())).append(" = <code>")
                            .append(escape(evidence.value())).append("</code></li>");
                }
                sb.append("</ul>");
            }
            sb.append("</div>");
        }
        appendCloudContextHtml(sb, bundle);
        sb.append("<h2>Attack Paths</h2>");
        for (AttackPath path : bundle.attackPaths()) {
            sb.append("<div class=\"card\"><div class=\"risk ").append(path.riskLevel().name()).append("\">")
                    .append(path.riskLevel().label()).append("</div><h3>").append(escape(path.title())).append("</h3>");
            sb.append("<p><b>Action:</b> ").append(escape(path.reachableAction())).append("</p>");
            sb.append("<p><b>Impact:</b> ").append(escape(path.impact())).append("</p>");
            sb.append("<p><b>Remediation:</b> ").append(escape(path.remediation())).append("</p></div>");
        }
        sb.append("<h2>Graph</h2><pre>").append(escape(bundle.graphText())).append("</pre>");
        sb.append("</body></html>");
        return sb.toString();
    }

    private static void appendCloudContextMarkdown(StringBuilder sb, ReportBundle bundle) {
        Map<String, List<Finding>> groups = cloudFindingsByProvider(bundle);
        if (groups.isEmpty()) return;
        sb.append("## Cloud Identity Context\n\n");
        for (Map.Entry<String, List<Finding>> entry : groups.entrySet()) {
            sb.append("### ").append(entry.getKey()).append("\n\n");
            for (Finding finding : entry.getValue()) {
                sb.append("- [").append(finding.riskLevel().label()).append("] ").append(finding.title())
                        .append(" - `").append(finding.resource()).append("`\n");
                for (Evidence evidence : finding.evidence()) {
                    sb.append("  - Evidence: `").append(evidence.field()).append("` = `")
                            .append(evidence.value()).append("`\n");
                }
            }
            sb.append("\n");
        }
    }

    private static void appendCloudContextHtml(StringBuilder sb, ReportBundle bundle) {
        Map<String, List<Finding>> groups = cloudFindingsByProvider(bundle);
        if (groups.isEmpty()) return;
        sb.append("<h2>Cloud Identity Context</h2>");
        for (Map.Entry<String, List<Finding>> entry : groups.entrySet()) {
            sb.append("<div class=\"card\"><h3>").append(escape(entry.getKey())).append("</h3><ul>");
            for (Finding finding : entry.getValue()) {
                sb.append("<li><span class=\"risk ").append(finding.riskLevel().name()).append("\">")
                        .append(finding.riskLevel().label()).append("</span> ")
                        .append(escape(finding.title())).append(" <code>")
                        .append(escape(finding.resource())).append("</code>");
                if (!finding.evidence().isEmpty()) {
                    sb.append("<ul>");
                    for (Evidence evidence : finding.evidence()) {
                        sb.append("<li><code>").append(escape(evidence.field())).append("</code> = <code>")
                                .append(escape(evidence.value())).append("</code></li>");
                    }
                    sb.append("</ul>");
                }
                sb.append("</li>");
            }
            sb.append("</ul></div>");
        }
    }

    private static Map<String, List<Finding>> cloudFindingsByProvider(ReportBundle bundle) {
        Map<String, List<Finding>> groups = new LinkedHashMap<>();
        for (Finding finding : bundle.findings()) {
            if (!"CLOUD_CONTEXT".equals(finding.module().name())) continue;
            String provider = finding.evidence().isEmpty() ? "Unknown" : finding.evidence().get(0).source();
            groups.computeIfAbsent(provider, ignored -> new java.util.ArrayList<>()).add(finding);
        }
        return groups;
    }

    private static Map<RiskLevel, Integer> countByRisk(ReportBundle bundle) {
        Map<RiskLevel, Integer> counts = new EnumMap<>(RiskLevel.class);
        for (RiskLevel level : RiskLevel.values()) counts.put(level, 0);
        for (Finding finding : bundle.findings()) {
            counts.put(finding.riskLevel(), counts.get(finding.riskLevel()) + 1);
        }
        return counts;
    }

    private static String escape(String value) {
        if (value == null) return "";
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
