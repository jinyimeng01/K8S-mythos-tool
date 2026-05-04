package com.k8spen.tool.core.model;

import java.util.ArrayList;
import java.util.List;

public record Finding(
        String id,
        ScanModule module,
        RiskLevel riskLevel,
        String title,
        String summary,
        String resource,
        String category,
        String standard,
        String remediation,
        List<Evidence> evidence) {

    public Finding {
        evidence = evidence == null ? List.of() : List.copyOf(evidence);
    }

    public static Builder builder(String id, ScanModule module, RiskLevel riskLevel, String title) {
        return new Builder(id, module, riskLevel, title);
    }

    public static final class Builder {
        private final String id;
        private final ScanModule module;
        private final RiskLevel riskLevel;
        private final String title;
        private String summary = "";
        private String resource = "";
        private String category = "";
        private String standard = "";
        private String remediation = "";
        private final List<Evidence> evidence = new ArrayList<>();

        private Builder(String id, ScanModule module, RiskLevel riskLevel, String title) {
            this.id = id;
            this.module = module;
            this.riskLevel = riskLevel;
            this.title = title;
        }

        public Builder summary(String summary) { this.summary = summary; return this; }
        public Builder resource(String resource) { this.resource = resource; return this; }
        public Builder category(String category) { this.category = category; return this; }
        public Builder standard(String standard) { this.standard = standard; return this; }
        public Builder remediation(String remediation) { this.remediation = remediation; return this; }
        public Builder evidence(Evidence item) { if (item != null) this.evidence.add(item); return this; }

        public Finding build() {
            return new Finding(id, module, riskLevel, title, summary, resource, category, standard, remediation, evidence);
        }
    }
}
