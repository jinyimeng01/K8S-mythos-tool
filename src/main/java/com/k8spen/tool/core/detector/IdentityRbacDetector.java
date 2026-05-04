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
import java.util.List;

public class IdentityRbacDetector implements ScanDetector {
    @Override
    public List<Finding> detect(ScanRequest request, ScanSnapshot snapshot) {
        List<Finding> findings = new ArrayList<>();
        findings.addAll(clusterRoleBindingFindings(snapshot));
        findings.addAll(selfSubjectRuleFindings(request, snapshot));
        findings.addAll(serviceAccountFindings(snapshot));
        return findings;
    }

    private List<Finding> clusterRoleBindingFindings(ScanSnapshot snapshot) {
        List<Finding> findings = new ArrayList<>();
        JsonArray items = DetectorUtils.items(snapshot.object("clusterRoleBindings"));
        for (JsonElement e : items) {
            JsonObject binding = e.getAsJsonObject();
            JsonObject metadata = DetectorUtils.obj(binding, "metadata");
            JsonObject roleRef = DetectorUtils.obj(binding, "roleRef");
            String role = DetectorUtils.str(roleRef, "name");
            if (!"cluster-admin".equals(role)) continue;

            String bindingName = DetectorUtils.str(metadata, "name");
            JsonArray subjects = DetectorUtils.arr(binding, "subjects");
            for (JsonElement subjectEl : subjects) {
                JsonObject subject = subjectEl.getAsJsonObject();
                String kind = DetectorUtils.str(subject, "kind");
                String name = DetectorUtils.str(subject, "name");
                String namespace = DetectorUtils.str(subject, "namespace");
                String subjectLabel = kind + "/" + (namespace.isBlank() ? name : namespace + "/" + name);
                RiskLevel level = "ServiceAccount".equals(kind) && "default".equals(name) ? RiskLevel.CRITICAL : RiskLevel.HIGH;
                findings.add(Finding.builder("rbac.cluster-admin." + bindingName + "." + subjectLabel.replace('/', '.'),
                                ScanModule.IDENTITY_RBAC, level, "cluster-admin binding grants full cluster control")
                        .summary("ClusterRoleBinding " + bindingName + " binds cluster-admin to " + subjectLabel + ".")
                        .resource(subjectLabel)
                        .category("rbac-cluster-admin")
                        .standard("OWASP Kubernetes Top 10: RBAC and excessive privileges")
                        .remediation("Replace cluster-admin with least-privilege roles and remove default ServiceAccount high privilege bindings.")
                        .evidence(Evidence.of("clusterrolebindings", bindingName, "roleRef.name", role))
                        .evidence(Evidence.of("clusterrolebindings", bindingName, "subject", subjectLabel))
                        .build());
            }
        }
        return findings;
    }

    private List<Finding> selfSubjectRuleFindings(ScanRequest request, ScanSnapshot snapshot) {
        List<Finding> findings = new ArrayList<>();
        JsonObject review = snapshot.object("selfSubjectRules");
        JsonObject status = DetectorUtils.obj(review, "status");
        JsonArray rules = DetectorUtils.arr(status, "resourceRules");
        if (rules.size() == 0) return findings;

        boolean admin = can(rules, "*", "*");
        boolean createPods = can(rules, "create", "pods");
        boolean createExec = can(rules, "create", "pods/exec");
        boolean listSecrets = canAnyVerb(rules, new String[]{"get", "list", "watch"}, "secrets");
        boolean createRoles = can(rules, "create", "roles") || can(rules, "create", "clusterroles")
                || can(rules, "bind", "roles") || can(rules, "bind", "clusterroles");

        if (admin) {
            findings.add(Finding.builder("rbac.current-identity.cluster-admin", ScanModule.IDENTITY_RBAC,
                            RiskLevel.CRITICAL, "Current identity has wildcard resource permissions")
                    .summary("SelfSubjectRulesReview shows wildcard verbs and resources, equivalent to broad administrative control.")
                    .resource(request.auth().maskedIdentity())
                    .category("rbac-current-admin")
                    .standard("Kubernetes Security Checklist: least privilege")
                    .remediation("Use scoped roles and short-lived credentials for testing identities.")
                    .evidence(Evidence.of("selfsubjectrulesreviews", request.auth().maskedIdentity(), "resourceRules", "*/*"))
                    .build());
        }
        if (createPods && listSecrets) {
            findings.add(Finding.builder("rbac.current-identity.create-pods-read-secrets", ScanModule.IDENTITY_RBAC,
                            RiskLevel.HIGH, "Current identity can create Pods and read Secrets")
                    .summary("This permission combination can support credential harvesting and controlled workload placement.")
                    .resource(request.auth().maskedIdentity())
                    .category("rbac-create-pods-read-secrets")
                    .standard("OWASP Kubernetes Top 10: RBAC and secrets management")
                    .remediation("Split workload creation and secret-reading permissions across separate, tightly scoped identities.")
                    .evidence(Evidence.of("selfsubjectrulesreviews", request.auth().maskedIdentity(), "verbs/resources", "create pods + get/list secrets"))
                    .build());
        } else if (createPods || createExec || listSecrets || createRoles) {
            String capability = (createPods ? "create pods " : "") + (createExec ? "create pods/exec " : "")
                    + (listSecrets ? "read secrets " : "") + (createRoles ? "create/bind roles" : "");
            findings.add(Finding.builder("rbac.current-identity.sensitive-permissions", ScanModule.IDENTITY_RBAC,
                            RiskLevel.MEDIUM, "Current identity has sensitive Kubernetes permissions")
                    .summary("SelfSubjectRulesReview shows sensitive permission(s): " + capability.trim() + ".")
                    .resource(request.auth().maskedIdentity())
                    .category("rbac-sensitive")
                    .standard("Kubernetes Security Checklist: least privilege")
                    .remediation("Limit sensitive verbs and resources to identities that require them operationally.")
                    .evidence(Evidence.of("selfsubjectrulesreviews", request.auth().maskedIdentity(), "verbs/resources", capability.trim()))
                    .build());
        }
        return findings;
    }

    private List<Finding> serviceAccountFindings(ScanSnapshot snapshot) {
        List<Finding> findings = new ArrayList<>();
        JsonArray items = DetectorUtils.items(snapshot.object("serviceAccounts"));
        for (JsonElement e : items) {
            JsonObject sa = e.getAsJsonObject();
            String resource = DetectorUtils.namespacedName(sa);
            JsonArray secrets = DetectorUtils.arr(sa, "secrets");
            if ("default".equals(DetectorUtils.str(DetectorUtils.obj(sa, "metadata"), "name")) && secrets.size() > 0) {
                findings.add(Finding.builder("rbac.default-sa.static-token." + resource.replace('/', '.'),
                                ScanModule.IDENTITY_RBAC, RiskLevel.MEDIUM, "Default ServiceAccount has static Secret references")
                        .summary("The default ServiceAccount references Secret objects. In newer clusters this is uncommon and may indicate long-lived token exposure.")
                        .resource(resource)
                        .category("service-account-token")
                        .standard("Kubernetes ServiceAccount token hardening")
                        .remediation("Prefer projected bound tokens and disable automatic ServiceAccount token mounting for workloads that do not need API access.")
                        .evidence(Evidence.of("serviceaccounts", resource, "secrets.count", String.valueOf(secrets.size())))
                        .build());
            }
        }
        return findings;
    }

    public static boolean can(JsonArray rules, String verb, String resource) {
        for (JsonElement e : rules) {
            JsonObject rule = e.getAsJsonObject();
            JsonArray verbs = DetectorUtils.arr(rule, "verbs");
            JsonArray resources = DetectorUtils.arr(rule, "resources");
            if (DetectorUtils.arrayHasWildcardOr(verbs, verb) && DetectorUtils.arrayHasWildcardOr(resources, resource)) {
                return true;
            }
        }
        return false;
    }

    private static boolean canAnyVerb(JsonArray rules, String[] verbs, String resource) {
        for (String verb : verbs) {
            if (can(rules, verb, resource)) return true;
        }
        return false;
    }
}
