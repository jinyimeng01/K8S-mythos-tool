package com.k8spen.tool.controller;

import com.k8spen.tool.core.engine.ScanOrchestrator;
import com.k8spen.tool.core.model.AuthProfile;
import com.k8spen.tool.core.model.Finding;
import com.k8spen.tool.core.model.ReportBundle;
import com.k8spen.tool.core.model.RiskLevel;
import com.k8spen.tool.core.model.ScanModule;
import com.k8spen.tool.core.model.ScanRequest;
import com.k8spen.tool.core.model.TargetProfile;
import com.k8spen.tool.core.report.ReportRenderer;
import javafx.application.Platform;
import javafx.beans.property.ReadOnlyStringWrapper;
import javafx.collections.FXCollections;
import javafx.concurrent.Task;
import javafx.scene.control.CheckBox;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;

import java.io.File;
import java.nio.file.Files;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class AdvancedDetectionHandler {
    private final ControllerContext ctx;
    private final TextField namespaceScope;
    private final CheckBox clusterProfileModule, identityRbacModule, workloadSecurityModule;
    private final CheckBox secretCredentialModule, networkExposureModule, cloudContextModule;
    private final CheckBox enableCloud, enableAttackPaths;
    private final TableView<Finding> findingsTable;
    private final TableColumn<Finding, String> advColRisk, advColModule, advColTitle, advColResource;
    private final TextArea summaryOutput, clusterOutput, identityOutput, workloadOutput, networkOutput;
    private final TextArea cloudOutput, attackPathOutput, graphOutput, reportOutput;

    private final ScanOrchestrator orchestrator = new ScanOrchestrator();
    private final ReportRenderer reportRenderer = new ReportRenderer();
    private ReportBundle lastReport;

    public AdvancedDetectionHandler(ControllerContext ctx,
                                    TextField namespaceScope,
                                    CheckBox clusterProfileModule, CheckBox identityRbacModule,
                                    CheckBox workloadSecurityModule, CheckBox secretCredentialModule,
                                    CheckBox networkExposureModule, CheckBox cloudContextModule,
                                    CheckBox enableCloud, CheckBox enableAttackPaths,
                                    TableView<Finding> findingsTable,
                                    TableColumn<Finding, String> advColRisk,
                                    TableColumn<Finding, String> advColModule,
                                    TableColumn<Finding, String> advColTitle,
                                    TableColumn<Finding, String> advColResource,
                                    TextArea summaryOutput, TextArea clusterOutput,
                                    TextArea identityOutput, TextArea workloadOutput,
                                    TextArea networkOutput, TextArea cloudOutput,
                                    TextArea attackPathOutput, TextArea graphOutput,
                                    TextArea reportOutput) {
        this.ctx = ctx;
        this.namespaceScope = namespaceScope;
        this.clusterProfileModule = clusterProfileModule;
        this.identityRbacModule = identityRbacModule;
        this.workloadSecurityModule = workloadSecurityModule;
        this.secretCredentialModule = secretCredentialModule;
        this.networkExposureModule = networkExposureModule;
        this.cloudContextModule = cloudContextModule;
        this.enableCloud = enableCloud;
        this.enableAttackPaths = enableAttackPaths;
        this.findingsTable = findingsTable;
        this.advColRisk = advColRisk;
        this.advColModule = advColModule;
        this.advColTitle = advColTitle;
        this.advColResource = advColResource;
        this.summaryOutput = summaryOutput;
        this.clusterOutput = clusterOutput;
        this.identityOutput = identityOutput;
        this.workloadOutput = workloadOutput;
        this.networkOutput = networkOutput;
        this.cloudOutput = cloudOutput;
        this.attackPathOutput = attackPathOutput;
        this.graphOutput = graphOutput;
        this.reportOutput = reportOutput;
    }

    public void init() {
        clusterProfileModule.setSelected(true);
        identityRbacModule.setSelected(true);
        workloadSecurityModule.setSelected(true);
        secretCredentialModule.setSelected(true);
        networkExposureModule.setSelected(true);
        cloudContextModule.setSelected(true);
        enableCloud.setSelected(true);
        enableAttackPaths.setSelected(true);

        advColRisk.setCellValueFactory(c -> new ReadOnlyStringWrapper(c.getValue().riskLevel().label()));
        advColModule.setCellValueFactory(c -> new ReadOnlyStringWrapper(c.getValue().module().displayName()));
        advColTitle.setCellValueFactory(c -> new ReadOnlyStringWrapper(c.getValue().title()));
        advColResource.setCellValueFactory(c -> new ReadOnlyStringWrapper(c.getValue().resource()));
        findingsTable.getSelectionModel().selectedItemProperty().addListener((obs, oldVal, finding) -> {
            if (finding != null) reportOutput.setText(renderFindingDetail(finding));
        });
    }

    public void runScan() {
        String host = ctx.getHost();
        if (host == null || host.isBlank()) return;
        Set<ScanModule> modules = selectedModules();
        if (modules.isEmpty()) {
            summaryOutput.setText("[-] Select at least one detection module.");
            return;
        }
        TargetProfile target = TargetProfile.fromHost(host, ctx.getTimeout(), ctx.isSkipTls());
        ScanRequest request = ScanRequest.create(target, AuthProfile.bearer(ctx.getToken()), modules,
                namespaceScope.getText(), enableCloud.isSelected(), enableAttackPaths.isSelected());
        ctx.setStatus("Advanced Detection running...");
        ctx.log("[*] Advanced Detection scan started: " + target.apiServerUrl());
        clearOutputs("Scanning...\n\nFULL EVIDENCE MODE: exported reports may contain live credentials and secrets.\n");

        Task<ReportBundle> task = new Task<>() {
            @Override
            protected ReportBundle call() {
                return orchestrator.scan(request);
            }
        };
        task.setOnSucceeded(e -> {
            lastReport = task.getValue();
            renderReport(lastReport);
            ctx.setStatus("Advanced Detection complete: " + lastReport.findings().size() + " findings");
            ctx.log("[+] Advanced Detection scan completed");
        });
        task.setOnFailed(e -> {
            String message = task.getException() != null ? task.getException().getMessage() : "unknown error";
            summaryOutput.setText("[-] Advanced Detection failed: " + message);
            ctx.setStatus("Advanced Detection failed");
            ctx.log("[-] Advanced Detection failed: " + message);
        });
        new Thread(task).start();
    }

    public void exportHtml() { export("html"); }
    public void exportJson() { export("json"); }
    public void exportMarkdown() { export("md"); }

    private Set<ScanModule> selectedModules() {
        Set<ScanModule> modules = EnumSet.noneOf(ScanModule.class);
        if (clusterProfileModule.isSelected()) modules.add(ScanModule.CLUSTER_PROFILE);
        if (identityRbacModule.isSelected()) modules.add(ScanModule.IDENTITY_RBAC);
        if (workloadSecurityModule.isSelected()) modules.add(ScanModule.WORKLOAD_SECURITY);
        if (secretCredentialModule.isSelected()) modules.add(ScanModule.SECRET_CREDENTIAL);
        if (networkExposureModule.isSelected()) modules.add(ScanModule.NETWORK_EXPOSURE);
        if (cloudContextModule.isSelected()) modules.add(ScanModule.CLOUD_CONTEXT);
        return modules;
    }

    private void renderReport(ReportBundle bundle) {
        findingsTable.setItems(FXCollections.observableArrayList(bundle.findings()));
        summaryOutput.setText(renderSummary(bundle));
        clusterOutput.setText(renderModule(bundle, ScanModule.CLUSTER_PROFILE));
        identityOutput.setText(renderModule(bundle, ScanModule.IDENTITY_RBAC));
        workloadOutput.setText(renderModule(bundle, ScanModule.WORKLOAD_SECURITY) + "\n" + renderModule(bundle, ScanModule.SECRET_CREDENTIAL));
        networkOutput.setText(renderModule(bundle, ScanModule.NETWORK_EXPOSURE));
        cloudOutput.setText(renderCloudModule(bundle));
        attackPathOutput.setText(renderAttackPaths(bundle));
        graphOutput.setText(bundle.graphText());
        reportOutput.setText(reportRenderer.toMarkdown(bundle));
    }

    private String renderSummary(ReportBundle bundle) {
        int critical = count(bundle, RiskLevel.CRITICAL);
        int high = count(bundle, RiskLevel.HIGH);
        int medium = count(bundle, RiskLevel.MEDIUM);
        int low = count(bundle, RiskLevel.LOW);
        StringBuilder sb = new StringBuilder();
        sb.append("Advanced Detection Summary\n");
        sb.append("Target: ").append(bundle.request().target().apiServerUrl()).append("\n");
        sb.append("Completed: ").append(bundle.completedAt()).append("\n\n");
        sb.append("Risk counts: Critical=").append(critical).append(", High=").append(high)
                .append(", Medium=").append(medium).append(", Low=").append(low).append("\n");
        sb.append("Attack paths: ").append(bundle.attackPaths().size()).append("\n\n");
        sb.append("Cluster profile\n");
        for (Map.Entry<String, String> entry : bundle.clusterProfile().entrySet()) {
            sb.append("  ").append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
        }
        return sb.toString();
    }

    private String renderModule(ReportBundle bundle, ScanModule module) {
        StringBuilder sb = new StringBuilder();
        sb.append(module.displayName()).append("\n").append("=".repeat(module.displayName().length())).append("\n\n");
        int count = 0;
        for (Finding finding : bundle.findings()) {
            if (finding.module() == module) {
                sb.append(renderFindingBrief(finding)).append("\n");
                count++;
            }
        }
        if (count == 0) sb.append("(no findings)\n");
        return sb.toString();
    }

    private String renderCloudModule(ReportBundle bundle) {
        Map<String, List<Finding>> byProvider = new LinkedHashMap<>();
        for (Finding finding : bundle.findings()) {
            if (finding.module() != ScanModule.CLOUD_CONTEXT) continue;
            String provider = finding.evidence().isEmpty() ? "Unknown" : finding.evidence().get(0).source();
            byProvider.computeIfAbsent(provider, ignored -> new java.util.ArrayList<>()).add(finding);
        }
        StringBuilder sb = new StringBuilder("Cloud Identity Context\n======\n\n");
        if (byProvider.isEmpty()) return sb.append("(no findings)\n").toString();
        for (Map.Entry<String, List<Finding>> entry : byProvider.entrySet()) {
            sb.append("## ").append(entry.getKey()).append("\n\n");
            for (Finding finding : entry.getValue()) {
                sb.append(renderFindingBrief(finding)).append("\n");
            }
        }
        return sb.toString();
    }

    private String renderAttackPaths(ReportBundle bundle) {
        StringBuilder sb = new StringBuilder();
        for (var path : bundle.attackPaths()) {
            sb.append("[").append(path.riskLevel().label()).append("] ").append(path.title()).append("\n");
            sb.append("Reachable action: ").append(path.reachableAction()).append("\n");
            sb.append("Impact: ").append(path.impact()).append("\n");
            sb.append("Remediation: ").append(path.remediation()).append("\n\n");
        }
        if (bundle.attackPaths().isEmpty()) sb.append("(no attack paths generated)\n");
        return sb.toString();
    }

    private String renderFindingBrief(Finding finding) {
        return "[" + finding.riskLevel().label() + "] " + finding.title() + "\n"
                + "Resource: " + finding.resource() + "\n"
                + "Summary: " + finding.summary() + "\n"
                + "Remediation: " + finding.remediation() + "\n";
    }

    private String renderFindingDetail(Finding finding) {
        StringBuilder sb = new StringBuilder(renderFindingBrief(finding));
        sb.append("Module: ").append(finding.module().displayName()).append("\n");
        sb.append("Standard: ").append(finding.standard()).append("\n");
        sb.append("Evidence:\n");
        finding.evidence().forEach(e -> sb.append("  - ").append(e.source()).append(" ")
                .append(e.resource()).append(" ").append(e.field()).append(" = ").append(e.value()).append("\n"));
        return sb.toString();
    }

    private int count(ReportBundle bundle, RiskLevel level) {
        int count = 0;
        for (Finding finding : bundle.findings()) {
            if (finding.riskLevel() == level) count++;
        }
        return count;
    }

    private void clearOutputs(String text) {
        summaryOutput.setText(text);
        clusterOutput.setText(text);
        identityOutput.setText(text);
        workloadOutput.setText(text);
        networkOutput.setText(text);
        cloudOutput.setText(text);
        attackPathOutput.setText(text);
        graphOutput.setText(text);
        reportOutput.setText(text);
        findingsTable.setItems(FXCollections.observableArrayList());
    }

    private void export(String extension) {
        if (lastReport == null) {
            reportOutput.setText("[-] Run Advanced Detection first.");
            return;
        }
        String content = switch (extension) {
            case "html" -> reportRenderer.toHtml(lastReport);
            case "json" -> reportRenderer.toJson(lastReport);
            default -> reportRenderer.toMarkdown(lastReport);
        };
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Export K8S-mythos-tool Full Evidence Report");
        chooser.setInitialFileName("k8s-mythos-full-evidence-report." + extension);
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter(extension.toUpperCase() + " report", "*." + extension));
        File file = chooser.showSaveDialog(reportOutput.getScene().getWindow());
        if (file == null) return;
        try {
            Files.writeString(file.toPath(), content);
            Platform.runLater(() -> ctx.log("[+] Full evidence report exported: " + file.getAbsolutePath()));
        } catch (Exception e) {
            reportOutput.setText("[-] Export failed: " + e.getMessage());
            ctx.log("[-] Report export failed: " + e.getMessage());
        }
    }
}
