package com.k8spen.tool.core.model;

import java.time.Instant;
import java.util.EnumSet;
import java.util.Set;

public record ScanRequest(
        TargetProfile target,
        AuthProfile auth,
        Set<ScanModule> modules,
        String namespaceScope,
        boolean enableCloudDetectors,
        boolean enableAttackPath,
        Instant requestedAt) {

    public static ScanRequest create(TargetProfile target, AuthProfile auth, Set<ScanModule> modules,
                                     String namespaceScope, boolean enableCloudDetectors,
                                     boolean enableAttackPath) {
        Set<ScanModule> enabled = modules == null || modules.isEmpty()
                ? EnumSet.allOf(ScanModule.class)
                : EnumSet.copyOf(modules);
        return new ScanRequest(target, auth, enabled,
                namespaceScope == null ? "" : namespaceScope.trim(),
                enableCloudDetectors, enableAttackPath, Instant.now());
    }

    public boolean isEnabled(ScanModule module) {
        return modules.contains(module);
    }
}
