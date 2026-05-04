package com.k8spen.tool.core.model;

public enum ScanModule {
    CLUSTER_PROFILE("Cluster Profile"),
    IDENTITY_RBAC("Identity & RBAC"),
    WORKLOAD_SECURITY("Workload Security"),
    SECRET_CREDENTIAL("Secret & Credential Exposure"),
    NETWORK_EXPOSURE("Network & Exposure"),
    CLOUD_CONTEXT("Cloud Identity Context");

    private final String displayName;

    ScanModule(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }
}
