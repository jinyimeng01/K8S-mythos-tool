package com.k8spen.tool.core.model;

public enum RiskLevel {
    CRITICAL(4, "Critical"),
    HIGH(3, "High"),
    MEDIUM(2, "Medium"),
    LOW(1, "Low"),
    INFO(0, "Info");

    private final int rank;
    private final String label;

    RiskLevel(int rank, String label) {
        this.rank = rank;
        this.label = label;
    }

    public int rank() {
        return rank;
    }

    public String label() {
        return label;
    }
}
