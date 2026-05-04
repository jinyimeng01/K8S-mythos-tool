package com.k8spen.tool.core.model;

public record Evidence(String source, String resource, String field, String value) {
    public static Evidence of(String source, String resource, String field, String value) {
        return new Evidence(nullToEmpty(source), nullToEmpty(resource), nullToEmpty(field), nullToEmpty(value));
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
