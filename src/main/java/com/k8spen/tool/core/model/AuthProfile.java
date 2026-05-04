package com.k8spen.tool.core.model;

public record AuthProfile(String bearerToken, String username, String password) {

    public static AuthProfile bearer(String token) {
        return new AuthProfile(trimToNull(token), null, null);
    }

    public boolean hasBearerToken() {
        return bearerToken != null && !bearerToken.isEmpty();
    }

    public String maskedIdentity() {
        if (hasBearerToken()) {
            return "Bearer redacted:sha256:" + sha256Short(bearerToken);
        }
        if (username != null && !username.isEmpty()) return username;
        return "anonymous";
    }

    private static String trimToNull(String value) {
        if (value == null) return null;
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static String sha256Short(String value) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(hash).substring(0, 16);
        } catch (Exception e) {
            return "hash-error";
        }
    }
}
