package com.k8spen.tool.core.client;

public record ApiResponse(String path, int statusCode, String body, String error, boolean anonymous) {

    public boolean isSuccess() {
        return statusCode >= 200 && statusCode < 300 && error.isEmpty();
    }

    public boolean isForbiddenOrUnauthorized() {
        return statusCode == 401 || statusCode == 403;
    }

    public static ApiResponse fromRaw(String path, String raw, boolean anonymous) {
        if (raw == null) return new ApiResponse(path, -1, "", "empty response", anonymous);
        String text = raw.trim();
        int code = -1;
        String body = text;
        if (text.startsWith("[HTTP")) {
            int end = text.indexOf(']');
            if (end > 5) {
                try {
                    code = Integer.parseInt(text.substring(6, end).trim());
                } catch (NumberFormatException ignored) {
                    code = -1;
                }
            }
            int nl = text.indexOf('\n');
            body = nl >= 0 ? text.substring(nl + 1).trim() : "";
        }
        return new ApiResponse(path, code, body, "", anonymous);
    }

    public static ApiResponse error(String path, String error, boolean anonymous) {
        return new ApiResponse(path, -1, "", error == null ? "" : error, anonymous);
    }
}
