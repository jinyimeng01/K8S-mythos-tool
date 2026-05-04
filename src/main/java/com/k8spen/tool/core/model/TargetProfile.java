package com.k8spen.tool.core.model;

public record TargetProfile(String host, String apiServerUrl, int timeoutSec, boolean skipTls) {

    public static TargetProfile fromHost(String host, int timeoutSec, boolean skipTls) {
        String cleanHost = host == null ? "" : host.trim();
        String url = cleanHost;
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "https://" + url;
        }
        if (!hasExplicitPort(url)) {
            url = url + ":6443";
        }
        return new TargetProfile(cleanHost, url, timeoutSec <= 0 ? 5 : timeoutSec, skipTls);
    }

    public String resolve(String path) {
        String p = path == null || path.isEmpty() ? "/" : path;
        if (!p.startsWith("/")) p = "/" + p;
        return apiServerUrl + p;
    }

    private static boolean hasExplicitPort(String url) {
        int scheme = url.indexOf("://");
        String hostPart = scheme >= 0 ? url.substring(scheme + 3) : url;
        int slash = hostPart.indexOf('/');
        if (slash >= 0) hostPart = hostPart.substring(0, slash);
        return hostPart.lastIndexOf(':') > hostPart.lastIndexOf(']');
    }
}
