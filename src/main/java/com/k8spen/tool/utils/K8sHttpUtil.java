package com.k8spen.tool.utils;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.security.cert.X509Certificate;

public class K8sHttpUtil {

    /**
     * Legacy escape hatch kept for old callers. New code should prefer the per-request
     * skipTls overloads so one unsafe request does not change JVM-wide TLS behavior.
     */
    @Deprecated
    public static void disableSslVerification() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                    }
            };
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HostnameVerifier allHostsValid = (hostname, session) -> true;
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String sendRequest(String urlStr, String method, String token, int timeoutSec) throws Exception {
        return sendRequest(urlStr, method, token, timeoutSec, true);
    }

    public static String sendRequest(String urlStr, String method, String token, int timeoutSec, boolean skipTls) throws Exception {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        if (skipTls && conn instanceof HttpsURLConnection) {
            applyUnsafeTls((HttpsURLConnection) conn);
        }
        conn.setRequestMethod(method);
        conn.setConnectTimeout(timeoutSec * 1000);
        conn.setReadTimeout(timeoutSec * 1000);
        conn.setRequestProperty("User-Agent", "K8S-mythos-tool/1.0");
        conn.setRequestProperty("Accept", "application/json");
        if (token != null && !token.trim().isEmpty()) {
            conn.setRequestProperty("Authorization", "Bearer " + token.trim());
        }

        int code;
        try {
            code = conn.getResponseCode();
        } catch (javax.net.ssl.SSLHandshakeException e) {
            throw e;
        } catch (Exception e) {
            throw new Exception("\u8fde\u63a5\u5931\u8d25: " + e.getMessage());
        }

        InputStream is = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
        if (is == null) {
            return "[HTTP " + code + "] (\u65e0\u54cd\u5e94\u4f53)";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("[HTTP ").append(code).append("]\n");
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, "UTF-8"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
        }
        return sb.toString();
    }

    public static String sendPost(String urlStr, String body, String contentType, String token, int timeoutSec) throws Exception {
        return sendPost(urlStr, body, contentType, token, timeoutSec, true);
    }

    public static String sendPost(String urlStr, String body, String contentType, String token, int timeoutSec, boolean skipTls) throws Exception {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        if (skipTls && conn instanceof HttpsURLConnection) {
            applyUnsafeTls((HttpsURLConnection) conn);
        }
        conn.setRequestMethod("POST");
        conn.setConnectTimeout(timeoutSec * 1000);
        conn.setReadTimeout(timeoutSec * 1000);
        conn.setDoOutput(true);
        conn.setRequestProperty("User-Agent", "K8S-mythos-tool/1.0");
        conn.setRequestProperty("Content-Type", contentType != null ? contentType : "application/json");
        if ("application/x-www-form-urlencoded".equals(contentType)) {
            conn.setRequestProperty("Accept", "*/*");
        } else {
            conn.setRequestProperty("Accept", "application/json");
        }
        if (token != null && !token.trim().isEmpty()) {
            conn.setRequestProperty("Authorization", "Bearer " + token.trim());
        }

        if (body != null) {
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes("UTF-8"));
            }
        }

        int code;
        try {
            code = conn.getResponseCode();
        } catch (Exception e) {
            throw new Exception("\u8fde\u63a5\u5931\u8d25: " + e.getMessage());
        }

        InputStream is = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
        if (is == null) {
            return "[HTTP " + code + "] (\u65e0\u54cd\u5e94\u4f53)";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("[HTTP ").append(code).append("]\n");
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, "UTF-8"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
        }
        return sb.toString();
    }

    private static void applyUnsafeTls(HttpsURLConnection conn) throws Exception {
        SSLContext sc = trustAllSslContext();
        conn.setSSLSocketFactory(sc.getSocketFactory());
        conn.setHostnameVerifier((hostname, session) -> true);
    }

    private static SSLContext trustAllSslContext() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
        };
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        return sc;
    }

    public static boolean isPortOpen(String host, int port, int timeoutSec) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutSec * 1000);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static String formatJson(String json) {
        if (json == null) return "";
        try {
            com.google.gson.Gson gson = new com.google.gson.GsonBuilder().setPrettyPrinting().create();
            Object obj = gson.fromJson(json, Object.class);
            return gson.toJson(obj);
        } catch (Exception e) {
            return json;
        }
    }
}
