package com.k8spen.tool.core.client;

import com.k8spen.tool.core.model.AuthProfile;
import com.k8spen.tool.core.model.TargetProfile;
import com.k8spen.tool.utils.K8sHttpUtil;

public class K8sApiClient {

    private final TargetProfile target;
    private final AuthProfile auth;

    public K8sApiClient(TargetProfile target, AuthProfile auth) {
        this.target = target;
        this.auth = auth == null ? AuthProfile.bearer(null) : auth;
    }

    public ApiResponse get(String path) {
        return get(path, false);
    }

    public ApiResponse getAnonymous(String path) {
        return get(path, true);
    }

    public ApiResponse post(String path, String body) {
        return request(path, "POST", body, false);
    }

    public ApiResponse getVersion() { return get("/version"); }
    public ApiResponse getApiRoot() { return get("/api"); }
    public ApiResponse getApiGroups() { return get("/apis"); }
    public ApiResponse listNamespaces() { return get("/api/v1/namespaces"); }
    public ApiResponse listNodes() { return get("/api/v1/nodes"); }
    public ApiResponse listPods(String namespaceScope) {
        if (namespaceScope != null && !namespaceScope.isBlank()) {
            return get("/api/v1/namespaces/" + namespaceScope.trim() + "/pods");
        }
        return get("/api/v1/pods");
    }
    public ApiResponse listServices() { return get("/api/v1/services"); }
    public ApiResponse listEndpoints() { return get("/api/v1/endpoints"); }
    public ApiResponse listSecrets(String namespaceScope) {
        if (namespaceScope != null && !namespaceScope.isBlank()) {
            return get("/api/v1/namespaces/" + namespaceScope.trim() + "/secrets");
        }
        return get("/api/v1/secrets");
    }
    public ApiResponse listServiceAccounts() { return get("/api/v1/serviceaccounts"); }
    public ApiResponse listClusterRoleBindings() { return get("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"); }
    public ApiResponse listNetworkPolicies() { return get("/apis/networking.k8s.io/v1/networkpolicies"); }

    public ApiResponse selfSubjectRulesReview(String namespace) {
        String ns = namespace == null || namespace.isBlank() ? "default" : namespace.trim();
        String body = "{\"apiVersion\":\"authorization.k8s.io/v1\",\"kind\":\"SelfSubjectRulesReview\",\"spec\":{\"namespace\":\"" + ns + "\"}}";
        return post("/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", body);
    }

    private ApiResponse get(String path, boolean anonymous) {
        return request(path, "GET", null, anonymous);
    }

    private ApiResponse request(String path, String method, String body, boolean anonymous) {
        try {
            String token = anonymous ? null : auth.bearerToken();
            String raw;
            if ("POST".equals(method)) {
                raw = K8sHttpUtil.sendPost(target.resolve(path), body == null ? "{}" : body,
                        "application/json", token, target.timeoutSec(), target.skipTls());
            } else {
                raw = K8sHttpUtil.sendRequest(target.resolve(path), method, token, target.timeoutSec(), target.skipTls());
            }
            return ApiResponse.fromRaw(path, raw, anonymous);
        } catch (Exception e) {
            return ApiResponse.error(path, e.getMessage(), anonymous);
        }
    }
}
