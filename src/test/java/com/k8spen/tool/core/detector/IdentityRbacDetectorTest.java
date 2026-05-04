package com.k8spen.tool.core.detector;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IdentityRbacDetectorTest {
    @Test
    void canDetectsWildcardPermissions() {
        JsonArray rules = JsonParser.parseString("""
                [{
                  "verbs": ["*"],
                  "resources": ["*"]
                }]
                """).getAsJsonArray();

        assertTrue(IdentityRbacDetector.can(rules, "create", "pods"));
        assertTrue(IdentityRbacDetector.can(rules, "get", "secrets"));
    }

    @Test
    void canDetectsSpecificPermissionAndRejectsMissingResource() {
        JsonObject rule = new JsonObject();
        JsonArray verbs = new JsonArray();
        verbs.add("create");
        JsonArray resources = new JsonArray();
        resources.add("pods");
        rule.add("verbs", verbs);
        rule.add("resources", resources);
        JsonArray rules = new JsonArray();
        rules.add(rule);

        assertTrue(IdentityRbacDetector.can(rules, "create", "pods"));
        assertFalse(IdentityRbacDetector.can(rules, "list", "secrets"));
    }
}
