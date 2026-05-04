package com.k8spen.tool.core.detector;

import org.junit.jupiter.api.Test;
import com.k8spen.tool.core.model.Finding;
import com.k8spen.tool.core.model.ScanModule;
import com.k8spen.tool.test.DetectorFixtureRunner;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecretCredentialDetectorTest {
    @Test
    void detectsHighValueKeyNames() {
        assertTrue(SecretCredentialDetector.isHighValueKey("aws_secret_access_key"));
        assertTrue(SecretCredentialDetector.isHighValueKey("client-token"));
        assertTrue(SecretCredentialDetector.isHighValueKey("id_rsa"));
    }

    @Test
    void redactionDoesNotReturnOriginalSecretValue() {
        String secret = "very-sensitive-token-value";
        String redacted = SecretCredentialDetector.redactedValue(secret);

        assertNotEquals(secret, redacted);
        assertTrue(redacted.startsWith("redacted:sha256:"));
    }

    @Test
    void detectorEmitsFullEvidenceForSecretData() {
        List<Finding> findings = DetectorFixtureRunner.run(new SecretCredentialDetector(), ScanModule.SECRET_CREDENTIAL, Map.of(
                "secrets", "fixtures/secrets/service-account-token.json"));

        String evidence = findings.toString();
        assertTrue(evidence.contains("bGl2ZS1zZXJ2aWNlLWFjY291bnQtdG9rZW4="));
        assertTrue(evidence.contains("live-service-account-token"));
    }
}
