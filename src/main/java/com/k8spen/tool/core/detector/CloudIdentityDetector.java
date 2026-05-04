package com.k8spen.tool.core.detector;

import com.k8spen.tool.core.engine.ScanSnapshot;
import com.k8spen.tool.core.model.Finding;
import com.k8spen.tool.core.model.ScanRequest;

import java.util.ArrayList;
import java.util.List;

public class CloudIdentityDetector implements ScanDetector {
    private final List<CloudContextDetector> providers;

    public CloudIdentityDetector() {
        this(List.of(
                new AwsCloudContextDetector(),
                new GcpCloudContextDetector(),
                new AzureCloudContextDetector(),
                new AlibabaCloudContextDetector(),
                new GenericCloudContextDetector()));
    }

    public CloudIdentityDetector(List<CloudContextDetector> providers) {
        this.providers = providers == null ? List.of() : List.copyOf(providers);
    }

    @Override
    public List<Finding> detect(ScanRequest request, ScanSnapshot snapshot) {
        if (!request.enableCloudDetectors()) return List.of();
        List<Finding> findings = new ArrayList<>();
        for (CloudContextDetector provider : providers) {
            findings.addAll(provider.detect(request, snapshot));
        }
        return findings;
    }
}
