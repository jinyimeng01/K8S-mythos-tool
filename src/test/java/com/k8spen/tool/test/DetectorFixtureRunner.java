package com.k8spen.tool.test;

import com.k8spen.tool.core.client.ApiResponse;
import com.k8spen.tool.core.detector.ScanDetector;
import com.k8spen.tool.core.engine.ScanSnapshot;
import com.k8spen.tool.core.model.AuthProfile;
import com.k8spen.tool.core.model.Finding;
import com.k8spen.tool.core.model.ScanModule;
import com.k8spen.tool.core.model.ScanRequest;
import com.k8spen.tool.core.model.TargetProfile;

import java.util.EnumSet;
import java.util.List;
import java.util.Map;

public final class DetectorFixtureRunner {
    private DetectorFixtureRunner() {}

    public static List<Finding> run(ScanDetector detector, ScanModule module, Map<String, String> snapshotFixtures) {
        ScanSnapshot snapshot = snapshot(snapshotFixtures);
        ScanRequest request = ScanRequest.create(TargetProfile.fromHost("127.0.0.1", 5, true),
                AuthProfile.bearer("fixture-token"), EnumSet.of(module), "", true, true);
        return detector.detect(request, snapshot);
    }

    public static ScanSnapshot snapshot(Map<String, String> snapshotFixtures) {
        ScanSnapshot snapshot = new ScanSnapshot();
        for (Map.Entry<String, String> entry : snapshotFixtures.entrySet()) {
            String raw = FixtureLoader.read(entry.getValue());
            snapshot.put(entry.getKey(), ApiResponse.fromRaw("/fixture/" + entry.getKey(), "[HTTP 200]\n" + raw, false));
        }
        return snapshot;
    }
}
