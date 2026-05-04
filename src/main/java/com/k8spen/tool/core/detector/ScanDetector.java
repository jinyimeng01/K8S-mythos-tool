package com.k8spen.tool.core.detector;

import com.k8spen.tool.core.engine.ScanSnapshot;
import com.k8spen.tool.core.model.Finding;
import com.k8spen.tool.core.model.ScanRequest;

import java.util.List;

public interface ScanDetector {
    List<Finding> detect(ScanRequest request, ScanSnapshot snapshot);
}
