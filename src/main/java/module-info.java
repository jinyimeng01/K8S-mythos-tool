module com.k8spen.tool {
    requires javafx.controls;
    requires javafx.fxml;
    requires javafx.swing;
    requires java.desktop;
    requires com.google.gson;

    opens com.k8spen.tool to javafx.graphics;
    opens com.k8spen.tool.controller to javafx.fxml;
    opens com.k8spen.tool.core.model to com.google.gson;
    exports com.k8spen.tool;
    exports com.k8spen.tool.core.client;
    exports com.k8spen.tool.core.detector;
    exports com.k8spen.tool.core.engine;
    exports com.k8spen.tool.core.model;
    exports com.k8spen.tool.core.report;
}
