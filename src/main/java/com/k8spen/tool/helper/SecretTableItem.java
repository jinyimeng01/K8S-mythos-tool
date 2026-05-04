package com.k8spen.tool.helper;

import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;

public class SecretTableItem {
    private final SimpleStringProperty namespace;
    private final SimpleStringProperty name;
    private final SimpleStringProperty type;
    private final SimpleStringProperty creationTime;

    public SecretTableItem(String namespace, String name, String type, String creationTime) {
        this.namespace = new SimpleStringProperty(namespace);
        this.name = new SimpleStringProperty(name);
        this.type = new SimpleStringProperty(type);
        this.creationTime = new SimpleStringProperty(creationTime);
    }

    public String getNamespace() { return namespace.get(); }
    public StringProperty namespaceProperty() { return namespace; }
    public String getName() { return name.get(); }
    public StringProperty nameProperty() { return name; }
    public String getType() { return type.get(); }
    public StringProperty typeProperty() { return type; }
    public String getCreationTime() { return creationTime.get(); }
    public StringProperty creationTimeProperty() { return creationTime; }
}
