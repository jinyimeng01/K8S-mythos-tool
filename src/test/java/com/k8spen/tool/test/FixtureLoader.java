package com.k8spen.tool.test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public final class FixtureLoader {
    private FixtureLoader() {}

    public static String read(String path) {
        String normalized = path.startsWith("/") ? path : "/" + path;
        try (InputStream in = FixtureLoader.class.getResourceAsStream(normalized)) {
            if (in == null) throw new IllegalArgumentException("Missing fixture: " + path);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read fixture: " + path, e);
        }
    }
}
