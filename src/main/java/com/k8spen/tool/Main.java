package com.k8spen.tool;

import javafx.embed.swing.SwingFXUtils;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.geometry.Rectangle2D;
import javafx.scene.image.Image;
import javafx.stage.Screen;
import javafx.stage.Stage;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.GradientPaint;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.RoundRectangle2D;
import java.awt.image.BufferedImage;

public class Main extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception {
        Parent root = FXMLLoader.load(getClass().getResource("/gui.fxml"));
        root.getStyleClass().add("app-shell");
        primaryStage.setTitle("K8S-mythos-tool v1.0 - Industrial Kubernetes Red-Team Workbench");

        Rectangle2D screenBounds = Screen.getPrimary().getVisualBounds();
        double screenW = screenBounds.getWidth();
        double screenH = screenBounds.getHeight();

        double stageW = screenW * 0.82;
        double stageH = screenH * 0.82;

        Scene scene = new Scene(root, stageW, stageH);
        var stylesheet = getClass().getResource("/styles/mythos.css");
        if (stylesheet != null) {
            scene.getStylesheets().add(stylesheet.toExternalForm());
        }
        primaryStage.setScene(scene);
        primaryStage.getIcons().add(buildAppIcon());
        primaryStage.setMinWidth(900.0);
        primaryStage.setMinHeight(600.0);
        primaryStage.show();
    }

    private Image buildAppIcon() {
        BufferedImage image = new BufferedImage(64, 64, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = image.createGraphics();
        try {
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.setPaint(new GradientPaint(0, 0, new Color(8, 24, 34), 64, 64, new Color(0, 190, 210)));
            g.fill(new RoundRectangle2D.Double(0, 0, 64, 64, 16, 16));

            g.setColor(new Color(244, 190, 79, 235));
            g.setStroke(new BasicStroke(3f));
            g.drawOval(16, 16, 32, 32);
            g.fillOval(28, 28, 8, 8);
            for (int i = 0; i < 7; i++) {
                double angle = Math.toRadians(i * 360.0 / 7 - 90);
                int x1 = 32 + (int) (14 * Math.cos(angle));
                int y1 = 32 + (int) (14 * Math.sin(angle));
                g.drawLine(32, 32, x1, y1);
            }

            g.setColor(new Color(226, 232, 240, 120));
            g.setStroke(new BasicStroke(2f));
            g.drawRoundRect(3, 3, 58, 58, 14, 14);
        } finally {
            g.dispose();
        }
        return SwingFXUtils.toFXImage(image, null);
    }

    public static void main(String[] args) {
        launch(args);
    }
}
