package com.exemplo.seguranca;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.DisplayName;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;

import java.net.HttpURLConnection;
import java.net.URL;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class VulnerableTargetsIT {

    private static GenericContainer<?> juiceShop;

    @BeforeAll
    static void startContainers() {
        juiceShop = new GenericContainer<>(DockerImageName.parse("bkimminich/juice-shop"))
                .withExposedPorts(3000);
        juiceShop.start();
    }

    @AfterAll
    static void stopContainers() {
        if (juiceShop != null) juiceShop.stop();
    }

    @Test
    @DisplayName("Juice Shop deve responder 200 (alvo DAST disponível)")
    void juiceShopIsReachable() throws Exception {
        String baseUrl = "http://" + juiceShop.getHost() + ":" + juiceShop.getMappedPort(3000);
        URL url = new URL(baseUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setInstanceFollowRedirects(true);
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        assertEquals(200, conn.getResponseCode());
    }
}
