package io.github.junweiup.commonrelay;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Common Relay v2 client for Android Java/Kotlin (tailored for 日日 App snapshot uploads).
 * Covers Box(queue) upload, ACK, and protocol/v2 shared secret hashing with zero extra dependencies.
 */
public final class V2Client {
    private final String baseUrl;
    private final String accessPassword;
    private final String token;

    public V2Client(String baseUrl, String accessPassword, String token, boolean allowLocal) {
        String trimmed = baseUrl == null ? "" : baseUrl.trim().replaceAll("/+$", "");
        URI u = URI.create(trimmed);
        String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase();
        String host = u.getHost() == null ? "" : u.getHost().toLowerCase();
        if ("http".equals(scheme)) {
            if (!allowLocal || !("127.0.0.1".equals(host) || "localhost".equals(host) || "::1".equals(host))) {
                throw new IllegalArgumentException("v2 client requires https");
            }
        } else if (!"https".equals(scheme)) {
            throw new IllegalArgumentException("invalid v2 base URL");
        }
        this.baseUrl = trimmed;
        this.accessPassword = accessPassword == null ? "" : accessPassword;
        this.token = token == null ? "" : token;
    }

    public static String hashSecret(String plain) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] sum = md.digest(plain.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(64);
            for (byte b : sum) {
                sb.append(String.format("%02x", b & 0xff));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Uploads an encrypted snapshot payload into Box(queue) and returns HTTP status (201 on success). */
    public int putBoxItem(String space, String box, byte[] ciphertext, String contentType, String metaJson) throws IOException {
        URL url = new URL(baseUrl + "/v2/spaces/" + space + "/boxes/" + box + "/items");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(30000);
        if (!accessPassword.isEmpty()) {
            conn.setRequestProperty("Relay-Access", accessPassword);
        }
        conn.setRequestProperty("Authorization", "Bearer " + token);
        conn.setRequestProperty("Content-Type", contentType == null || contentType.isEmpty() ? "application/octet-stream" : contentType);
        if (metaJson != null && !metaJson.isEmpty()) {
            conn.setRequestProperty("X-Box-Meta", metaJson);
        }
        conn.setFixedLengthStreamingMode(ciphertext.length);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(ciphertext);
        }
        try {
            return conn.getResponseCode();
        } finally {
            conn.disconnect();
        }
    }
}
