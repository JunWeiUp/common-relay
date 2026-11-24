package io.github.junweiup.commonrelay;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Common Relay v2 client for Android Java/Kotlin.
 * Covers Box(queue) upload, protocol/v2 shared secret hashing, and the Admin Control Plane plugin API
 * (catalog, get, PATCH merge, scrypt account passwords). Admin JSON calls use OkHttp because
 * {@link HttpURLConnection} cannot send PATCH. Sealed (crs1) bridge payloads: see {@link V2Sealed}.
 */
public final class V2Client {
    private final String baseUrl;
    private final String accessPassword;
    private final String token;
    private final OkHttpClient http;
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");

    public V2Client(String baseUrl, String accessPassword, String token, boolean allowLocal) {
        this(baseUrl, accessPassword, token, allowLocal, null);
    }

    /** @param http shared OkHttp client for admin JSON calls; null creates a private one. */
    public V2Client(String baseUrl, String accessPassword, String token, boolean allowLocal, OkHttpClient http) {
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
        this.http = http != null ? http : new OkHttpClient();
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

    /* ───────── Admin Control Plane (/v2/admin/*) ───────── */

    /** Non-2xx relay response; {@link #body} is the trimmed response text. */
    public static final class ApiException extends IOException {
        public final int status;
        public final String body;

        public ApiException(int status, String body) {
            super("relay v2 http " + status + ": " + body);
            this.status = status;
            this.body = body == null ? "" : body;
        }

        /**
         * The server predates the endpoint (e.g. PATCH /v2/admin/plugins/{id}/{mount}): it answers
         * 405/501 or a plain-text 404 instead of a JSON error. Callers can fall back to the older PUT API.
         */
        public boolean isUnsupported() {
            return status == 405 || status == 501 || (status == 404 && !body.startsWith("{"));
        }
    }

    /** True when {@code e} (or a cause) is an {@link ApiException} for which {@link ApiException#isUnsupported()} holds. */
    public static boolean isUnsupported(Throwable e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t instanceof ApiException) return ((ApiException) t).isUnsupported();
        }
        return false;
    }

    public static final class PluginBindingSummary {
        public final String targetDevice, publicBase, tag;
        public final boolean targetOnline, hasHmac, hasToken;
        public final List<String> corsOrigins;

        PluginBindingSummary(JSONObject j) {
            targetDevice = j.optString("target_device", "");
            targetOnline = j.optBoolean("target_online", false);
            publicBase = j.optString("public_base", "");
            tag = j.optString("tag", "");
            hasHmac = j.optBoolean("has_hmac", false);
            hasToken = j.optBoolean("has_token", false);
            corsOrigins = strings(j.optJSONArray("cors_origins"));
        }
    }

    public static final class PluginAccountView {
        public final String scopeKey, username, mode;

        PluginAccountView(JSONObject j) {
            scopeKey = j.optString("scope_key", "");
            username = j.optString("username", "");
            mode = j.optString("mode", "");
        }
    }

    public static final class PluginBinding {
        public final String id, pluginId, mount, spaceId, boxName, configJson;
        public final boolean enabled;
        public final long updatedAt;
        /** Null when the server sent no summary. */
        public final PluginBindingSummary summary;
        public final List<PluginAccountView> accounts;
        /** Increments on every change; pass as {@link PluginPatch#ifVersion}. 0 on servers older than PATCH. */
        public final long configVersion;
        /** Write-only secret keys currently set (values are never returned). */
        public final List<String> secretKeys;
        /** Bridged payloads are sealed (crs1) to seal_public_key; open them with {@link V2Sealed}. */
        public final boolean sealed;

        public PluginBinding(JSONObject j) {
            id = j.optString("id", "");
            pluginId = j.optString("plugin_id", "");
            mount = j.optString("mount", "");
            spaceId = j.optString("space_id", "");
            boxName = j.optString("box_name", "");
            configJson = j.optString("config_json", "{}");
            enabled = j.optBoolean("enabled", false);
            updatedAt = j.optLong("updated_at", 0);
            JSONObject sum = j.optJSONObject("summary");
            summary = sum == null ? null : new PluginBindingSummary(sum);
            List<PluginAccountView> accts = new ArrayList<>();
            JSONArray arr = j.optJSONArray("accounts");
            if (arr != null) for (int i = 0; i < arr.length(); i++) {
                JSONObject a = arr.optJSONObject(i);
                if (a != null) accts.add(new PluginAccountView(a));
            }
            accounts = Collections.unmodifiableList(accts);
            configVersion = j.optLong("config_version", 0);
            secretKeys = strings(j.optJSONArray("secret_keys"));
            sealed = j.optBoolean("sealed", false);
        }
    }

    /** One config key a plugin accepts. */
    public static final class PluginFieldSpec {
        public final String key, type, description;
        public final boolean secret, required;

        PluginFieldSpec(JSONObject j) {
            key = j.optString("key", "");
            type = j.optString("type", "");
            description = j.optString("description", "");
            secret = j.optBoolean("secret", false);
            required = j.optBoolean("required", false);
        }
    }

    /** A registered plugin with its config schema (empty on servers that predate schemas). */
    public static final class PluginInfo {
        public final String id, requiredTrust;
        public final List<PluginFieldSpec> schema;

        PluginInfo(JSONObject j) {
            id = j.optString("id", "");
            requiredTrust = j.optString("required_trust", "");
            List<PluginFieldSpec> out = new ArrayList<>();
            JSONArray arr = j.optJSONArray("schema");
            if (arr != null) for (int i = 0; i < arr.length(); i++) {
                JSONObject f = arr.optJSONObject(i);
                if (f != null) out.add(new PluginFieldSpec(f));
            }
            schema = Collections.unmodifiableList(out);
        }
    }

    public static final class PluginAccount {
        public final String bindingId, scopeKey, username, mode, metaJson;
        public final long updatedAt;

        PluginAccount(JSONObject j) {
            bindingId = j.optString("binding_id", "");
            scopeKey = j.optString("scope_key", "");
            username = j.optString("username", "");
            mode = j.optString("mode", "");
            metaJson = j.optString("meta_json", "");
            updatedAt = j.optLong("updated_at", 0);
        }
    }

    /**
     * Partial binding update. Null fields are unchanged; a config entry with a null value deletes that
     * key. Secret keys are write-only: send a plaintext "token" to rotate a Bearer token (hashed server-side).
     */
    public static final class PluginPatch {
        private String spaceId, boxName;
        private Boolean enabled;
        private final Map<String, Object> config = new LinkedHashMap<>();
        private long ifVersion;

        public PluginPatch spaceId(String v) { spaceId = v; return this; }
        public PluginPatch boxName(String v) { boxName = v; return this; }
        public PluginPatch enabled(Boolean v) { enabled = v; return this; }
        /** Sets a config key; {@code value == null} deletes the key on the server. */
        public PluginPatch config(String key, Object value) { config.put(key, value); return this; }
        /** Deletes a config key (sent as JSON null). */
        public PluginPatch deleteConfig(String key) { config.put(key, null); return this; }
        /** Optimistic concurrency: the server rejects with 409 unless config_version matches. 0 disables. */
        public PluginPatch ifVersion(long v) { ifVersion = v; return this; }

        public JSONObject toJson() {
            try {
                JSONObject j = new JSONObject();
                if (spaceId != null) j.put("space_id", spaceId);
                if (boxName != null) j.put("box_name", boxName);
                if (enabled != null) j.put("enabled", enabled.booleanValue());
                if (!config.isEmpty()) {
                    JSONObject c = new JSONObject();
                    for (Map.Entry<String, Object> e : config.entrySet()) {
                        c.put(e.getKey(), e.getValue() == null ? JSONObject.NULL : JSONObject.wrap(e.getValue()));
                    }
                    j.put("config", c);
                }
                if (ifVersion != 0) j.put("if_version", ifVersion);
                return j;
            } catch (JSONException e) {
                throw new IllegalArgumentException("invalid plugin patch", e);
            }
        }
    }

    /** A registered v2 device (never includes the token). */
    public static final class Device {
        public final String id, name, publicKey;
        public final boolean isAdmin, revoked;
        public final long createdAt;

        Device(JSONObject j) {
            id = j.optString("id", "");
            name = j.optString("name", "");
            publicKey = j.optString("public_key", "");
            isAdmin = j.optBoolean("is_admin", false);
            revoked = j.optBoolean("revoked", false);
            createdAt = j.optLong("created_at", 0);
        }
    }

    /** Result of {@link #me()}: the token's device, or {@link #rootAdmin} (and a null device) for the Root Admin secret. */
    public static final class Me {
        /** Null for the Root Admin secret. */
        public final Device device;
        public final boolean rootAdmin;

        Me(JSONObject j) {
            JSONObject d = j.optJSONObject("device");
            device = d == null ? null : new Device(d);
            rootAdmin = j.optBoolean("root_admin", false);
        }
    }

    /**
     * The device the client's token belongs to. {@link Me#rootAdmin} is true (and {@link Me#device} null)
     * for the Root Admin secret. Older servers answer 404/405 (see {@link #isUnsupported}).
     */
    public Me me() throws IOException {
        HttpUrl base = HttpUrl.parse(baseUrl);
        if (base == null) throw new IllegalStateException("invalid v2 base URL");
        return new Me(adminJson("GET", base.newBuilder().addPathSegments("v2/me").build(), null));
    }

    /** Registered plugins with their config schemas. */
    public List<PluginInfo> pluginCatalog() throws IOException {
        JSONObject res = adminJson("GET", pluginsUrl().build(), null);
        List<PluginInfo> out = new ArrayList<>();
        JSONArray arr = res.optJSONArray("plugins");
        if (arr != null) for (int i = 0; i < arr.length(); i++) {
            JSONObject p = arr.optJSONObject(i);
            if (p != null) out.add(new PluginInfo(p));
        }
        return out;
    }

    /** One binding (public view) regardless of its enabled state. */
    public PluginBinding getPlugin(String pluginId, String mount) throws IOException {
        return binding(adminJson("GET", bindingUrl(pluginId, mount).build(), null));
    }

    /** Merges a partial update into an existing binding. Older servers answer 404/405 (see {@link #isUnsupported}). */
    public PluginBinding patchPlugin(String pluginId, String mount, PluginPatch patch) throws IOException {
        return binding(adminJson("PATCH", bindingUrl(pluginId, mount).build(), patch.toJson()));
    }

    /** Stores an account whose password the server hashes with salted scrypt (preferred over secret_sha256). */
    public PluginAccount upsertPluginAccountPassword(String pluginId, String mount, String scopeKey, String username, String password, String mode) throws IOException {
        JSONObject body = new JSONObject();
        try {
            body.put("scope_key", scopeKey).put("username", username).put("password", password).put("mode", mode);
        } catch (JSONException e) {
            throw new IllegalArgumentException(e);
        }
        JSONObject res = adminJson("PUT", bindingUrl(pluginId, mount).addPathSegment("accounts").build(), body);
        JSONObject a = res.optJSONObject("account");
        if (a == null) throw new IOException("relay v2: missing account");
        return new PluginAccount(a);
    }

    private HttpUrl.Builder pluginsUrl() {
        HttpUrl base = HttpUrl.parse(baseUrl);
        if (base == null) throw new IllegalStateException("invalid v2 base URL");
        return base.newBuilder().addPathSegments("v2/admin/plugins");
    }

    private HttpUrl.Builder bindingUrl(String pluginId, String mount) {
        return pluginsUrl().addPathSegment(pluginId).addPathSegment(mount);
    }

    private static PluginBinding binding(JSONObject res) throws IOException {
        JSONObject b = res.optJSONObject("binding");
        if (b == null) throw new IOException("relay v2: missing binding");
        return new PluginBinding(b);
    }

    private JSONObject adminJson(String method, HttpUrl url, JSONObject body) throws IOException {
        Request.Builder rb = new Request.Builder().url(url).header("Authorization", "Bearer " + token);
        if (!accessPassword.isEmpty()) rb.header("Relay-Access", accessPassword);
        rb.method(method, body == null ? null : RequestBody.create(body.toString(), JSON));
        try (Response resp = http.newCall(rb.build()).execute()) {
            ResponseBody rbody = resp.body();
            String text = rbody == null ? "" : rbody.string();
            if (!resp.isSuccessful()) {
                throw new ApiException(resp.code(), text.length() > 4096 ? text.substring(0, 4096).trim() : text.trim());
            }
            try {
                return new JSONObject(text);
            } catch (JSONException e) {
                throw new IOException("relay v2: invalid json", e);
            }
        }
    }

    private HttpUrl uploadsUrl(String spaceId, String boxName, String suffix) {
        HttpUrl.Builder b = HttpUrl.parse(baseUrl).newBuilder()
                .addPathSegment("v2").addPathSegment("spaces").addPathSegment(spaceId)
                .addPathSegment("boxes");
        for (String seg : boxName.split("/")) {
            b.addPathSegment(seg);
        }
        b.addPathSegment("uploads");
        if (suffix != null && !suffix.isEmpty()) {
            for (String seg : suffix.split("/")) {
                if (!seg.isEmpty()) b.addPathSegment(seg);
            }
        }
        return b.build();
    }

    public JSONObject createBoxUpload(String spaceId, String boxName, long totalSize, String key, String contentType, String metaJson, long ttlSec) throws IOException {
        JSONObject body = new JSONObject();
        try {
            body.put("total_size", totalSize);
            if (key != null && !key.isEmpty()) body.put("key", key);
            body.put("content_type", contentType == null || contentType.isEmpty() ? "application/octet-stream" : contentType);
            body.put("meta", metaJson == null || metaJson.isEmpty() ? "{}" : metaJson);
            if (ttlSec > 0) body.put("ttl", ttlSec);
        } catch (JSONException e) {
            throw new IOException(e);
        }
        return adminJson("POST", uploadsUrl(spaceId, boxName, ""), body).optJSONObject("upload");
    }

    public JSONObject getBoxUpload(String spaceId, String boxName, String uploadId) throws IOException {
        return adminJson("GET", uploadsUrl(spaceId, boxName, uploadId), null).optJSONObject("upload");
    }

    public JSONObject appendBoxUploadChunk(String spaceId, String boxName, String uploadId, long offset, byte[] chunk) throws IOException {
        HttpUrl url = uploadsUrl(spaceId, boxName, uploadId).newBuilder()
                .addQueryParameter("offset", Long.toString(offset))
                .build();
        Request.Builder rb = new Request.Builder().url(url).header("Authorization", "Bearer " + token);
        if (!accessPassword.isEmpty()) rb.header("Relay-Access", accessPassword);
        rb.patch(RequestBody.create(chunk, MediaType.get("application/octet-stream")));
        try (Response resp = http.newCall(rb.build()).execute()) {
            ResponseBody rbody = resp.body();
            String text = rbody == null ? "" : rbody.string();
            if (!resp.isSuccessful()) {
                throw new ApiException(resp.code(), text.trim());
            }
            try {
                return new JSONObject(text).optJSONObject("upload");
            } catch (JSONException e) {
                throw new IOException("relay v2: invalid json", e);
            }
        }
    }

    public JSONObject completeBoxUpload(String spaceId, String boxName, String uploadId, String sha256Hex, String expectedETag) throws IOException {
        JSONObject body = new JSONObject();
        try {
            if (sha256Hex != null && !sha256Hex.isEmpty()) body.put("sha256", sha256Hex);
            if (expectedETag != null && !expectedETag.isEmpty()) body.put("expected_etag", expectedETag);
        } catch (JSONException e) {
            throw new IOException(e);
        }
        return adminJson("POST", uploadsUrl(spaceId, boxName, uploadId + "/complete"), body);
    }

    public void abortBoxUpload(String spaceId, String boxName, String uploadId) throws IOException {
        adminJson("DELETE", uploadsUrl(spaceId, boxName, uploadId), null);
    }

    public JSONObject uploadBoxResumable(String spaceId, String boxName, byte[] data, String key, String contentType, String metaJson, int chunkSize, long ttlSec, String expectedETag) throws IOException {
        int step = chunkSize <= 0 ? (256 * 1024) : chunkSize;
        String digest;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] sum = md.digest(data);
            StringBuilder sb = new StringBuilder(64);
            for (byte b : sum) sb.append(String.format("%02x", b & 0xff));
            digest = sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IOException(e);
        }
        JSONObject up = createBoxUpload(spaceId, boxName, data.length, key, contentType, metaJson, ttlSec);
        String uid = up.optString("id", "");
        int offset = 0;
        while (offset < data.length) {
            int end = Math.min(offset + step, data.length);
            byte[] chunk = new byte[end - offset];
            System.arraycopy(data, offset, chunk, 0, chunk.length);
            up = appendBoxUploadChunk(spaceId, boxName, uid, offset, chunk);
            offset = (int) up.optLong("offset", end);
        }
        return completeBoxUpload(spaceId, boxName, uid, digest, expectedETag);
    }

    private static List<String> strings(JSONArray arr) {
        List<String> out = new ArrayList<>();
        if (arr != null) for (int i = 0; i < arr.length(); i++) {
            String v = arr.optString(i, null);
            if (v != null) out.add(v);
        }
        return Collections.unmodifiableList(out);
    }
}
