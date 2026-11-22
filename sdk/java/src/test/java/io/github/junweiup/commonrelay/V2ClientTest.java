package io.github.junweiup.commonrelay;

import okhttp3.*;
import okio.Buffer;
import org.json.JSONObject;
import org.junit.Test;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.junit.Assert.*;

public class V2ClientTest {
    private static final String PUB = "132c442be010fbd57e72603328aa76e71fccc1503aae219327d14d9c9993f472";
    private static final String PRIV = "42".repeat(32);
    private static final String HELLO = "435253318060211cbbbb765d2dcb943d8373a8389ce9e2409001ca7cd5fa9572c3267b305d3593574756b28720e140d0a61e3bc20371a2aa079a321fb808722e208c2d2cb4e3804a2b3f32f1160a1e832e7a55fb08290b6df4e8cd043917b0f2f3c89463000000210ea5b12a2fb9ef63bc511f08e718632e069600737c791c3032ee1bd1dbf961bc9d";
    private static final String EMPTY = "43525331d23a619a1d158a1af281e170675d0d63e98c4fb84c8dc1cc4598bea00692183cfac3564174de5cd264f242fd4972beea37f96f1c0901e95d147a63f561235f78d02b9b6fd1f2bc8a1195b015fcd417064dea8fa17a669b86d3bcc4fe6d7d3a230000001024ef6f7ff1b06ef0b51a3ecc2b6e9026";

    /** Records requests and answers with a canned status/body without touching the network. */
    private static OkHttpClient canned(List<Request> seen, List<String> bodies, int code, String contentType, String body) {
        return new OkHttpClient.Builder().addInterceptor(chain -> {
            Request r = chain.request();
            seen.add(r);
            Buffer buf = new Buffer();
            if (r.body() != null) r.body().writeTo(buf);
            bodies.add(buf.readUtf8());
            return new Response.Builder().request(r).protocol(Protocol.HTTP_1_1).code(code).message("x")
                .body(ResponseBody.create(body, MediaType.get(contentType))).build();
        }).build();
    }

    private static final String BINDING = "{\"ok\":true,\"binding\":{\"id\":\"b1\",\"plugin_id\":\"webhook\",\"mount\":\"gh\",\"space_id\":\"personal\",\"box_name\":\"hooks\",\"config_json\":\"{\\\"tag\\\":\\\"x\\\"}\",\"enabled\":true,\"updated_at\":7,\"config_version\":3,\"secret_keys\":[\"token_sha256\"],\"sealed\":true,\"summary\":{\"tag\":\"x\",\"has_token\":true},\"accounts\":[{\"scope_key\":\"s\",\"username\":\"u\",\"mode\":\"rw\"}]}}";

    @Test public void patchPluginShapesRequestAndParsesBinding() throws Exception {
        List<Request> seen = new ArrayList<>(); List<String> bodies = new ArrayList<>();
        V2Client c = new V2Client("https://relay.example/base/", "acc-pass", "tok", false, canned(seen, bodies, 200, "application/json", BINDING));
        V2Client.PluginBinding b = c.patchPlugin("web hook", "g/h", new V2Client.PluginPatch().enabled(false).config("tag", "y").deleteConfig("cors_origins"));
        Request r = seen.get(0);
        assertEquals("PATCH", r.method());
        assertEquals("/base/v2/admin/plugins/web%20hook/g%2Fh", r.url().encodedPath());
        assertEquals("Bearer tok", r.header("Authorization"));
        assertEquals("acc-pass", r.header("Relay-Access"));
        JSONObject sent = new JSONObject(bodies.get(0));
        assertFalse(sent.getBoolean("enabled"));
        assertEquals("y", sent.getJSONObject("config").getString("tag"));
        assertTrue(sent.getJSONObject("config").has("cors_origins"));
        assertTrue(sent.getJSONObject("config").isNull("cors_origins"));
        assertFalse(sent.has("if_version"));
        assertFalse(sent.has("space_id"));
        assertFalse(sent.has("box_name"));
        assertEquals(3, b.configVersion);
        assertEquals(List.of("token_sha256"), b.secretKeys);
        assertTrue(b.sealed);
        assertTrue(b.summary.hasToken);
        assertEquals("u", b.accounts.get(0).username);

        new V2Client("https://relay.example", "", "tok", false, canned(seen, bodies, 200, "application/json", BINDING))
            .patchPlugin("webhook", "gh", new V2Client.PluginPatch().spaceId("p2").ifVersion(3));
        JSONObject second = new JSONObject(bodies.get(1));
        assertEquals(3, second.getLong("if_version"));
        assertEquals("p2", second.getString("space_id"));
        assertFalse(second.has("config"));
        assertNull(seen.get(1).header("Relay-Access"));
    }

    @Test public void getPluginCatalogAndAccountPassword() throws Exception {
        List<Request> seen = new ArrayList<>(); List<String> bodies = new ArrayList<>();
        String catalog = "{\"ok\":true,\"registered\":[\"drop\"],\"plugins\":[{\"id\":\"drop\",\"required_trust\":\"bridge_allowed\",\"schema\":[{\"key\":\"token\",\"type\":\"string\",\"secret\":true,\"required\":true}]}],\"bindings\":[]}";
        List<V2Client.PluginInfo> plugins = new V2Client("https://relay.example", "", "tok", false, canned(seen, bodies, 200, "application/json", catalog)).pluginCatalog();
        assertEquals("GET", seen.get(0).method());
        assertEquals("/v2/admin/plugins", seen.get(0).url().encodedPath());
        assertEquals("drop", plugins.get(0).id);
        assertEquals("bridge_allowed", plugins.get(0).requiredTrust);
        assertTrue(plugins.get(0).schema.get(0).secret);
        assertTrue(plugins.get(0).schema.get(0).required);

        V2Client.PluginBinding b = new V2Client("https://relay.example", "", "tok", false, canned(seen, bodies, 200, "application/json", BINDING)).getPlugin("webhook", "gh");
        assertEquals("GET", seen.get(1).method());
        assertEquals("/v2/admin/plugins/webhook/gh", seen.get(1).url().encodedPath());
        assertEquals("b1", b.id);

        String acct = "{\"ok\":true,\"account\":{\"binding_id\":\"b1\",\"scope_key\":\"s\",\"username\":\"u\",\"mode\":\"rw\",\"meta_json\":\"\",\"updated_at\":9}}";
        V2Client.PluginAccount a = new V2Client("https://relay.example", "", "tok", false, canned(seen, bodies, 200, "application/json", acct))
            .upsertPluginAccountPassword("webdav", "files", "s", "u", "pw-123", "rw");
        assertEquals("PUT", seen.get(2).method());
        assertEquals("/v2/admin/plugins/webdav/files/accounts", seen.get(2).url().encodedPath());
        JSONObject sent = new JSONObject(bodies.get(2));
        assertEquals("pw-123", sent.getString("password"));
        assertFalse(sent.has("secret_sha256"));
        assertEquals("s", sent.getString("scope_key"));
        assertEquals("rw", sent.getString("mode"));
        assertEquals(9, a.updatedAt);
    }

    @Test public void unsupportedDetection() throws Exception {
        assertTrue(new V2Client.ApiException(405, "method not allowed").isUnsupported());
        assertTrue(new V2Client.ApiException(501, "").isUnsupported());
        assertTrue(new V2Client.ApiException(404, "404 page not found").isUnsupported());
        assertFalse(new V2Client.ApiException(404, "{\"ok\":false,\"error\":\"not found\"}").isUnsupported());
        assertFalse(new V2Client.ApiException(409, "{}").isUnsupported());
        assertFalse(V2Client.isUnsupported(new java.io.IOException("x")));
        assertTrue(V2Client.isUnsupported(new RuntimeException(new V2Client.ApiException(405, ""))));

        List<Request> seen = new ArrayList<>(); List<String> bodies = new ArrayList<>();
        V2Client old = new V2Client("https://relay.example", "", "tok", false, canned(seen, bodies, 404, "text/plain", "404 page not found\n"));
        V2Client.ApiException e = assertThrows(V2Client.ApiException.class, () -> old.patchPlugin("webhook", "gh", new V2Client.PluginPatch().enabled(true)));
        assertEquals(404, e.status);
        assertTrue(V2Client.isUnsupported(e));
        V2Client fresh = new V2Client("https://relay.example", "", "tok", false, canned(seen, bodies, 404, "application/json", "{\"ok\":false,\"error\":\"not found\"}\n"));
        assertFalse(V2Client.isUnsupported(assertThrows(V2Client.ApiException.class, () -> fresh.getPlugin("webhook", "missing"))));
    }

    @Test public void meParsesDeviceRootAdminAndUnsupported() throws Exception {
        List<Request> seen = new ArrayList<>(); List<String> bodies = new ArrayList<>();
        String dev = "{\"ok\":true,\"device\":{\"id\":\"d1\",\"name\":\"phone\",\"public_key\":\"pk\",\"is_admin\":true,\"revoked\":false,\"created_at\":5}}";
        V2Client.Me me = new V2Client("https://relay.example/base", "acc-pass", "tok", false, canned(seen, bodies, 200, "application/json", dev)).me();
        Request r = seen.get(0);
        assertEquals("GET", r.method());
        assertEquals("/base/v2/me", r.url().encodedPath());
        assertEquals("Bearer tok", r.header("Authorization"));
        assertEquals("acc-pass", r.header("Relay-Access"));
        assertFalse(me.rootAdmin);
        assertEquals("d1", me.device.id);
        assertEquals("phone", me.device.name);
        assertEquals("pk", me.device.publicKey);
        assertTrue(me.device.isAdmin);
        assertFalse(me.device.revoked);
        assertEquals(5, me.device.createdAt);

        V2Client.Me root = new V2Client("https://relay.example", "", "admin-secret", false, canned(seen, bodies, 200, "application/json", "{\"ok\":true,\"root_admin\":true}")).me();
        assertTrue(root.rootAdmin);
        assertNull(root.device);

        V2Client old = new V2Client("https://relay.example", "", "tok", false, canned(seen, bodies, 404, "text/plain", "404 page not found\n"));
        assertTrue(V2Client.isUnsupported(assertThrows(V2Client.ApiException.class, old::me)));
    }

    @Test public void opensGoSealedVectors() throws Exception {
        byte[] pub = V2Sealed.parsePublicKey(PUB), priv = V2Sealed.parseKey(PRIV);
        byte[] hello = Crypto.unhex(HELLO);
        assertTrue(V2Sealed.isSealed(hello));
        assertFalse(V2Sealed.isSealed("CRS".getBytes(StandardCharsets.US_ASCII)));
        assertFalse(V2Sealed.isSealed("{\"a\":1}".getBytes(StandardCharsets.US_ASCII)));
        assertEquals("hello sealed crs1", new String(V2Sealed.openSealed(hello, pub, priv), StandardCharsets.UTF_8));
        assertEquals(0, V2Sealed.openSealed(Crypto.unhex(EMPTY), pub, priv).length);

        // Truncation (drop the whole single frame, or part of it), tampering, and trailing junk fail.
        assertThrows(V2Sealed.CorruptException.class, () -> V2Sealed.openSealed(Arrays.copyOf(hello, 100), pub, priv));
        assertThrows(V2Sealed.CorruptException.class, () -> V2Sealed.openSealed(Arrays.copyOf(hello, hello.length - 1), pub, priv));
        byte[] tampered = hello.clone(); tampered[tampered.length - 1] ^= 1;
        assertThrows(V2Sealed.CorruptException.class, () -> V2Sealed.openSealed(tampered, pub, priv));
        byte[] junk = Arrays.copyOf(hello, hello.length + 4);
        assertThrows(V2Sealed.CorruptException.class, () -> V2Sealed.openSealed(junk, pub, priv));

        V2Sealed.KeyPair other = V2Sealed.generateSealKeyPair();
        assertEquals(64, other.publicHex.length());
        assertEquals(64, other.privateHex.length());
        assertNotEquals(other.publicHex, V2Sealed.generateSealKeyPair().publicHex);
        assertThrows(V2Sealed.CorruptException.class, () -> V2Sealed.openSealed(hello, V2Sealed.parseKey(other.publicHex), V2Sealed.parseKey(other.privateHex)));
        assertThrows(IllegalArgumentException.class, () -> V2Sealed.parseKey("zz"));
        assertEquals(V2Sealed.SEALED_CONTENT_TYPE, "application/vnd.common-relay.sealed");
    }
}
