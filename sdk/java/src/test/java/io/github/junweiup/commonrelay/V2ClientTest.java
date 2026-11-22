package io.github.junweiup.commonrelay;

import okhttp3.*;
import okio.Buffer;
import org.json.JSONObject;
import org.junit.Test;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.junit.Assert.*;

public class V2ClientTest {
    private static JSONObject vectors(String name) throws Exception {
        return new JSONObject(new String(java.nio.file.Files.readAllBytes(java.nio.file.Path.of("../../protocol/v2/" + name)), StandardCharsets.UTF_8));
    }

    private static String sha256(byte[] b) throws Exception { return RelayGroups.digest(b); }

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

    @Test public void hashSecretVectors() throws Exception {
        org.json.JSONArray cases = vectors("vectors.json").getJSONArray("hash_secret");
        assertTrue(cases.length() > 0);
        for (int i = 0; i < cases.length(); i++) {
            JSONObject c = cases.getJSONObject(i);
            assertEquals(c.getString("use"), c.getString("sha256"), V2Client.hashSecret(c.getString("input")));
        }
    }

    @Test public void opensGoSealedVectors() throws Exception {
        JSONObject v = vectors("sealed-vectors.json");
        byte[] pub = V2Sealed.parsePublicKey(v.getString("recipient_public")), priv = V2Sealed.parseKey(v.getString("recipient_private"));
        Map<String, byte[]> sealed = new HashMap<>();
        org.json.JSONArray valid = v.getJSONArray("valid");
        assertTrue(valid.length() >= 3);
        for (int i = 0; i < valid.length(); i++) {
            JSONObject c = valid.getJSONObject(i);
            String name = c.getString("name");
            byte[] box = Base64.getDecoder().decode(c.getString("sealed_b64"));
            sealed.put(name, box);
            assertTrue(name, V2Sealed.isSealed(box));
            byte[] plain = V2Sealed.openSealed(box, pub, priv);
            assertEquals(name, c.getInt("plaintext_length"), plain.length);
            assertEquals(name, c.getString("plaintext_sha256"), sha256(plain));
            if (c.has("plaintext_hex")) assertEquals(name, c.getString("plaintext_hex"), Crypto.hex(plain));
            if (name.equals("two_frames")) for (int j = 0; j < plain.length; j++) assertEquals((byte) ((j * 7 + 3) & 0xff), plain[j]);
        }
        assertEquals("hello sealed crs1", new String(V2Sealed.openSealed(sealed.get("hello"), pub, priv), StandardCharsets.UTF_8));
        assertEquals(0, V2Sealed.openSealed(sealed.get("empty"), pub, priv).length);
        assertFalse(V2Sealed.isSealed("CRS".getBytes(StandardCharsets.US_ASCII)));
        assertFalse(V2Sealed.isSealed("{\"a\":1}".getBytes(StandardCharsets.US_ASCII)));

        // Truncation, tampering, and trailing junk fail.
        org.json.JSONArray invalid = v.getJSONArray("invalid");
        assertTrue(invalid.length() > 0);
        for (int i = 0; i < invalid.length(); i++) {
            JSONObject c = invalid.getJSONObject(i);
            byte[] base = sealed.get(c.getString("base")), bad;
            assertNotNull(c.getString("base"), base);
            switch (c.getString("op")) {
                case "truncate": bad = Arrays.copyOf(base, c.getInt("length")); break;
                case "append": {
                    byte[] extra = Crypto.unhex(c.getString("hex"));
                    bad = Arrays.copyOf(base, base.length + extra.length);
                    System.arraycopy(extra, 0, bad, base.length, extra.length);
                    break;
                }
                case "flip": bad = base.clone(); bad[c.getInt("offset")] ^= 1; break;
                default: throw new AssertionError("unknown op " + c.getString("op"));
            }
            final byte[] attempt = bad;
            assertThrows(c.getString("name"), V2Sealed.CorruptException.class, () -> V2Sealed.openSealed(attempt, pub, priv));
        }
        byte[] wrongPub = V2Sealed.parseKey(v.getString("wrong_public")), wrongPriv = V2Sealed.parseKey(v.getString("wrong_private"));
        assertThrows(V2Sealed.CorruptException.class, () -> V2Sealed.openSealed(sealed.get("hello"), wrongPub, wrongPriv));

        V2Sealed.KeyPair other = V2Sealed.generateSealKeyPair();
        assertEquals(64, other.publicHex.length());
        assertEquals(64, other.privateHex.length());
        assertNotEquals(other.publicHex, V2Sealed.generateSealKeyPair().publicHex);
        assertThrows(V2Sealed.CorruptException.class, () -> V2Sealed.openSealed(sealed.get("hello"), V2Sealed.parseKey(other.publicHex), V2Sealed.parseKey(other.privateHex)));
        assertThrows(IllegalArgumentException.class, () -> V2Sealed.parseKey("zz"));
        assertEquals(V2Sealed.SEALED_CONTENT_TYPE, "application/vnd.common-relay.sealed");
    }
}
