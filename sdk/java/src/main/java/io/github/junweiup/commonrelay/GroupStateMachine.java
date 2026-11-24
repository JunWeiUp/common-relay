package io.github.junweiup.commonrelay;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Callback-driven draft-before-send group state machine and optional direct-upgrade
 * ({@code relay.direct.v1}) payload helpers.
 */
public final class GroupStateMachine<T> {
    /** Pipe {@code msg} topic reserved for optional LAN/direct candidate exchange (§4.9). */
    public static final String DIRECT_UPGRADE_TOPIC = "relay.direct.v1";

    /** Pending credential/mutation draft persisted BEFORE issuing network requests. */
    public static final class GroupDraft {
        public final String draftId;
        public final String op; // "create" | "join" | "auto_join" | "rotate"
        public final String app;
        public final String group;
        public final String device;
        public final String secretKey;
        public final String signSecretKey;
        public final String token;
        public final String inviteId;
        public final long createdAt;

        public GroupDraft(
                String draftId,
                String op,
                String app,
                String group,
                String device,
                String secretKey,
                String signSecretKey,
                String token,
                String inviteId,
                long createdAt) {
            this.draftId = draftId;
            this.op = op;
            this.app = app;
            this.group = group;
            this.device = device;
            this.secretKey = secretKey;
            this.signSecretKey = signSecretKey;
            this.token = token;
            this.inviteId = inviteId == null ? "" : inviteId;
            this.createdAt = createdAt;
        }

        public String encodeJson() throws JSONException {
            JSONObject obj = new JSONObject();
            obj.put("draft_id", draftId);
            obj.put("op", op);
            obj.put("app", app);
            obj.put("group", group);
            obj.put("device", device);
            obj.put("secret_key", secretKey);
            obj.put("sign_secret_key", signSecretKey);
            obj.put("token", token);
            if (!inviteId.isEmpty()) {
                obj.put("invite_id", inviteId);
            }
            obj.put("created_at", createdAt);
            return obj.toString();
        }

        public static GroupDraft decodeJson(String raw) throws JSONException {
            JSONObject obj = new JSONObject(raw);
            return new GroupDraft(
                    obj.getString("draft_id"),
                    obj.getString("op"),
                    obj.getString("app"),
                    obj.getString("group"),
                    obj.getString("device"),
                    obj.getString("secret_key"),
                    obj.getString("sign_secret_key"),
                    obj.getString("token"),
                    obj.optString("invite_id", ""),
                    obj.optLong("created_at", 0L));
        }
    }

    public interface DraftStore<T> {
        void saveDraft(GroupDraft draft) throws Exception;

        GroupDraft loadDraft() throws Exception;

        void commit(GroupDraft draft, T result) throws Exception;

        void clearDraft(String draftId) throws Exception;
    }

    public interface NetworkAction<T> {
        T run(GroupDraft draft) throws Exception;
    }

    private final DraftStore<T> store;

    public GroupStateMachine(DraftStore<T> store) {
        if (store == null) {
            throw new IllegalArgumentException("store is required");
        }
        this.store = store;
    }

    public GroupDraft pendingDraft() throws Exception {
        return store.loadDraft();
    }

    /**
     * Persists {@code draft} before invoking {@code action}. If {@code action} throws,
     * the draft stays stored for recovery; on success, {@code commit} and {@code clearDraft} run.
     */
    public T execute(GroupDraft draft, NetworkAction<T> action) throws Exception {
        store.saveDraft(draft);
        T result = action.run(draft);
        store.commit(draft, result);
        store.clearDraft(draft.draftId);
        return result;
    }

    /** Plaintext payload carried inside a §6 encrypted envelope on {@link #DIRECT_UPGRADE_TOPIC}. */
    public static final class DirectUpgradeMessage {
        public final String op; // "offer" | "answer" | "fallback"
        public final String session;
        public final List<String> candidates;
        public final String nonce;

        public DirectUpgradeMessage(String op, String session, List<String> candidates, String nonce) {
            this.op = op == null ? "" : op;
            this.session = session == null ? "" : session;
            this.candidates = candidates == null
                    ? Collections.emptyList()
                    : Collections.unmodifiableList(new ArrayList<>(candidates));
            this.nonce = nonce == null ? "" : nonce;
        }

        public void validate() {
            if (!"offer".equals(op) && !"answer".equals(op) && !"fallback".equals(op)) {
                throw new IllegalArgumentException("invalid direct upgrade op: " + op);
            }
            if (session.trim().isEmpty()) {
                throw new IllegalArgumentException("direct upgrade session is required");
            }
        }

        public byte[] encode() throws JSONException {
            validate();
            JSONObject obj = new JSONObject();
            obj.put("op", op);
            obj.put("session", session);
            if (!candidates.isEmpty()) {
                obj.put("candidates", new JSONArray(candidates));
            }
            if (!nonce.isEmpty()) {
                obj.put("nonce", nonce);
            }
            return obj.toString().getBytes(StandardCharsets.UTF_8);
        }

        public static DirectUpgradeMessage decode(byte[] raw) throws JSONException {
            JSONObject obj = new JSONObject(new String(raw, StandardCharsets.UTF_8));
            List<String> cands = new ArrayList<>();
            JSONArray arr = obj.optJSONArray("candidates");
            if (arr != null) {
                for (int i = 0; i < arr.length(); i++) {
                    cands.add(arr.getString(i));
                }
            }
            DirectUpgradeMessage msg = new DirectUpgradeMessage(
                    obj.optString("op", ""),
                    obj.optString("session", ""),
                    cands,
                    obj.optString("nonce", ""));
            msg.validate();
            return msg;
        }
    }
}
