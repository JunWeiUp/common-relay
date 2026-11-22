package io.github.junweiup.commonrelay;

import com.sun.jna.Library;
import com.sun.jna.Native;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Sealed bridge payloads ("crs1"): bridge plugins (Webhook, Drop, WebDAV queue) seal plaintext
 * to a recipient X25519 public key before it reaches relay disk. Matches sdk/go/v2client/sealed.go.
 *
 * <pre>
 * magic "CRS1" (4) || crypto_box_seal(32-byte content key) (80) || nonce prefix (16)
 * frames: uint32 BE ciphertext length || secretbox(chunk, prefix || uint64 BE counter)
 * </pre>
 * The final frame sets the counter's high bit, so truncation is detected.
 */
public final class V2Sealed {
    public static final String SCHEME = "crs1";
    /** Content type of queue items whose body is a crs1 payload; the original type is in item meta "content_type". */
    public static final String SEALED_CONTENT_TYPE = "application/vnd.common-relay.sealed";
    static final int CHUNK_SIZE = 64 << 10;
    static final int SEALED_KEY_LEN = 32 + 48;
    static final int SECRETBOX_OVERHEAD = 16;
    static final long FINAL_FRAME_BIT = 1L << 63;
    private static final byte[] MAGIC = "CRS1".getBytes(StandardCharsets.US_ASCII);

    interface Sodium extends Library {
        int sodium_init();
        int crypto_box_keypair(byte[] pk, byte[] sk);
        int crypto_box_seal_open(byte[] out, byte[] cipher, long length, byte[] pk, byte[] sk);
        int crypto_secretbox_open_easy(byte[] out, byte[] cipher, long length, byte[] nonce, byte[] key);
    }
    private static final class Lib {
        static final Sodium S = Native.load("sodium", Sodium.class);
        static { if (S.sodium_init() < 0) throw new IllegalStateException("Sodium initialization failed"); }
    }

    /** Thrown when a sealed payload is corrupt, truncated, or not addressed to the given key. */
    public static final class CorruptException extends Exception {
        CorruptException() { super("sealed payload corrupt or truncated"); }
    }

    /** Hex X25519 key pair: {@code [publicHex, privateHex]}. */
    public static final class KeyPair {
        public final String publicHex, privateHex;
        KeyPair(String publicHex, String privateHex) { this.publicHex = publicHex; this.privateHex = privateHex; }
    }

    private V2Sealed() {}

    /** Decodes a 64-char hex X25519 key (public or private). */
    public static byte[] parseKey(String hexKey) {
        String s = hexKey == null ? "" : hexKey.trim();
        if (s.length() != 64) throw new IllegalArgumentException("key must be 64 hex characters");
        try {
            return Crypto.unhex(s);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("key must be 64 hex characters");
        }
    }

    /** Alias of {@link #parseKey} mirroring Go's ParsePublicKey. */
    public static byte[] parsePublicKey(String hexKey) { return parseKey(hexKey); }

    /** Creates a fresh X25519 key pair; publish publicHex as the binding's seal_public_key. */
    public static KeyPair generateSealKeyPair() {
        byte[] pk = new byte[32], sk = new byte[32];
        if (Lib.S.crypto_box_keypair(pk, sk) != 0) throw new IllegalStateException("keypair generation failed");
        try {
            return new KeyPair(Crypto.hex(pk), Crypto.hex(sk));
        } finally {
            Arrays.fill(sk, (byte) 0);
        }
    }

    /** Reports whether data starts with the sealed-payload magic. */
    public static boolean isSealed(byte[] head) {
        if (head == null || head.length < 4) return false;
        for (int i = 0; i < 4; i++) if (head[i] != MAGIC[i]) return false;
        return true;
    }

    /** Decrypts a complete sealed payload with the recipient key pair. */
    public static byte[] openSealed(byte[] sealed, byte[] publicKey, byte[] privateKey) throws CorruptException {
        if (publicKey == null || publicKey.length != 32 || privateKey == null || privateKey.length != 32) {
            throw new IllegalArgumentException("keys must be 32 bytes");
        }
        int header = 4 + SEALED_KEY_LEN + 16;
        if (sealed == null || sealed.length < header || !isSealed(sealed)) throw new CorruptException();
        byte[] key = new byte[32];
        try {
            byte[] sealedKey = Arrays.copyOfRange(sealed, 4, 4 + SEALED_KEY_LEN);
            if (Lib.S.crypto_box_seal_open(key, sealedKey, sealedKey.length, publicKey, privateKey) != 0) {
                throw new CorruptException();
            }
            byte[] prefix = Arrays.copyOfRange(sealed, 4 + SEALED_KEY_LEN, header);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int pos = header;
            for (long ctr = 0; ; ctr++) {
                if (sealed.length - pos < 4) throw new CorruptException();
                long len = ByteBuffer.wrap(sealed, pos, 4).getInt() & 0xffffffffL;
                pos += 4;
                if (len < SECRETBOX_OVERHEAD || len > CHUNK_SIZE + SECRETBOX_OVERHEAD || len > sealed.length - pos) {
                    throw new CorruptException();
                }
                int l = (int) len;
                byte[] frame = Arrays.copyOfRange(sealed, pos, pos + l);
                pos += l;
                boolean last = pos == sealed.length;
                byte[] nonce = ByteBuffer.allocate(24).put(prefix).putLong(last ? ctr | FINAL_FRAME_BIT : ctr).array();
                byte[] plain = new byte[l - SECRETBOX_OVERHEAD];
                if (Lib.S.crypto_secretbox_open_easy(plain, frame, l, nonce, key) != 0) throw new CorruptException();
                out.write(plain, 0, plain.length);
                if (last) return out.toByteArray();
            }
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }
}
