package dev.chainguard.fipstest.suites.scenarios;

import dev.chainguard.fipstest.harness.Expect;
import dev.chainguard.fipstest.harness.TestContext;
import dev.chainguard.fipstest.harness.TestSuite;
import dev.chainguard.fipstest.util.TestKeys;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.Set;

/**
 * KMS-style envelope encryption, the pattern data services use for at-rest
 * encryption: random DEK encrypts the payload with AES-GCM (streaming via
 * Cipher streams), the DEK travels wrapped by a KEK (AESKW or RSA-OAEP).
 */
public final class EnvelopeSuite implements TestSuite {

    private static final int PAYLOAD_SIZE = 1024 * 1024;
    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public String name() {
        return "scenarios.envelope";
    }

    @Override
    public Set<String> tags() {
        return Set.of("scenarios", "envelope", "gcm");
    }

    @Override
    public void register(TestContext ctx) {
        ctx.add("aeskw-kek/one-mebibyte-roundtrip", () -> {
            SecretKey kek = aesKey(256);
            Envelope envelope = seal(payload());

            Cipher wrap = Cipher.getInstance("AESKW", "BCFIPS");
            wrap.init(Cipher.WRAP_MODE, kek);
            byte[] wrappedDek = wrap.wrap(envelope.dek);

            Cipher unwrap = Cipher.getInstance("AESKW", "BCFIPS");
            unwrap.init(Cipher.UNWRAP_MODE, kek);
            SecretKey dek = (SecretKey) unwrap.unwrap(wrappedDek, "AES", Cipher.SECRET_KEY);
            Expect.assertArrayEquals(envelope.plaintext, open(envelope, dek),
                    "payload after AESKW unwrap");
        });

        ctx.add("rsa-oaep-kek/one-mebibyte-roundtrip", () -> {
            KeyPair kek = TestKeys.rsaWrap(2048);
            Envelope envelope = seal(payload());

            Cipher wrap = Cipher.getInstance("RSA/NONE/OAEPwithSHA256andMGF1Padding",
                    "BCFIPS");
            wrap.init(Cipher.WRAP_MODE, kek.getPublic());
            byte[] wrappedDek = wrap.wrap(envelope.dek);

            Cipher unwrap = Cipher.getInstance("RSA/NONE/OAEPwithSHA256andMGF1Padding",
                    "BCFIPS");
            unwrap.init(Cipher.UNWRAP_MODE, kek.getPrivate());
            SecretKey dek = (SecretKey) unwrap.unwrap(wrappedDek, "AES", Cipher.SECRET_KEY);
            Expect.assertArrayEquals(envelope.plaintext, open(envelope, dek),
                    "payload after RSA-OAEP unwrap");
        });

        ctx.add("negative/flipped-ciphertext-fails-on-stream-read", () -> {
            Envelope envelope = seal(payload());
            envelope.ciphertext[envelope.ciphertext.length / 3] ^= 0x02;
            Expect.mustFail("streaming GCM decrypt of tampered ciphertext", () ->
                    open(envelope, envelope.dek));
        });

        ctx.add("negative/wrapped-dek-bit-flip-fails-unwrap", () -> {
            SecretKey kek = aesKey(256);
            SecretKey dek = aesKey(256);
            Cipher wrap = Cipher.getInstance("AESKW", "BCFIPS");
            wrap.init(Cipher.WRAP_MODE, kek);
            byte[] wrappedDek = wrap.wrap(dek);
            wrappedDek[1] ^= 0x80;
            byte[] corrupted = wrappedDek;

            Cipher unwrap = Cipher.getInstance("AESKW", "BCFIPS");
            unwrap.init(Cipher.UNWRAP_MODE, kek);
            Expect.mustFail("unwrap of bit-flipped DEK", () ->
                    unwrap.unwrap(corrupted, "AES", Cipher.SECRET_KEY));
        });

        ctx.add("negative/swapped-iv-fails-tag-check", () -> {
            Envelope envelope = seal(payload());
            RANDOM.nextBytes(envelope.iv);
            Expect.mustFail("GCM decrypt with wrong IV", () ->
                    open(envelope, envelope.dek));
        });
    }

    private static final class Envelope {
        final byte[] plaintext;
        final byte[] ciphertext;
        final byte[] iv;
        final SecretKey dek;

        Envelope(byte[] plaintext, byte[] ciphertext, byte[] iv, SecretKey dek) {
            this.plaintext = plaintext;
            this.ciphertext = ciphertext;
            this.iv = iv;
            this.dek = dek;
        }
    }

    /** Encrypt through CipherOutputStream, the way services stream to disk. */
    private static Envelope seal(byte[] plaintext) throws Exception {
        SecretKey dek = aesKey(256);
        byte[] iv = new byte[12];
        RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BCFIPS");
        cipher.init(Cipher.ENCRYPT_MODE, dek, new GCMParameterSpec(128, iv));
        ByteArrayOutputStream sink = new ByteArrayOutputStream(plaintext.length + 16);
        try (CipherOutputStream out = new CipherOutputStream(sink, cipher)) {
            // Write in odd-sized chunks to exercise buffering.
            int offset = 0;
            while (offset < plaintext.length) {
                int n = Math.min(65531, plaintext.length - offset);
                out.write(plaintext, offset, n);
                offset += n;
            }
        }
        return new Envelope(plaintext, sink.toByteArray(), iv, dek);
    }

    /** Decrypt through CipherInputStream; tag failure surfaces as IOException. */
    private static byte[] open(Envelope envelope, SecretKey dek) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BCFIPS");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(dek.getEncoded(), "AES"),
                new GCMParameterSpec(128, envelope.iv));
        ByteArrayOutputStream sink = new ByteArrayOutputStream(envelope.plaintext.length);
        try (InputStream in = new CipherInputStream(
                new ByteArrayInputStream(envelope.ciphertext), cipher)) {
            byte[] buffer = new byte[8192];
            int n;
            while ((n = in.read(buffer)) > 0) {
                sink.write(buffer, 0, n);
            }
        } catch (IOException e) {
            throw e; // AEADBadTagException arrives wrapped in IOException
        }
        return sink.toByteArray();
    }

    private static SecretKey aesKey(int bits) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES", "BCFIPS");
        kg.init(bits);
        return kg.generateKey();
    }

    private static byte[] payload() {
        // The FIPS DRBG caps a single request at 262144 bits (SP 800-90A),
        // so large payloads must be filled in chunks - asserted explicitly
        // in primitives.drbg.
        byte[] payload = new byte[PAYLOAD_SIZE];
        byte[] chunk = new byte[16384];
        for (int offset = 0; offset < payload.length; offset += chunk.length) {
            RANDOM.nextBytes(chunk);
            System.arraycopy(chunk, 0, payload, offset,
                    Math.min(chunk.length, payload.length - offset));
        }
        return payload;
    }
}
