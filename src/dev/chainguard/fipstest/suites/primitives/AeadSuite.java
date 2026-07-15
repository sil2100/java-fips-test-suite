package dev.chainguard.fipstest.suites.primitives;

import dev.chainguard.fipstest.harness.Expect;
import dev.chainguard.fipstest.harness.TestContext;
import dev.chainguard.fipstest.harness.TestSuite;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
import java.util.Set;

/**
 * AEAD coverage: AES-GCM parameter matrix with round-trips, the full tamper
 * set (every authenticated input), and AES-CCM. This is where a silent
 * wrong-answer regression in a provider update is most dangerous - GCM is
 * what TLS and application-level envelope encryption actually use.
 */
public final class AeadSuite implements TestSuite {

    private static final int[] KEY_SIZES = {128, 192, 256};
    private static final int[] TAG_BITS = {96, 104, 112, 120, 128};

    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public String name() {
        return "primitives.aead";
    }

    @Override
    public Set<String> tags() {
        return Set.of("primitives", "aead", "gcm");
    }

    @Override
    public void register(TestContext ctx) throws Exception {
        for (int keySize : KEY_SIZES) {
            for (int tagBits : TAG_BITS) {
                ctx.add("aes-gcm/k" + keySize + "/t" + tagBits + "/roundtrip", () ->
                        gcmRoundTrip(keySize, tagBits, 12, true));
            }
            // Non-default IV length and no AAD.
            ctx.add("aes-gcm/k" + keySize + "/iv16/no-aad/roundtrip", () ->
                    gcmRoundTrip(keySize, 128, 16, false));
            // Empty plaintext (pure authentication).
            ctx.add("aes-gcm/k" + keySize + "/empty-plaintext/roundtrip", () -> {
                SecretKey key = aesKey(keySize);
                byte[] iv = randomIv(12);
                byte[] aad = "header".getBytes();

                Cipher enc = gcm(Cipher.ENCRYPT_MODE, key, iv, 128);
                enc.updateAAD(aad);
                byte[] tagOnly = enc.doFinal(new byte[0]);
                Expect.assertEquals(16, tagOnly.length, "GCM tag-only output length");

                Cipher dec = gcm(Cipher.DECRYPT_MODE, key, iv, 128);
                dec.updateAAD(aad);
                Expect.assertEquals(0, dec.doFinal(tagOnly).length, "decrypted length");
            });
        }

        // GCM known answer: NIST GCM spec test case 13 (AES-256, empty PT/AAD).
        ctx.add("aes-gcm/k256/nist-kat-empty", () -> {
            byte[] key = new byte[32];
            byte[] iv = new byte[12];
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding", "BCFIPS");
            c.init(Cipher.ENCRYPT_MODE,
                    new javax.crypto.spec.SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, iv));
            byte[] out = c.doFinal(new byte[0]);
            Expect.assertArrayEquals(
                    dev.chainguard.fipstest.util.Hex.decode("530f8afbc74536b9a963b4f1c4cb738b"),
                    out, "AES-256-GCM empty-input tag (NIST test case 13)");
        });

        registerTamperCases(ctx);

        // CCM: 12-byte nonce, common tag sizes.
        for (int keySize : KEY_SIZES) {
            ctx.add("aes-ccm/k" + keySize + "/roundtrip", () -> {
                SecretKey key = aesKey(keySize);
                byte[] nonce = randomIv(12);
                byte[] aad = "ccm-aad".getBytes();
                byte[] plaintext = new byte[48];
                RANDOM.nextBytes(plaintext);

                Cipher enc = Cipher.getInstance("AES/CCM/NoPadding", "BCFIPS");
                enc.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
                enc.updateAAD(aad);
                byte[] ciphertext = enc.doFinal(plaintext);

                Cipher dec = Cipher.getInstance("AES/CCM/NoPadding", "BCFIPS");
                dec.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
                dec.updateAAD(aad);
                Expect.assertArrayEquals(plaintext, dec.doFinal(ciphertext), "CCM round-trip");
            });
        }

        registerWycheproof(ctx, "AES/GCM/NoPadding", "aes-gcm",
                "aead/aes-gcm-wycheproof.rsp");
        registerWycheproof(ctx, "AES/CCM/NoPadding", "aes-ccm",
                "aead/aes-ccm-wycheproof.rsp");

        ctx.addApproved("chacha20-poly1305/rejected-approved", () ->
                Expect.mustFail("ChaCha20-Poly1305 in approved mode", () ->
                        Cipher.getInstance("ChaCha20-Poly1305", "BCFIPS")));

        ctx.addApproved("aes-eax/rejected-approved", () ->
                Expect.mustFail("AES/EAX in approved mode", () ->
                        Cipher.getInstance("AES/EAX/NoPadding", "BCFIPS")));
    }

    /**
     * Wycheproof vector cases, decrypt-direction primary:
     * - result=valid: decryption must succeed and yield msg. A tag failure is
     *   a FAIL; a parameter-policy rejection (e.g. approved mode refusing an
     *   exotic IV size) is tolerated and logged, since Wycheproof "valid"
     *   only means cryptographically consistent, not FIPS-acceptable.
     * - result=invalid: decryption must be rejected one way or another;
     *   success is a FAIL (failure to fail).
     * Deterministic encrypt cross-check runs when decryption succeeded.
     */
    private void registerWycheproof(TestContext ctx, String transformation,
                                    String label, String vectorFile) throws Exception {
        dev.chainguard.fipstest.util.VectorFile vf = ctx.vectors(vectorFile);
        PolicyRejections.Coverage coverage = new PolicyRejections.Coverage(
                (int) vf.records().stream()
                        .filter(r -> "valid".equals(r.result())).count());
        for (dev.chainguard.fipstest.util.VectorFile.Record rec : vf.records()) {
            ctx.add(label + "/wycheproof/" + rec.id(), () -> {
                byte[] key = rec.bytes("key");
                byte[] iv = rec.bytes("iv");
                byte[] aad = rec.bytes("aad");
                byte[] msg = rec.bytes("msg");
                byte[] ct = rec.bytes("ct");
                byte[] tag = rec.bytes("tag");
                int tagBits = tag.length * 8;

                byte[] ctAndTag = new byte[ct.length + tag.length];
                System.arraycopy(ct, 0, ctAndTag, 0, ct.length);
                System.arraycopy(tag, 0, ctAndTag, ct.length, tag.length);

                byte[] decrypted;
                try {
                    Cipher dec = Cipher.getInstance(transformation, "BCFIPS");
                    dec.init(Cipher.DECRYPT_MODE,
                            new javax.crypto.spec.SecretKeySpec(key, "AES"),
                            new GCMParameterSpec(tagBits, iv));
                    if (aad.length > 0) {
                        dec.updateAAD(aad);
                    }
                    decrypted = dec.doFinal(ctAndTag);
                } catch (AEADBadTagException e) {
                    if (rec.expectedValid()) {
                        throw new dev.chainguard.fipstest.harness.TestFailure(
                                "valid vector rejected as bad tag ("
                                        + rec.comment() + ")", e);
                    }
                    return; // expected rejection
                } catch (Throwable t) {
                    if (rec.expectedValid()) {
                        if (!PolicyRejections.isPolicyRejection(t)) {
                            throw new dev.chainguard.fipstest.harness.TestFailure(
                                    label + " " + rec.id() + " valid vector rejected"
                                            + " with a non-policy error ("
                                            + rec.comment() + ")", t);
                        }
                        // Parameter policy rejection of a cryptographically
                        // valid vector - tolerated, but visible in the log.
                        if ("valid".equals(rec.result())) {
                            coverage.policyRejected++;
                        }
                        System.out.println("INFO|" + label + " " + rec.id()
                                + " valid vector rejected by policy: " + t);
                        return;
                    }
                    return; // expected rejection
                }

                if (!rec.expectedValid()) {
                    // Some records are "invalid" by parameter policy only
                    // (their crypto is internally consistent). bc-fips 2.1.x
                    // accepts e.g. sub-32-bit CCM tag sizes at the JCA layer;
                    // record it, but do not fail the provider for it.
                    String flags = rec.getOrDefault("flags", "");
                    if (flags.contains("InvalidTagSize") || flags.contains("InsecureTagSize")) {
                        System.out.println("INFO|" + label + " " + rec.id()
                                + " policy-invalid vector accepted by provider (flags="
                                + flags + ")");
                        return;
                    }
                    throw new dev.chainguard.fipstest.harness.TestFailure(
                            "invalid vector accepted (" + rec.comment()
                                    + ", flags=" + flags + ")");
                }
                Expect.assertArrayEquals(msg, decrypted,
                        label + " " + rec.id() + " plaintext (" + rec.comment() + ")");
                if ("valid".equals(rec.result())) {
                    coverage.verified++;
                }

                // Deterministic re-encrypt cross-check. Encryption may hit
                // stricter IV policy than decryption - tolerated and logged.
                byte[] reEncrypted;
                try {
                    Cipher enc = Cipher.getInstance(transformation, "BCFIPS");
                    enc.init(Cipher.ENCRYPT_MODE,
                            new javax.crypto.spec.SecretKeySpec(key, "AES"),
                            new GCMParameterSpec(tagBits, iv));
                    if (aad.length > 0) {
                        enc.updateAAD(aad);
                    }
                    reEncrypted = enc.doFinal(msg);
                } catch (Throwable t) {
                    System.out.println("INFO|" + label + " " + rec.id()
                            + " re-encryption rejected by policy: " + t);
                    return;
                }
                Expect.assertArrayEquals(ctAndTag, reEncrypted,
                        label + " " + rec.id() + " re-encryption");
            });
        }
        // A provider throwing across a whole parameter corner must not pass
        // the file wholesale: at least one valid record must have verified.
        ctx.add(label + "/wycheproof/coverage-floor", () ->
                coverage.assertFloor(label));
    }

    private void registerTamperCases(TestContext ctx) {
        ctx.add("aes-gcm/tamper/ciphertext-bit-flip", () -> tamper(TamperKind.CIPHERTEXT));
        ctx.add("aes-gcm/tamper/tag-bit-flip", () -> tamper(TamperKind.TAG));
        ctx.add("aes-gcm/tamper/aad-modified", () -> tamper(TamperKind.AAD));
        ctx.add("aes-gcm/tamper/wrong-key", () -> tamper(TamperKind.WRONG_KEY));
        ctx.add("aes-gcm/tamper/wrong-iv", () -> tamper(TamperKind.WRONG_IV));
        ctx.add("aes-gcm/tamper/truncated-ciphertext", () -> tamper(TamperKind.TRUNCATED));
    }

    private enum TamperKind { CIPHERTEXT, TAG, AAD, WRONG_KEY, WRONG_IV, TRUNCATED }

    /**
     * Encrypt-then-corrupt: every corruption of authenticated input must
     * surface as AEADBadTagException on doFinal - never partial plaintext.
     */
    private static void tamper(TamperKind kind) throws Exception {
        SecretKey key = aesKey(256);
        byte[] iv = randomIv(12);
        byte[] aad = "authenticated-header".getBytes();
        byte[] plaintext = new byte[64];
        RANDOM.nextBytes(plaintext);

        Cipher enc = gcm(Cipher.ENCRYPT_MODE, key, iv, 128);
        enc.updateAAD(aad);
        byte[] ciphertext = enc.doFinal(plaintext);

        byte[] corrupted = ciphertext.clone();
        byte[] decryptAad = aad;
        byte[] decryptIv = iv;
        SecretKey decryptKey = key;
        switch (kind) {
            case CIPHERTEXT:
                corrupted[0] ^= 0x01;
                break;
            case TAG:
                corrupted[corrupted.length - 1] ^= 0x01;
                break;
            case AAD:
                decryptAad = "Authenticated-header".getBytes();
                break;
            case WRONG_KEY:
                decryptKey = aesKey(256);
                break;
            case WRONG_IV:
                decryptIv = randomIv(12);
                break;
            case TRUNCATED:
                corrupted = java.util.Arrays.copyOf(ciphertext, ciphertext.length - 4);
                break;
            default:
                throw new IllegalStateException();
        }

        final Cipher dec = gcm(Cipher.DECRYPT_MODE, decryptKey, decryptIv, 128);
        final byte[] aadToUse = decryptAad;
        final byte[] input = corrupted;
        Expect.mustThrow(AEADBadTagException.class, "GCM decrypt after " + kind, () -> {
            dec.updateAAD(aadToUse);
            dec.doFinal(input);
        });
    }

    private static void gcmRoundTrip(int keySize, int tagBits, int ivLen, boolean withAad)
            throws Exception {
        SecretKey key = aesKey(keySize);
        byte[] iv = randomIv(ivLen);
        byte[] plaintext = new byte[100];
        RANDOM.nextBytes(plaintext);

        Cipher enc = gcm(Cipher.ENCRYPT_MODE, key, iv, tagBits);
        if (withAad) {
            enc.updateAAD("aad".getBytes());
        }
        byte[] ciphertext = enc.doFinal(plaintext);
        Expect.assertEquals(plaintext.length + tagBits / 8, ciphertext.length,
                "GCM ciphertext length");

        Cipher dec = gcm(Cipher.DECRYPT_MODE, key, iv, tagBits);
        if (withAad) {
            dec.updateAAD("aad".getBytes());
        }
        Expect.assertArrayEquals(plaintext, dec.doFinal(ciphertext), "GCM round-trip");
    }

    private static Cipher gcm(int mode, SecretKey key, byte[] iv, int tagBits) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding", "BCFIPS");
        c.init(mode, key, new GCMParameterSpec(tagBits, iv));
        return c;
    }

    private static SecretKey aesKey(int bits) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES", "BCFIPS");
        kg.init(bits);
        return kg.generateKey();
    }

    private static byte[] randomIv(int len) {
        byte[] iv = new byte[len];
        RANDOM.nextBytes(iv);
        return iv;
    }
}
