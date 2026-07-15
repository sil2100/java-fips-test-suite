package dev.chainguard.fipstest.suites.primitives;

import dev.chainguard.fipstest.harness.Expect;
import dev.chainguard.fipstest.harness.TestContext;
import dev.chainguard.fipstest.harness.TestFailure;
import dev.chainguard.fipstest.harness.TestSuite;
import dev.chainguard.fipstest.util.VectorFile;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.List;
import java.util.Set;

/**
 * Key wrapping (absorbs our FIPS image test suite key-wrap coverage): AESKW/AESKWP with
 * Wycheproof KATs (RFC 3394/5649 semantics incl. corrupt-wrap negatives),
 * RSA-OAEP wrapping of symmetric keys, and non-FIPS wrap rejections.
 * This is the "envelope encryption KEK" primitive real services use.
 */
public final class KeyWrapSuite implements TestSuite {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public String name() {
        return "primitives.keywrap";
    }

    @Override
    public Set<String> tags() {
        return Set.of("primitives", "keywrap");
    }

    @Override
    public void register(TestContext ctx) throws Exception {
        for (String alg : List.of("AESKW", "AESKWP")) {
            for (int kekBits : new int[] {128, 256}) {
                ctx.add(alg.toLowerCase() + "/kek" + kekBits + "/wrap-unwrap-roundtrip", () -> {
                    SecretKey kek = aesKey(kekBits);
                    SecretKey dek = aesKey(256);

                    Cipher wrap = Cipher.getInstance(alg, "BCFIPS");
                    wrap.init(Cipher.WRAP_MODE, kek);
                    byte[] wrapped = wrap.wrap(dek);

                    Cipher unwrap = Cipher.getInstance(alg, "BCFIPS");
                    unwrap.init(Cipher.UNWRAP_MODE, kek);
                    SecretKey unwrapped = (SecretKey) unwrap.unwrap(wrapped, "AES",
                            Cipher.SECRET_KEY);
                    Expect.assertArrayEquals(dek.getEncoded(), unwrapped.getEncoded(),
                            alg + " round-trip");
                });

                ctx.add(alg.toLowerCase() + "/kek" + kekBits + "/corrupt-unwrap-fails", () -> {
                    SecretKey kek = aesKey(kekBits);
                    SecretKey dek = aesKey(256);
                    Cipher wrap = Cipher.getInstance(alg, "BCFIPS");
                    wrap.init(Cipher.WRAP_MODE, kek);
                    byte[] wrapped = wrap.wrap(dek);
                    wrapped[3] ^= 0x40;

                    Cipher unwrap = Cipher.getInstance(alg, "BCFIPS");
                    unwrap.init(Cipher.UNWRAP_MODE, kek);
                    byte[] corrupted = wrapped;
                    Expect.mustFail(alg + " unwrap of corrupted blob", () ->
                            unwrap.unwrap(corrupted, "AES", Cipher.SECRET_KEY));
                });
            }
        }

        registerWycheproof(ctx, "AESKW", "aes-kw", "wrap/aes-kw-wycheproof.rsp");
        registerWycheproof(ctx, "AESKWP", "aes-kwp", "wrap/aes-kwp-wycheproof.rsp");

        // RSA-OAEP key transport of an AES key (the asymmetric KEK pattern).
        ctx.add("rsa-oaep-sha256/wrap-unwrap-roundtrip", () -> {
            KeyPair kp = rsaKeyPair(2048);
            SecretKey dek = aesKey(256);

            Cipher wrap = Cipher.getInstance("RSA/NONE/OAEPwithSHA256andMGF1Padding", "BCFIPS");
            wrap.init(Cipher.WRAP_MODE, kp.getPublic());
            byte[] wrapped = wrap.wrap(dek);

            Cipher unwrap = Cipher.getInstance("RSA/NONE/OAEPwithSHA256andMGF1Padding", "BCFIPS");
            unwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate());
            SecretKey unwrapped = (SecretKey) unwrap.unwrap(wrapped, "AES", Cipher.SECRET_KEY);
            Expect.assertArrayEquals(dek.getEncoded(), unwrapped.getEncoded(),
                    "RSA-OAEP wrap round-trip");
        });

        ctx.add("rsa-oaep-sha256/corrupt-unwrap-fails", () -> {
            KeyPair kp = rsaKeyPair(2048);
            SecretKey dek = aesKey(256);
            Cipher wrap = Cipher.getInstance("RSA/NONE/OAEPwithSHA256andMGF1Padding", "BCFIPS");
            wrap.init(Cipher.WRAP_MODE, kp.getPublic());
            byte[] wrapped = wrap.wrap(dek);
            wrapped[10] ^= 0x01;

            Cipher unwrap = Cipher.getInstance("RSA/NONE/OAEPwithSHA256andMGF1Padding", "BCFIPS");
            unwrap.init(Cipher.UNWRAP_MODE, kp.getPrivate());
            byte[] corrupted = wrapped;
            Expect.mustFail("RSA-OAEP unwrap of corrupted blob", () ->
                    unwrap.unwrap(corrupted, "AES", Cipher.SECRET_KEY));
        });

        // Non-FIPS wrap algorithms (our FIPS image test suite rejection list).
        for (String alg : List.of("CamelliaKW", "SEEDKW", "DESedeKW", "RC2KW")) {
            ctx.addApproved("rejected/" + alg.toLowerCase() + "-approved", () ->
                    Expect.mustFail(alg + " in approved mode", () ->
                            Cipher.getInstance(alg, "BCFIPS")));
        }
    }

    /**
     * Wycheproof KW/KWP: deterministic, so valid records check exact bytes in
     * both directions; invalid records must fail to unwrap.
     */
    private void registerWycheproof(TestContext ctx, String algorithm, String label,
                                    String file) throws Exception {
        VectorFile vf = ctx.vectors(file);
        PolicyRejections.Coverage coverage = new PolicyRejections.Coverage(
                (int) vf.records().stream()
                        .filter(r -> "valid".equals(r.result())).count());
        for (VectorFile.Record rec : vf.records()) {
            ctx.add(label + "/wycheproof/" + rec.id(), () -> {
                byte[] kek = rec.bytes("key");
                byte[] msg = rec.bytes("msg");
                byte[] ct = rec.bytes("ct");

                byte[] unwrapped;
                try {
                    Cipher unwrap = Cipher.getInstance(algorithm, "BCFIPS");
                    unwrap.init(Cipher.UNWRAP_MODE, new SecretKeySpec(kek, "AES"));
                    unwrapped = ((SecretKey) unwrap.unwrap(ct, "AES", Cipher.SECRET_KEY))
                            .getEncoded();
                } catch (Throwable t) {
                    if (rec.expectedValid()) {
                        if (!PolicyRejections.isPolicyRejection(t)) {
                            throw new TestFailure(label + " " + rec.id()
                                    + " valid vector rejected with a non-policy error ("
                                    + rec.comment() + ")", t);
                        }
                        if ("valid".equals(rec.result())) {
                            coverage.policyRejected++;
                        }
                        System.out.println("INFO|" + label + " " + rec.id()
                                + " valid vector rejected by policy: " + t);
                    }
                    return; // rejection is the expected outcome for invalid
                }
                if (!rec.expectedValid()) {
                    throw new TestFailure(label + " " + rec.id()
                            + " invalid vector unwrapped (failure to fail: "
                            + rec.comment() + ")");
                }
                Expect.assertArrayEquals(msg, unwrapped,
                        label + " " + rec.id() + " unwrapped key");
                if ("valid".equals(rec.result())) {
                    coverage.verified++;
                }

                Cipher wrap = Cipher.getInstance(algorithm, "BCFIPS");
                wrap.init(Cipher.WRAP_MODE, new SecretKeySpec(kek, "AES"));
                Expect.assertArrayEquals(ct,
                        wrap.wrap(new SecretKeySpec(msg, "AES")),
                        label + " " + rec.id() + " deterministic wrap");
            });
        }
        ctx.add(label + "/wycheproof/coverage-floor", () -> coverage.assertFloor(label));
    }

    private static SecretKey aesKey(int bits) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES", "BCFIPS");
        kg.init(bits);
        return kg.generateKey();
    }

    private static KeyPair rsaKeyPair(int bits) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BCFIPS");
        kpg.initialize(bits);
        return kpg.generateKeyPair();
    }
}
