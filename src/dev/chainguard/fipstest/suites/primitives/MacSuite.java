package dev.chainguard.fipstest.suites.primitives;

import dev.chainguard.fipstest.harness.Capabilities;
import dev.chainguard.fipstest.harness.Expect;
import dev.chainguard.fipstest.harness.TestContext;
import dev.chainguard.fipstest.harness.TestFailure;
import dev.chainguard.fipstest.harness.TestSuite;
import dev.chainguard.fipstest.util.VectorFile;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * MAC coverage: HMAC family round-trips and Wycheproof KATs (incl. truncated
 * tags and wrong-tag negatives), AES-CMAC vectors, GMAC round-trip, KMAC
 * capability probes, and non-FIPS MAC rejections.
 */
public final class MacSuite implements TestSuite {

    private static final List<String> HMACS = List.of(
            "HmacSHA1", "HmacSHA224", "HmacSHA256", "HmacSHA384", "HmacSHA512",
            "HmacSHA3-256", "HmacSHA3-512");

    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public String name() {
        return "primitives.mac";
    }

    @Override
    public Set<String> tags() {
        return Set.of("primitives", "mac", "hmac");
    }

    @Override
    public void register(TestContext ctx) throws Exception {
        for (String alg : HMACS) {
            ctx.add(alg + "/roundtrip-keygen", () -> {
                KeyGenerator kg = KeyGenerator.getInstance(alg, "BCFIPS");
                SecretKey key = kg.generateKey();
                Mac mac = Mac.getInstance(alg, "BCFIPS");
                mac.init(key);
                byte[] one = mac.doFinal("The quick brown fox".getBytes());
                mac.reset();
                mac.update("The quick brown ".getBytes());
                mac.update("fox".getBytes());
                Expect.assertArrayEquals(one, mac.doFinal(), alg + " incremental vs one-shot");
            });

            ctx.add(alg + "/flipped-message-differs", () -> {
                Mac mac = Mac.getInstance(alg, "BCFIPS");
                byte[] keyBytes = new byte[32];
                RANDOM.nextBytes(keyBytes);
                mac.init(new SecretKeySpec(keyBytes, alg));
                byte[] tagA = mac.doFinal("message-a".getBytes());
                byte[] tagB = mac.doFinal("message-b".getBytes());
                Expect.assertTrue(!Arrays.equals(tagA, tagB),
                        alg + " identical MACs for different messages");
            });
        }

        registerWycheproofHmac(ctx, "HmacSHA256", "mac/hmac-sha256-wycheproof.rsp");
        registerWycheproofHmac(ctx, "HmacSHA512", "mac/hmac-sha512-wycheproof.rsp");
        registerWycheproofCmac(ctx, "mac/aes-cmac-wycheproof.rsp");

        // GMAC: JCA registration name varies; probe the known spellings.
        ctx.add("gmac/roundtrip", () -> {
            String name = firstAvailableMac("AES-GMAC", "AESGMAC", "GMAC");
            Mac mac = Mac.getInstance(name, "BCFIPS");
            byte[] keyBytes = new byte[16];
            byte[] iv = new byte[12];
            RANDOM.nextBytes(keyBytes);
            RANDOM.nextBytes(iv);
            mac.init(new SecretKeySpec(keyBytes, "AES"), new IvParameterSpec(iv));
            byte[] tag1 = mac.doFinal("gmac-data".getBytes());
            mac.init(new SecretKeySpec(keyBytes, "AES"), new IvParameterSpec(iv));
            byte[] tag2 = mac.doFinal("gmac-data".getBytes());
            Expect.assertArrayEquals(tag1, tag2, "GMAC determinism");
            Expect.assertTrue(tag1.length > 0, "GMAC tag empty");
        });

        // KMAC arrived later in the bc-fips line - capability-gated.
        for (String kmac : List.of("KMAC128", "KMAC256")) {
            ctx.add(kmac + "/roundtrip-if-available", () -> {
                Capabilities.require("Mac", kmac, "BCFIPS");
                Mac mac = Mac.getInstance(kmac, "BCFIPS");
                byte[] keyBytes = new byte[32];
                RANDOM.nextBytes(keyBytes);
                mac.init(new SecretKeySpec(keyBytes, kmac));
                Expect.assertTrue(mac.doFinal("kmac-data".getBytes()).length > 0,
                        kmac + " output");
            });
        }

        ctx.addApproved("hmac-md5/rejected-approved", () ->
                Expect.mustFail("HmacMD5 in approved mode", () -> {
                    Mac mac = Mac.getInstance("HmacMD5", "BCFIPS");
                    mac.init(new SecretKeySpec(new byte[16], "HmacMD5"));
                    mac.doFinal("x".getBytes());
                }));
    }

    /**
     * Wycheproof HMAC semantics: tagSize may truncate; a computed-prefix
     * mismatch on an invalid record IS the expected outcome.
     */
    private void registerWycheproofHmac(TestContext ctx, String algorithm, String file)
            throws Exception {
        registerWycheproofMac(ctx, algorithm.toLowerCase(), algorithm, algorithm, file);
    }

    private void registerWycheproofCmac(TestContext ctx, String file) throws Exception {
        registerWycheproofMac(ctx, "aes-cmac", "AESCMAC", "AES", file);
    }

    private void registerWycheproofMac(TestContext ctx, String label, String algorithm,
                                       String keyAlg, String file) throws Exception {
        VectorFile vf = ctx.vectors(file);
        PolicyRejections.Coverage coverage = new PolicyRejections.Coverage(
                (int) vf.records().stream()
                        .filter(r -> "valid".equals(r.result())).count());
        for (VectorFile.Record rec : vf.records()) {
            ctx.add(label + "/wycheproof/" + rec.id(), () ->
                    checkMacVector(algorithm, rec, rec.bytes("key"), keyAlg, coverage));
        }
        ctx.add(label + "/wycheproof/coverage-floor", () -> coverage.assertFloor(label));
    }

    private static void checkMacVector(String algorithm, VectorFile.Record rec,
                                       byte[] key, String keyAlg,
                                       PolicyRejections.Coverage coverage) throws Throwable {
        byte[] expectedTag = rec.bytes("tag");
        byte[] computed;
        try {
            Mac mac = Mac.getInstance(algorithm, "BCFIPS");
            mac.init(new SecretKeySpec(key, keyAlg));
            computed = mac.doFinal(rec.bytes("msg"));
        } catch (Throwable t) {
            if (rec.expectedValid()) {
                if (!PolicyRejections.isPolicyRejection(t)) {
                    throw new TestFailure(algorithm + " " + rec.id()
                            + " valid vector rejected with a non-policy error ("
                            + rec.comment() + ")", t);
                }
                // e.g. approved mode refusing short HMAC keys - a policy
                // rejection of a cryptographically valid vector.
                if ("valid".equals(rec.result())) {
                    coverage.policyRejected++;
                }
                System.out.println("INFO|" + algorithm + " " + rec.id()
                        + " valid vector rejected by policy: " + t);
                return;
            }
            return;
        }
        if (computed.length < expectedTag.length) {
            if (!rec.expectedValid()) {
                return; // e.g. oversized tag in an invalid record
            }
            throw new TestFailure(algorithm + " " + rec.id() + ": computed tag shorter ("
                    + computed.length + ") than vector tag (" + expectedTag.length + ")");
        }
        boolean matches = MessageDigest.isEqual(
                Arrays.copyOf(computed, expectedTag.length), expectedTag);
        if (rec.expectedValid() && !matches) {
            throw new TestFailure(algorithm + " " + rec.id() + " tag mismatch ("
                    + rec.comment() + ")");
        }
        if (!rec.expectedValid() && matches) {
            throw new TestFailure(algorithm + " " + rec.id()
                    + " invalid vector matched (failure to fail: " + rec.comment() + ")");
        }
        if (rec.expectedValid() && "valid".equals(rec.result())) {
            coverage.verified++;
        }
    }

    private static String firstAvailableMac(String... names) {
        for (String name : names) {
            if (Capabilities.has("Mac", name, "BCFIPS")) {
                return name;
            }
        }
        throw new dev.chainguard.fipstest.harness.SkipException(
                "no GMAC registration found under: " + String.join(", ", names));
    }
}
