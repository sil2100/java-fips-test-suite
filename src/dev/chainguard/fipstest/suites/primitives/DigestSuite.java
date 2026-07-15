package dev.chainguard.fipstest.suites.primitives;

import dev.chainguard.fipstest.harness.Expect;
import dev.chainguard.fipstest.harness.TestContext;
import dev.chainguard.fipstest.harness.TestSuite;
import dev.chainguard.fipstest.util.Hex;

import dev.chainguard.fipstest.util.VectorFile;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Message digest coverage: availability matrix (absorbed from
 * bcfips-policy-140-3 Test.java), inline known-answer checks for the
 * workhorse algorithms, and negative availability for non-FIPS digests.
 * Vector-file driven CAVP KATs and MCT arrive with the vectors phase.
 */
public final class DigestSuite implements TestSuite {

    private static final List<String> SUPPORTED = List.of(
            "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512",
            "SHA-512(224)", "SHA-512(256)",
            "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
            "SHAKE128", "SHAKE256");

    /**
     * Rejected in approved mode; observed bc-fips 2.1.1 behavior is that all
     * of these come back in unapproved mode via the provider's "general"
     * algorithm set - both directions are asserted so drift is surfaced.
     */
    private static final List<String> NON_FIPS_DIGESTS = List.of(
            "GOST3411", "GOST3411-2012-256", "GOST3411-2012-512",
            "RIPEMD128", "RIPEMD160", "RIPEMD256", "RIPEMD320",
            "Tiger", "Whirlpool");

    /** KATs for "abc" - classic single-block known answers (FIPS 180-4 / 202 examples). */
    private static final Map<String, String> ABC_KAT = Map.of(
            "SHA-1", "a9993e364706816aba3e25717850c26c9cd0d89d",
            "SHA-224", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
            "SHA-256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "SHA-384", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                    + "8086072ba1e7cc2358baeca134c825a7",
            "SHA-512", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                    + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "SHA3-256", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
            "SHA3-512", "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
                    + "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");

    @Override
    public String name() {
        return "primitives.digest";
    }

    @Override
    public Set<String> tags() {
        return Set.of("primitives", "digest");
    }

    @Override
    public void register(TestContext ctx) throws Exception {
        for (String alg : SUPPORTED) {
            ctx.add(alg + "/available", () -> {
                MessageDigest md = MessageDigest.getInstance(alg, "BCFIPS");
                Expect.assertEquals("BCFIPS", md.getProvider().getName(), "digest provider");
            });
            ctx.add(alg + "/digest-and-reset-consistency", () -> {
                MessageDigest md = MessageDigest.getInstance(alg, "BCFIPS");
                byte[] one = md.digest("The quick brown fox".getBytes(StandardCharsets.US_ASCII));
                md.reset();
                md.update("The quick brown ".getBytes(StandardCharsets.US_ASCII));
                md.update("fox".getBytes(StandardCharsets.US_ASCII));
                byte[] two = md.digest();
                Expect.assertArrayEquals(one, two, alg + " one-shot vs incremental");
                Expect.assertTrue(one.length > 0, "empty digest output");
            });
        }

        for (Map.Entry<String, String> kat : ABC_KAT.entrySet()) {
            ctx.add(kat.getKey() + "/kat-abc", () -> {
                MessageDigest md = MessageDigest.getInstance(kat.getKey(), "BCFIPS");
                byte[] digest = md.digest("abc".getBytes(StandardCharsets.US_ASCII));
                Expect.assertArrayEquals(Hex.decode(kat.getValue()), digest,
                        kat.getKey() + "(\"abc\")");
            });
        }

        for (String alg : NON_FIPS_DIGESTS) {
            ctx.addApproved(alg + "/rejected-approved", () ->
                    Expect.mustThrow(NoSuchAlgorithmException.class,
                            alg + " from BCFIPS in approved mode",
                            () -> MessageDigest.getInstance(alg, "BCFIPS")));
            ctx.addUnapproved(alg + "/available-unapproved", () -> {
                MessageDigest md = MessageDigest.getInstance(alg, "BCFIPS");
                Expect.assertTrue(md.digest("abc".getBytes(StandardCharsets.US_ASCII)).length > 0,
                        alg + " digest output");
            });
        }

        // MD5 semantics are mode-, provider- and CONFIG-dependent:
        // - approved mode default: rejected by BCFIPS
        // - approved mode with org.bouncycastle.jsse.enable_md5=true (the
        //   openjdk-fips >= 25 packaged config, per FIPS 140-3 IG 2.4.A for
        //   non-security use): available from BCFIPS
        // - unapproved mode: always available from BCFIPS
        // - default lookup: SUN if installed, else follows the BCFIPS rules
        ctx.addApproved("MD5/bcfips-follows-enable-md5-property", () -> {
            if (md5Enabled()) {
                MessageDigest md5 = MessageDigest.getInstance("MD5", "BCFIPS");
                Expect.assertArrayEquals(
                        Hex.decode("900150983cd24fb0d6963f7d28e17f72"),
                        md5.digest("abc".getBytes(StandardCharsets.US_ASCII)),
                        "MD5(\"abc\") with enable_md5=true");
            } else {
                Expect.mustThrow(NoSuchAlgorithmException.class,
                        "MD5 from BCFIPS (enable_md5 not set)",
                        () -> MessageDigest.getInstance("MD5", "BCFIPS"));
            }
        });

        ctx.addUnapproved("MD5/available-from-bcfips-unapproved", () -> {
            MessageDigest md5 = MessageDigest.getInstance("MD5", "BCFIPS");
            byte[] d = md5.digest("abc".getBytes(StandardCharsets.US_ASCII));
            Expect.assertArrayEquals(Hex.decode("900150983cd24fb0d6963f7d28e17f72"), d,
                    "MD5(\"abc\")");
        });

        registerCavpKats(ctx);
        registerMonteCarlo(ctx);

        ctx.add("MD5/default-lookup-follows-java-security", () -> {
            // Provider-less MD5 lookup resolves via SUN where installed
            // (JDK <= 21 policy configs), via BCFIPS when the packaged config
            // sets enable_md5 (JDK >= 25 stream, no SUN), and must fail when
            // neither applies in approved mode.
            boolean sunPresent = Security.getProvider("SUN") != null;
            boolean bcfipsMd5Allowed = md5Enabled()
                    || ctx.mode() == dev.chainguard.fipstest.harness.Mode.UNAPPROVED;
            try {
                MessageDigest md = MessageDigest.getInstance("MD5");
                String provider = md.getProvider().getName();
                if ("BCFIPS".equals(provider)) {
                    Expect.assertTrue(bcfipsMd5Allowed,
                            "MD5 from BCFIPS although neither enable_md5 nor"
                                    + " unapproved mode applies");
                } else {
                    Expect.assertTrue(sunPresent && "SUN".equals(provider),
                            "MD5 resolved via unexpected provider " + provider);
                }
            } catch (NoSuchAlgorithmException e) {
                Expect.assertTrue(!sunPresent && !bcfipsMd5Allowed,
                        "MD5 unavailable although the configuration provides it");
            }
        });
    }

    /** The packaged FIPS 140-3 IG 2.4.A switch (security or system property). */
    private static boolean md5Enabled() {
        String property = Security.getProperty("org.bouncycastle.jsse.enable_md5");
        if (property == null) {
            property = System.getProperty("org.bouncycastle.jsse.enable_md5");
        }
        return Boolean.parseBoolean(property);
    }

    /** File-name stems of the curated CAVP vector files under vectors/digest. */
    private static final List<String> CAVP_STEMS = List.of(
            "sha-1", "sha-224", "sha-256", "sha-384", "sha-512",
            "sha-512-224", "sha-512-256",
            "sha3-224", "sha3-256", "sha3-384", "sha3-512");

    private void registerCavpKats(TestContext ctx) throws Exception {
        for (String stem : CAVP_STEMS) {
            for (String kind : List.of("short-kat", "long-kat")) {
                VectorFile vf = ctx.vectors("digest/" + stem + "-" + kind + ".rsp");
                String algorithm = vf.records().get(0).get("algorithm");
                for (VectorFile.Record rec : vf.records()) {
                    int lenBits = rec.intValue("Len");
                    ctx.add(algorithm + "/cavp-" + kind + "/len" + lenBits, () -> {
                        // CAVP quirk: Len is in bits and a zero-length message
                        // is encoded as Msg = 00, which must be ignored.
                        byte[] msg = lenBits == 0 ? new byte[0] : rec.bytes("Msg");
                        Expect.assertEquals(lenBits / 8, msg.length, "CAVP Msg length");
                        MessageDigest md = MessageDigest.getInstance(algorithm, "BCFIPS");
                        Expect.assertArrayEquals(rec.bytes("MD"), md.digest(msg),
                                algorithm + " CAVP KAT Len=" + lenBits);
                    });
                }
            }
        }
    }

    /**
     * CAVP Monte Carlo tests. The checkpoints chain (checkpoint j seeds outer
     * iteration j+1), so reduced depth = verify the first N checkpoints with
     * exact known answers; full depth verifies all 100.
     *
     * SHA-2 MCT: seed three-message window, 1000 inner iterations of
     * H(md[i-3] || md[i-2] || md[i-1]). SHA-3 MCT: simple 1000-step chain
     * of H(md).
     */
    private void registerMonteCarlo(TestContext ctx) throws Exception {
        int outerLimit = ctx.mctDepth() == TestContext.MctDepth.FULL ? 100 : 4;
        for (String stem : CAVP_STEMS) {
            VectorFile vf = ctx.vectors("digest/" + stem + "-mct.rsp");
            String algorithm = vf.records().get(0).get("algorithm");
            ctx.add(algorithm + "/cavp-mct/outer" + outerLimit,
                    Set.of("mct", "slow"), java.util.EnumSet.allOf(
                            dev.chainguard.fipstest.harness.Mode.class), () -> {
                List<VectorFile.Record> records = vf.records();
                byte[] seed = records.get(0).bytes("Seed");
                boolean sha3 = algorithm.startsWith("SHA3");
                MessageDigest md = MessageDigest.getInstance(algorithm, "BCFIPS");
                for (int outer = 0; outer < outerLimit; outer++) {
                    byte[] checkpoint;
                    if (sha3) {
                        byte[] current = seed;
                        for (int i = 0; i < 1000; i++) {
                            current = md.digest(current);
                        }
                        checkpoint = current;
                    } else {
                        byte[] a = seed;
                        byte[] b = seed;
                        byte[] c = seed;
                        for (int i = 0; i < 1000; i++) {
                            md.update(a);
                            md.update(b);
                            md.update(c);
                            byte[] next = md.digest();
                            a = b;
                            b = c;
                            c = next;
                        }
                        checkpoint = c;
                    }
                    VectorFile.Record expected = records.get(1 + outer);
                    Expect.assertEquals(outer, expected.intValue("COUNT"),
                            "MCT record order");
                    Expect.assertArrayEquals(expected.bytes("MD"), checkpoint,
                            algorithm + " MCT checkpoint " + outer);
                    seed = checkpoint;
                }
            });
        }
    }
}
