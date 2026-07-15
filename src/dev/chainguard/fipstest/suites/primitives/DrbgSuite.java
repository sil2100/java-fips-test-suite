package dev.chainguard.fipstest.suites.primitives;

import dev.chainguard.fipstest.harness.Expect;
import dev.chainguard.fipstest.harness.TestContext;
import dev.chainguard.fipstest.harness.TestSuite;
import dev.chainguard.fipstest.util.Hex;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.crypto.EntropySource;
import org.bouncycastle.crypto.EntropySourceProvider;
import org.bouncycastle.crypto.fips.FipsDRBG;
import org.bouncycastle.crypto.fips.FipsSecureRandom;
import org.bouncycastle.crypto.util.BasicEntropySourceProvider;

/**
 * DRBG coverage: the FipsDRBG mechanism matrix (instantiate/generate/reseed),
 * deterministic pinned-output tests, and the statistical smoke tests absorbed
 * from bcfips-policy Test.java.
 *
 * Why no external CAVP SP 800-90A KATs: bc-fips wraps every EntropySource in
 * its FIPS 140-3 continuous-health-test layer (ContinuousTestingEntropySource),
 * which pre-draws and transforms the entropy stream, so exact CAVP vectors
 * cannot be replayed through the public API - by design of the certified
 * module boundary. The module executes its own SP 800-90A KATs at power-on
 * (covered by preflight's FipsStatus.isReady()). Instead, the pinned cases
 * below feed a deterministic entropy source and compare against outputs
 * recorded on bc-fips 2.1.1: any change to DRBG seeding or generation
 * plumbing in a provider update surfaces as a mismatch to investigate.
 */
public final class DrbgSuite implements TestSuite {

    /**
     * Outputs recorded on bc-fips 2.1.1 (Linux x86_64, approved mode) for the
     * deterministic entropy source below with nonce "fipstest-nonce-0001" and
     * personalization "fipstest-perso": 2x nextBytes(64), second output.
     * A mismatch on a provider update is not automatically a bug - it means
     * DRBG plumbing changed and the change needs review; re-pin afterwards.
     */
    private static final Map<String, String> PINNED_211 = Map.of(
            "sha256-hmac", "e07478d9d79acb63b55779f01731fdeae5b381d3d0f30f9e8a3b1c09a7412e02"
                    + "d46839c8d01bfbac25121edcbf74b831a266b43d211134bc4b8c7e4e2b908a59",
            "sha512-hmac", "d1b0c81e5c0cd25cae7c3f6ebfcab5ce811cd5e93c948aaa4fd702394f55872d"
                    + "579aa895058d611c56c67da4f126b1d82e4944957da5ab36ad6534df6c907265",
            "sha256", "9f0ca6ef5cb2001444140b019e135471a3f355b391f27080e97e0c14d0b2643e"
                    + "1ea744e9a50a02bca9d1c6f7c9b8b748d3b1113989c7ac55b730d4b9e6a5ed5e",
            "sha512", "0e27533666004291ebbc46ef66bae9eb0a6ad85d021037643900bf86fcbcfe04"
                    + "1c174cc07710cddfedddd819000b0672809ae3f24ef2e86cb0f297c7cb1d0a28",
            "ctr-aes-256", "13106d8715c2cccb0c675e0503ef8be0e33f86c7e09e65b040ba288237f3a7cb"
                    + "ab214a13b80e8a1634b8b9101c202e3652a310972f3cc434623f3579fd22818b");

    private static final Map<String, FipsDRBG.Base> PINNED_BASES = Map.of(
            "sha256-hmac", FipsDRBG.SHA256_HMAC,
            "sha512-hmac", FipsDRBG.SHA512_HMAC,
            "sha256", FipsDRBG.SHA256,
            "sha512", FipsDRBG.SHA512,
            "ctr-aes-256", FipsDRBG.CTR_AES_256);

    @Override
    public String name() {
        return "primitives.drbg";
    }

    @Override
    public Set<String> tags() {
        return Set.of("primitives", "drbg", "random");
    }

    @Override
    public void register(TestContext ctx) throws Exception {
        registerLiveMatrix(ctx);
        registerPinned(ctx);
        registerStatistical(ctx);
    }

    /** Live DRBGs from real entropy: instantiate -> generate -> reseed -> generate. */
    private void registerLiveMatrix(TestContext ctx) {
        Map<String, FipsDRBG.Base> bases = Map.of(
                "sha256", FipsDRBG.SHA256,
                "sha512", FipsDRBG.SHA512,
                "sha256-hmac", FipsDRBG.SHA256_HMAC,
                "sha512-hmac", FipsDRBG.SHA512_HMAC,
                "ctr-aes-256", FipsDRBG.CTR_AES_256);
        for (Map.Entry<String, FipsDRBG.Base> e : bases.entrySet()) {
            ctx.add("live/" + e.getKey() + "/generate-reseed-generate", () -> {
                FipsSecureRandom drbg = e.getValue()
                        .fromEntropySource(new BasicEntropySourceProvider(
                                new SecureRandom(), true))
                        .setPersonalizationString("fipstest".getBytes())
                        .build("nonce-0001".getBytes(), false);
                byte[] first = new byte[64];
                drbg.nextBytes(first);
                drbg.reseed();
                byte[] second = new byte[64];
                drbg.nextBytes(second);
                Expect.assertTrue(!java.util.Arrays.equals(first, second),
                        "DRBG produced identical blocks around a reseed");
            });
        }
    }

    /** Deterministic-entropy pinned outputs; see class comment for semantics. */
    private void registerPinned(TestContext ctx) {
        for (Map.Entry<String, FipsDRBG.Base> e : PINNED_BASES.entrySet()) {
            ctx.add("pinned/" + e.getKey() + "/deterministic-and-matches-2.1.1", () -> {
                byte[] first = pinnedRun(e.getValue());
                byte[] second = pinnedRun(e.getValue());
                Expect.assertArrayEquals(first, second,
                        e.getKey() + " deterministic-entropy reproducibility");
                Expect.assertArrayEquals(Hex.decode(PINNED_211.get(e.getKey())), first,
                        e.getKey() + " pinned output (recorded on bc-fips 2.1.1;"
                                + " a mismatch means DRBG plumbing changed in this"
                                + " provider version - review and re-pin)");
            });
        }
    }

    private static byte[] pinnedRun(FipsDRBG.Base base) throws Exception {
        FipsSecureRandom drbg = base
                .fromEntropySource(new DeterministicEntropySourceProvider(
                        "fipstest-drbg-pin-seed-0001".getBytes("US-ASCII")))
                .setPersonalizationString("fipstest-perso".getBytes("US-ASCII"))
                .build("fipstest-nonce-0001".getBytes("US-ASCII"), false);
        byte[] out = new byte[64];
        drbg.nextBytes(out, (byte[]) null);
        drbg.nextBytes(out, (byte[]) null);
        return out;
    }

    private void registerStatistical(TestContext ctx) {
        int keys = ctx.mctDepth() == TestContext.MctDepth.FULL ? 125 : 10;
        ctx.add("statistical/rsa-keygen-uniqueness-" + keys, Set.of("slow"),
                java.util.EnumSet.allOf(dev.chainguard.fipstest.harness.Mode.class), () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BCFIPS");
            kpg.initialize(2048);
            Set<String> seen = new HashSet<>();
            for (int i = 0; i < keys; i++) {
                KeyPair kp = kpg.generateKeyPair();
                Expect.assertTrue(seen.add(Base64.getEncoder()
                                .encodeToString(kp.getPrivate().getEncoded())),
                        "duplicate RSA private key generated");
            }
        });

        // SP 800-90A caps a single generate request at 2^19 = 262144 bits
        // (32768 bytes) - the provider must enforce it, and consumers filling
        // large buffers must chunk (see scenarios.envelope).
        ctx.add("limits/single-request-cap-enforced", () -> {
            SecureRandom drbg = SecureRandom.getInstance("DEFAULT", "BCFIPS");
            byte[] ok = new byte[32768];
            drbg.nextBytes(ok);
            Expect.mustFail("DRBG request above 262144 bits", () ->
                    drbg.nextBytes(new byte[32769]));
        });

        ctx.add("statistical/strong-instances-independent", () -> {
            SecureRandom r1 = SecureRandom.getInstanceStrong();
            SecureRandom r2 = SecureRandom.getInstanceStrong();
            byte[] a = new byte[32];
            byte[] b = new byte[32];
            r1.nextBytes(a);
            r2.nextBytes(b);
            Expect.assertTrue(!java.util.Arrays.equals(a, b),
                    "two strong SecureRandom instances produced identical output");
        });
    }

    /**
     * Deterministic, non-repeating entropy stream: draw i is SHA-256(seed||i)
     * expanded to the requested size. Distinct consecutive blocks keep the
     * provider's continuous entropy health test happy while making the whole
     * DRBG pipeline reproducible.
     */
    private static final class DeterministicEntropySourceProvider
            implements EntropySourceProvider {
        private final byte[] seed;

        DeterministicEntropySourceProvider(byte[] seed) {
            this.seed = seed;
        }

        @Override
        public EntropySource get(int bitsRequired) {
            return new EntropySource() {
                private int counter;

                @Override
                public boolean isPredictionResistant() {
                    return false;
                }

                @Override
                public byte[] getEntropy() {
                    try {
                        MessageDigest md = MessageDigest.getInstance("SHA-256", "BCFIPS");
                        byte[] out = new byte[(bitsRequired + 7) / 8];
                        int off = 0;
                        while (off < out.length) {
                            md.reset();
                            md.update(seed);
                            md.update(new byte[] {(byte) (counter >> 8), (byte) counter});
                            counter++;
                            byte[] block = md.digest();
                            int n = Math.min(block.length, out.length - off);
                            System.arraycopy(block, 0, out, off, n);
                            off += n;
                        }
                        return out;
                    } catch (Exception e) {
                        throw new IllegalStateException(e);
                    }
                }

                @Override
                public int entropySize() {
                    return bitsRequired;
                }
            };
        }
    }
}
