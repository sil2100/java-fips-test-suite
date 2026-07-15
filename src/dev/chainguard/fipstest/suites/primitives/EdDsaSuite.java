package dev.chainguard.fipstest.suites.primitives;

import dev.chainguard.fipstest.harness.Capabilities;
import dev.chainguard.fipstest.harness.Expect;
import dev.chainguard.fipstest.harness.TestContext;
import dev.chainguard.fipstest.harness.TestSuite;
import dev.chainguard.fipstest.util.TestKeys;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.List;
import java.util.Set;

/**
 * EdDSA - the headline algorithm addition of the bc-fips 2.1 line, so this is
 * exactly where an update regression is most likely. Fully capability-gated:
 * on a provider without EdDSA every case SKIPs cleanly.
 */
public final class EdDsaSuite implements TestSuite {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public String name() {
        return "primitives.eddsa";
    }

    @Override
    public Set<String> tags() {
        return Set.of("primitives", "eddsa");
    }

    @Override
    public void register(TestContext ctx) throws Exception {
        for (String algorithm : List.of("Ed25519", "Ed448")) {
            ctx.add(algorithm.toLowerCase() + "/sign-verify-roundtrip", () -> {
                Capabilities.require("Signature", algorithm, "BCFIPS");
                KeyPair kp = TestKeys.eddsa(algorithm);
                byte[] message = new byte[64];
                RANDOM.nextBytes(message);

                Signature signer = Signature.getInstance(algorithm, "BCFIPS");
                signer.initSign(kp.getPrivate());
                signer.update(message);
                byte[] signature = signer.sign();

                Signature verifier = Signature.getInstance(algorithm, "BCFIPS");
                verifier.initVerify(kp.getPublic());
                verifier.update(message);
                Expect.assertTrue(verifier.verify(signature), algorithm + " verify");

                // EdDSA signing is deterministic - same message, same signature.
                signer.initSign(kp.getPrivate());
                signer.update(message);
                Expect.assertArrayEquals(signature, signer.sign(),
                        algorithm + " determinism");

                message[0] ^= 0x01;
                verifier.initVerify(kp.getPublic());
                verifier.update(message);
                boolean tampered;
                try {
                    tampered = verifier.verify(signature);
                } catch (Exception e) {
                    tampered = false;
                }
                Expect.mustBeFalse(tampered, algorithm + " tampered message");
            });
        }

        if (Capabilities.has("Signature", "Ed25519", "BCFIPS")) {
            SignatureVectors.register(ctx, "ed25519",
                    "sign/ed25519-wycheproof.rsp", "Ed25519", "Ed25519");
        } else {
            ctx.add("ed25519/wycheproof-vectors", () -> {
                throw new dev.chainguard.fipstest.harness.SkipException(
                        "Ed25519 not available from this provider version");
            });
        }
    }
}
