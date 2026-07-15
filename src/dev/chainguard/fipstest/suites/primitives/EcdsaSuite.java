package dev.chainguard.fipstest.suites.primitives;

import dev.chainguard.fipstest.harness.Expect;
import dev.chainguard.fipstest.harness.TestContext;
import dev.chainguard.fipstest.harness.TestSuite;
import dev.chainguard.fipstest.util.TestKeys;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.List;
import java.util.Set;

/**
 * ECDSA coverage: NIST curve keygen, curve x hash sign/verify matrix with
 * tamper negatives, and Wycheproof verification vectors (DER malleability,
 * r/s boundary values, historically the richest source of provider bugs).
 */
public final class EcdsaSuite implements TestSuite {

    private static final List<String> CURVES = List.of("P-256", "P-384", "P-521");
    private static final List<String> HASHES = List.of("SHA256", "SHA384", "SHA512");

    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public String name() {
        return "primitives.ecdsa";
    }

    @Override
    public Set<String> tags() {
        return Set.of("primitives", "ecdsa", "ec");
    }

    @Override
    public void register(TestContext ctx) throws Exception {
        for (String curve : CURVES) {
            ctx.add("keygen/" + curve.toLowerCase(), () -> {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BCFIPS");
                kpg.initialize(new ECGenParameterSpec(curve));
                Expect.assertTrue(kpg.generateKeyPair() != null, curve + " keypair");
            });

            for (String hash : HASHES) {
                String algorithm = hash + "withECDSA";
                ctx.add("sign-verify/" + curve.toLowerCase() + "/"
                        + algorithm.toLowerCase() + "/roundtrip", () -> {
                    KeyPair kp = TestKeys.ec(curve);
                    byte[] message = new byte[80];
                    RANDOM.nextBytes(message);

                    Signature signer = Signature.getInstance(algorithm, "BCFIPS");
                    signer.initSign(kp.getPrivate());
                    signer.update(message);
                    byte[] signature = signer.sign();

                    Signature verifier = Signature.getInstance(algorithm, "BCFIPS");
                    verifier.initVerify(kp.getPublic());
                    verifier.update(message);
                    Expect.assertTrue(verifier.verify(signature),
                            curve + "/" + algorithm + " verify");

                    // ECDSA is randomized: two signatures over the same message
                    // must differ (a repeated k would leak the private key).
                    signer.initSign(kp.getPrivate());
                    signer.update(message);
                    byte[] second = signer.sign();
                    Expect.assertTrue(!java.util.Arrays.equals(signature, second),
                            "two ECDSA signatures were identical (k reuse?)");

                    message[3] ^= 0x08;
                    verifier.initVerify(kp.getPublic());
                    verifier.update(message);
                    Expect.mustBeFalse(safeVerify(verifier, signature),
                            curve + "/" + algorithm + " tampered message");

                    message[3] ^= 0x08;
                    byte[] badSig = signature.clone();
                    badSig[badSig.length - 1] ^= 0x01;
                    verifier.initVerify(kp.getPublic());
                    verifier.update(message);
                    Expect.mustBeFalse(safeVerify(verifier, badSig),
                            curve + "/" + algorithm + " tampered signature");
                });
            }
        }

        SignatureVectors.register(ctx, "ecdsa-p256-sha256",
                "sign/ecdsa-p256-sha256-wycheproof.rsp", "EC", "SHA256withECDSA");
        SignatureVectors.register(ctx, "ecdsa-p384-sha384",
                "sign/ecdsa-p384-sha384-wycheproof.rsp", "EC", "SHA384withECDSA");
    }

    private static boolean safeVerify(Signature verifier, byte[] signature) {
        try {
            return verifier.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }
}
