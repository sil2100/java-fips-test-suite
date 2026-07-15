package dev.chainguard.fipstest.suites.primitives;

import dev.chainguard.fipstest.harness.Expect;
import dev.chainguard.fipstest.harness.TestContext;
import dev.chainguard.fipstest.harness.TestFailure;
import dev.chainguard.fipstest.harness.TestSuite;
import dev.chainguard.fipstest.util.VectorFile;

import javax.crypto.KeyAgreement;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.Set;

/**
 * Key agreement: ECDH over the NIST curves, finite-field DH, and Wycheproof
 * ECDH vectors whose invalid records carry the dangerous inputs - public
 * points off the curve or on a twist, which a correct provider must REJECT
 * rather than silently derive a wrong secret from.
 */
public final class KeyAgreementSuite implements TestSuite {

    @Override
    public String name() {
        return "primitives.keyagreement";
    }

    @Override
    public Set<String> tags() {
        return Set.of("primitives", "keyagreement", "ecdh");
    }

    @Override
    public void register(TestContext ctx) throws Exception {
        for (String curve : List.of("P-256", "P-384", "P-521")) {
            ctx.add("ecdh/" + curve.toLowerCase() + "/shared-secret-agrees", () -> {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BCFIPS");
                kpg.initialize(new ECGenParameterSpec(curve));
                KeyPair alice = kpg.generateKeyPair();
                KeyPair bob = kpg.generateKeyPair();

                byte[] aliceSecret = agree("ECDH", alice.getPrivate(), bob.getPublic());
                byte[] bobSecret = agree("ECDH", bob.getPrivate(), alice.getPublic());
                Expect.assertArrayEquals(aliceSecret, bobSecret, curve + " ECDH secrets");
                Expect.assertTrue(aliceSecret.length > 0, "empty shared secret");

                // A third party's key must not produce the same secret.
                KeyPair eve = kpg.generateKeyPair();
                byte[] eveSecret = agree("ECDH", eve.getPrivate(), bob.getPublic());
                Expect.assertTrue(!java.util.Arrays.equals(aliceSecret, eveSecret),
                        "unrelated key derived the same secret");
            });
        }

        ctx.add("dh/2048/shared-secret-agrees", Set.of("slow"),
                java.util.EnumSet.allOf(dev.chainguard.fipstest.harness.Mode.class), () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", "BCFIPS");
            kpg.initialize(2048);
            KeyPair alice = kpg.generateKeyPair();
            KeyPair bob = kpg.generateKeyPair();
            Expect.assertArrayEquals(
                    agree("DH", alice.getPrivate(), bob.getPublic()),
                    agree("DH", bob.getPrivate(), alice.getPublic()),
                    "DH-2048 secrets");
        });

        registerWycheproofEcdh(ctx);
    }

    private void registerWycheproofEcdh(TestContext ctx) throws Exception {
        VectorFile vf = ctx.vectors("agree/ecdh-p256-wycheproof.rsp");

        for (VectorFile.Record rec : vf.records()) {
            ctx.add("ecdh-p256/wycheproof/" + rec.id(), () -> {
                KeyFactory kf = KeyFactory.getInstance("EC", "BCFIPS");
                AlgorithmParameters params = AlgorithmParameters.getInstance("EC", "BCFIPS");
                params.init(new ECGenParameterSpec("P-256"));
                ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);

                PrivateKey privateKey = kf.generatePrivate(new ECPrivateKeySpec(
                        new BigInteger(1, rec.bytes("private")), spec));

                byte[] secret;
                try {
                    PublicKey publicKey = kf.generatePublic(
                            new X509EncodedKeySpec(rec.bytes("public")));
                    secret = agree("ECDH", privateKey, publicKey);
                } catch (Throwable t) {
                    if ("valid".equals(rec.result())) {
                        throw new TestFailure("ecdh-p256 " + rec.id()
                                + " valid vector rejected (" + rec.comment() + "): " + t, t);
                    }
                    return; // rejection is the expected outcome for invalid keys
                }
                if ("invalid".equals(rec.result())) {
                    throw new TestFailure("ecdh-p256 " + rec.id()
                            + " invalid public key accepted (failure to fail: "
                            + rec.comment() + ", flags="
                            + rec.getOrDefault("flags", "") + ")");
                }
                Expect.assertArrayEquals(rec.bytes("shared"), secret,
                        "ecdh-p256 " + rec.id() + " shared secret ("
                                + rec.comment() + ")");
            });
        }
    }

    private static byte[] agree(String algorithm, PrivateKey privateKey, PublicKey publicKey)
            throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance(algorithm, "BCFIPS");
        ka.init(privateKey);
        ka.doPhase(publicKey, true);
        return ka.generateSecret();
    }
}
