package dev.chainguard.fipstest.suites.primitives;

import dev.chainguard.fipstest.harness.Expect;
import dev.chainguard.fipstest.harness.TestContext;
import dev.chainguard.fipstest.harness.TestSuite;
import dev.chainguard.fipstest.util.TestKeys;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Set;

/**
 * RSA coverage: key generation, PKCS#1 v1.5 and PSS signature matrix with
 * tamper negatives, OAEP encryption, and Wycheproof verification vectors
 * (BER/padding edge cases). PKCS#1 v1.5 SIGNATURES remain approved; PKCS#1
 * v1.5 ENCRYPTION does not (asserted in negative.approved).
 */
public final class RsaSuite implements TestSuite {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public String name() {
        return "primitives.rsa";
    }

    @Override
    public Set<String> tags() {
        return Set.of("primitives", "rsa");
    }

    @Override
    public void register(TestContext ctx) throws Exception {
        for (int bits : new int[] {2048, 3072}) {
            ctx.add("keygen/rsa-" + bits, () -> {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BCFIPS");
                kpg.initialize(bits);
                KeyPair kp = kpg.generateKeyPair();
                Expect.assertEquals(bits,
                        ((RSAPublicKey) kp.getPublic()).getModulus().bitLength(),
                        "generated modulus size");
            });
        }
        ctx.add("keygen/rsa-4096", Set.of("slow"),
                java.util.EnumSet.allOf(dev.chainguard.fipstest.harness.Mode.class), () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BCFIPS");
            kpg.initialize(4096);
            Expect.assertEquals(4096,
                    ((RSAPublicKey) kpg.generateKeyPair().getPublic())
                            .getModulus().bitLength(),
                    "generated modulus size");
        });

        for (String base : List.of("SHA256", "SHA384", "SHA512")) {
            for (String suffix : List.of("withRSA", "withRSA/PSS")) {
                String algorithm = base + suffix;
                ctx.add("sign-verify/" + algorithm.toLowerCase().replace('/', '-')
                        + "/roundtrip", () -> {
                    KeyPair kp = TestKeys.rsaSign(2048);
                    byte[] message = randomMessage();

                    Signature signer = Signature.getInstance(algorithm, "BCFIPS");
                    signer.initSign(kp.getPrivate());
                    signer.update(message);
                    byte[] signature = signer.sign();

                    Signature verifier = Signature.getInstance(algorithm, "BCFIPS");
                    verifier.initVerify(kp.getPublic());
                    verifier.update(message);
                    Expect.assertTrue(verifier.verify(signature), algorithm + " verify");

                    // Tampered message must NOT verify.
                    message[0] ^= 0x01;
                    verifier.initVerify(kp.getPublic());
                    verifier.update(message);
                    Expect.mustBeFalse(safeVerify(verifier, signature),
                            algorithm + " tampered message");

                    // Tampered signature must NOT verify.
                    message[0] ^= 0x01;
                    byte[] badSig = signature.clone();
                    badSig[badSig.length / 2] ^= 0x10;
                    verifier.initVerify(kp.getPublic());
                    verifier.update(message);
                    Expect.mustBeFalse(safeVerify(verifier, badSig),
                            algorithm + " tampered signature");

                    // Signature from a different key must NOT verify.
                    verifier.initVerify(TestKeys.rsaSign(3072).getPublic());
                    verifier.update(message);
                    Expect.mustBeFalse(safeVerify(verifier, signature),
                            algorithm + " wrong key");
                });
            }
        }

        // Observed bc-fips 2.1.1 behavior: in approved mode RSA-OAEP is key
        // transport ONLY (Cipher restricted to WRAP_MODE/UNWRAP_MODE - the
        // wrap path is covered in primitives.keywrap); general data
        // encryption is available with approved-only off.
        ctx.addApproved("encrypt/oaep-sha256/data-encryption-rejected-approved", () ->
                Expect.mustFail("RSA-OAEP ENCRYPT_MODE in approved mode", () -> {
                    Cipher enc = Cipher.getInstance(
                            "RSA/NONE/OAEPwithSHA256andMGF1Padding", "BCFIPS");
                    enc.init(Cipher.ENCRYPT_MODE, TestKeys.rsaWrap(2048).getPublic());
                    enc.doFinal(new byte[32]);
                }));

        ctx.addUnapproved("encrypt/oaep-sha256/roundtrip-unapproved", () -> {
            KeyPair kp = TestKeys.rsaWrap(2048);
            byte[] plaintext = new byte[64];
            RANDOM.nextBytes(plaintext);

            Cipher enc = Cipher.getInstance("RSA/NONE/OAEPwithSHA256andMGF1Padding", "BCFIPS");
            enc.init(Cipher.ENCRYPT_MODE, kp.getPublic());
            byte[] ciphertext = enc.doFinal(plaintext);

            Cipher dec = Cipher.getInstance("RSA/NONE/OAEPwithSHA256andMGF1Padding", "BCFIPS");
            dec.init(Cipher.DECRYPT_MODE, kp.getPrivate());
            Expect.assertArrayEquals(plaintext, dec.doFinal(ciphertext), "OAEP round-trip");
        });

        // The FIPS key-usage separation rule surfaced by our own test runs:
        // once an RSA modulus performs encrypt/decrypt (key transport), the
        // provider permanently refuses it for sign/verify. Consumers hit this
        // when reusing one key for TLS transport and token signing.
        ctx.add("key-usage-separation/wrap-then-sign-rejected", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BCFIPS");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();

            Cipher wrap = Cipher.getInstance("RSA/NONE/OAEPwithSHA256andMGF1Padding",
                    "BCFIPS");
            wrap.init(Cipher.WRAP_MODE, kp.getPublic());
            javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance(
                    "AES", "BCFIPS");
            kg.init(256);
            wrap.wrap(kg.generateKey());

            Expect.mustFail("signing with a modulus already used for key transport", () -> {
                Signature signer = Signature.getInstance("SHA256withRSA", "BCFIPS");
                signer.initSign(kp.getPrivate());
                signer.update("x".getBytes());
                signer.sign();
            });
        });

        SignatureVectors.register(ctx, "rsa-pkcs1-sha256",
                "sign/rsa-pkcs1-2048-sha256-wycheproof.rsp", "RSA", "SHA256withRSA");
        SignatureVectors.register(ctx, "rsa-pss-sha256",
                "sign/rsa-pss-2048-sha256-wycheproof.rsp", "RSA", "SHA256withRSA/PSS");
    }

    private static boolean safeVerify(Signature verifier, byte[] signature) {
        try {
            return verifier.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] randomMessage() {
        byte[] message = new byte[80];
        RANDOM.nextBytes(message);
        return message;
    }
}
