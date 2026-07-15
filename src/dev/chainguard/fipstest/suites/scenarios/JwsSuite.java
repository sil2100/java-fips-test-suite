package dev.chainguard.fipstest.suites.scenarios;

import dev.chainguard.fipstest.harness.Capabilities;
import dev.chainguard.fipstest.harness.Expect;
import dev.chainguard.fipstest.harness.TestContext;
import dev.chainguard.fipstest.harness.TestSuite;
import dev.chainguard.fipstest.util.TestKeys;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

/**
 * JWS-style token signing, the keycloak/elasticsearch JWT pattern in
 * miniature: sign base64url(header).base64url(payload) with the JOSE
 * algorithm set. ES* algorithms include the classic JOSE pitfall - JCA emits
 * DER-encoded ECDSA signatures while JOSE wants fixed-width raw r||s - so
 * the DER<->raw conversion is exercised in both directions.
 */
public final class JwsSuite implements TestSuite {

    /** JOSE alg -> (JCA algorithm, key type, raw signature part length or 0). */
    private static final Map<String, String[]> ALGORITHMS = Map.of(
            "RS256", new String[] {"SHA256withRSA", "RSA", "0"},
            "RS384", new String[] {"SHA384withRSA", "RSA", "0"},
            "RS512", new String[] {"SHA512withRSA", "RSA", "0"},
            "PS256", new String[] {"SHA256withRSA/PSS", "RSA", "0"},
            "ES256", new String[] {"SHA256withECDSA", "P-256", "32"},
            "ES384", new String[] {"SHA384withECDSA", "P-384", "48"},
            "ES512", new String[] {"SHA512withECDSA", "P-521", "66"});

    @Override
    public String name() {
        return "scenarios.jws";
    }

    @Override
    public Set<String> tags() {
        return Set.of("scenarios", "jws", "jwt");
    }

    @Override
    public void register(TestContext ctx) {
        for (Map.Entry<String, String[]> e : ALGORITHMS.entrySet()) {
            String jose = e.getKey();
            String jca = e.getValue()[0];
            String keyType = e.getValue()[1];
            int rawPartLen = Integer.parseInt(e.getValue()[2]);

            ctx.add(jose.toLowerCase() + "/sign-verify-token", () -> {
                KeyPair kp = "RSA".equals(keyType) ? TestKeys.rsaSign(2048)
                        : TestKeys.ec(keyType);
                String signingInput = signingInput(jose);

                Signature signer = Signature.getInstance(jca, "BCFIPS");
                signer.initSign(kp.getPrivate());
                signer.update(signingInput.getBytes(StandardCharsets.US_ASCII));
                byte[] jcaSig = signer.sign();

                // JOSE wire form: raw r||s for ES*, as-is for RS*/PS*.
                byte[] wireSig = rawPartLen > 0 ? derToRaw(jcaSig, rawPartLen) : jcaSig;
                String token = signingInput + "." + b64url(wireSig);

                // Verifier side: parse the token back.
                String[] parts = token.split("\\.");
                Expect.assertEquals(3, parts.length, "token part count");
                byte[] parsedWire = Base64.getUrlDecoder().decode(parts[2]);
                byte[] verifySig = rawPartLen > 0 ? rawToDer(parsedWire) : parsedWire;

                Signature verifier = Signature.getInstance(jca, "BCFIPS");
                verifier.initVerify(kp.getPublic());
                verifier.update((parts[0] + "." + parts[1])
                        .getBytes(StandardCharsets.US_ASCII));
                Expect.assertTrue(verifier.verify(verifySig), jose + " token verify");

                // Payload tamper: flip one claim character.
                String tamperedPayload = parts[1].charAt(0) == 'A'
                        ? "B" + parts[1].substring(1) : "A" + parts[1].substring(1);
                verifier.initVerify(kp.getPublic());
                verifier.update((parts[0] + "." + tamperedPayload)
                        .getBytes(StandardCharsets.US_ASCII));
                Expect.mustBeFalse(safeVerify(verifier, verifySig),
                        jose + " tampered payload");
            });
        }

        ctx.add("eddsa/sign-verify-token-if-available", () -> {
            Capabilities.require("Signature", "Ed25519", "BCFIPS");
            KeyPair kp = TestKeys.eddsa("Ed25519");
            String signingInput = signingInput("EdDSA");

            Signature signer = Signature.getInstance("Ed25519", "BCFIPS");
            signer.initSign(kp.getPrivate());
            signer.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            byte[] sig = signer.sign();

            Signature verifier = Signature.getInstance("Ed25519", "BCFIPS");
            verifier.initVerify(kp.getPublic());
            verifier.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            Expect.assertTrue(verifier.verify(sig), "EdDSA token verify");
        });

        // Algorithm confusion: a token signed with ES256 must not verify
        // under an RSA verifier or with the wrong curve's key.
        ctx.add("negative/alg-confusion-rejected", () -> {
            KeyPair ecKey = TestKeys.ec("P-256");
            String signingInput = signingInput("ES256");

            Signature signer = Signature.getInstance("SHA256withECDSA", "BCFIPS");
            signer.initSign(ecKey.getPrivate());
            signer.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            byte[] derSig = signer.sign();

            Signature rsaVerifier = Signature.getInstance("SHA256withRSA", "BCFIPS");
            boolean confused;
            try {
                rsaVerifier.initVerify(TestKeys.rsaSign(2048).getPublic());
                rsaVerifier.update(signingInput.getBytes(StandardCharsets.US_ASCII));
                confused = rsaVerifier.verify(derSig);
            } catch (Exception e) {
                confused = false;
            }
            Expect.mustBeFalse(confused, "ES256 signature accepted by RSA verifier");

            Signature otherCurve = Signature.getInstance("SHA256withECDSA", "BCFIPS");
            boolean wrongKey;
            try {
                otherCurve.initVerify(TestKeys.ec("P-384").getPublic());
                otherCurve.update(signingInput.getBytes(StandardCharsets.US_ASCII));
                wrongKey = otherCurve.verify(derSig);
            } catch (Exception e) {
                wrongKey = false;
            }
            Expect.mustBeFalse(wrongKey, "ES256 signature accepted with wrong key");
        });

        // Raw signature length manipulation must fail cleanly.
        ctx.add("negative/raw-signature-length-manipulation", () -> {
            KeyPair kp = TestKeys.ec("P-256");
            String signingInput = signingInput("ES256");
            Signature signer = Signature.getInstance("SHA256withECDSA", "BCFIPS");
            signer.initSign(kp.getPrivate());
            signer.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            byte[] raw = derToRaw(signer.sign(), 32);

            byte[] truncated = Arrays.copyOf(raw, raw.length - 2);
            byte[] padded = Arrays.copyOf(raw, raw.length + 2);
            for (byte[] mangled : new byte[][] {truncated, padded}) {
                boolean verified;
                try {
                    Signature verifier = Signature.getInstance("SHA256withECDSA", "BCFIPS");
                    verifier.initVerify(kp.getPublic());
                    verifier.update(signingInput.getBytes(StandardCharsets.US_ASCII));
                    // A robust JOSE layer rejects at conversion; if conversion
                    // "succeeds", the signature itself must not verify.
                    verified = verifier.verify(rawToDer(mangled));
                } catch (Exception e) {
                    verified = false;
                }
                Expect.mustBeFalse(verified, "mangled raw signature verified");
            }
        });
    }

    private static String signingInput(String alg) {
        String header = "{\"alg\":\"" + alg + "\",\"typ\":\"JWT\"}";
        String payload = "{\"sub\":\"fipstest\",\"iss\":\"dev.chainguard\","
                + "\"exp\":1999999999}";
        return b64url(header.getBytes(StandardCharsets.UTF_8)) + "."
                + b64url(payload.getBytes(StandardCharsets.UTF_8));
    }

    private static String b64url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    /** DER ECDSA signature -> fixed-width raw r||s (the JOSE wire form). */
    static byte[] derToRaw(byte[] der, int partLen) {
        // SEQUENCE { INTEGER r, INTEGER s }
        int idx = 2; // skip SEQUENCE tag + length (assume short/1-byte forms)
        if ((der[1] & 0x80) != 0) {
            idx = 2 + (der[1] & 0x7f);
        }
        Expect.assertEquals(0x02, (int) der[idx], "DER INTEGER tag (r)");
        int rLen = der[idx + 1];
        byte[] r = Arrays.copyOfRange(der, idx + 2, idx + 2 + rLen);
        idx = idx + 2 + rLen;
        Expect.assertEquals(0x02, (int) der[idx], "DER INTEGER tag (s)");
        int sLen = der[idx + 1];
        byte[] s = Arrays.copyOfRange(der, idx + 2, idx + 2 + sLen);

        byte[] out = new byte[partLen * 2];
        copyFixed(r, out, 0, partLen);
        copyFixed(s, out, partLen, partLen);
        return out;
    }

    /** Fixed-width raw r||s -> DER, for the verify direction. */
    static byte[] rawToDer(byte[] raw) {
        int partLen = raw.length / 2;
        byte[] r = new BigInteger(1, Arrays.copyOfRange(raw, 0, partLen)).toByteArray();
        byte[] s = new BigInteger(1, Arrays.copyOfRange(raw, partLen, raw.length))
                .toByteArray();
        int seqLen = 2 + r.length + 2 + s.length;
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        out.write(0x30);
        if (seqLen < 0x80) {
            out.write(seqLen);
        } else {
            out.write(0x81);
            out.write(seqLen);
        }
        out.write(0x02);
        out.write(r.length);
        out.write(r, 0, r.length);
        out.write(0x02);
        out.write(s.length);
        out.write(s, 0, s.length);
        return out.toByteArray();
    }

    private static void copyFixed(byte[] src, byte[] dst, int dstOff, int len) {
        // Strip a leading zero sign byte or left-pad to the fixed width.
        int srcOff = 0;
        int srcLen = src.length;
        while (srcLen > len && src[srcOff] == 0) {
            srcOff++;
            srcLen--;
        }
        Expect.assertTrue(srcLen <= len, "integer part longer than field width");
        System.arraycopy(src, srcOff, dst, dstOff + (len - srcLen), srcLen);
    }

    private static boolean safeVerify(Signature verifier, byte[] signature) {
        try {
            return verifier.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }
}
