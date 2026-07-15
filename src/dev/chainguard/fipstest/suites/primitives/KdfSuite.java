package dev.chainguard.fipstest.suites.primitives;

import dev.chainguard.fipstest.harness.Expect;
import dev.chainguard.fipstest.harness.TestContext;
import dev.chainguard.fipstest.harness.TestFailure;
import dev.chainguard.fipstest.harness.TestSuite;
import dev.chainguard.fipstest.util.Hex;
import dev.chainguard.fipstest.util.VectorFile;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;

import org.bouncycastle.crypto.KDFCalculator;
import org.bouncycastle.crypto.fips.FipsKDF;

/**
 * Key derivation: PBKDF2 (the password-storage path consumers like Kafka
 * SCRAM depend on, including the approved-mode 14-character password
 * boundary), HKDF via the FipsKDF low-level API (the path TLS/application
 * code actually takes - there is no stable JCA name), and SP 800-108 KBKDF.
 */
public final class KdfSuite implements TestSuite {

    @Override
    public String name() {
        return "primitives.kdf";
    }

    @Override
    public Set<String> tags() {
        return Set.of("primitives", "kdf", "pbkdf2", "hkdf");
    }

    @Override
    public void register(TestContext ctx) throws Exception {
        registerPbkdf2(ctx);
        registerHkdf(ctx);
        registerKbkdf(ctx);
    }

    private void registerPbkdf2(TestContext ctx) throws Exception {
        for (String algorithm : List.of("PBKDF2WithHmacSHA1", "PBKDF2WithHmacSHA256",
                "PBKDF2WithHmacSHA512")) {
            ctx.add(algorithm.toLowerCase() + "/deterministic", () -> {
                SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, "BCFIPS");
                // kafka ScramFormatter-style parameters
                PBEKeySpec spec = new PBEKeySpec("correct-horse-battery".toCharArray(),
                        "0123456789abcdef".getBytes(StandardCharsets.US_ASCII), 4096, 256);
                byte[] first = skf.generateSecret(spec).getEncoded();
                byte[] second = skf.generateSecret(spec).getEncoded();
                Expect.assertArrayEquals(first, second, algorithm + " determinism");
                Expect.assertEquals(32, first.length, "derived key length");
            });
        }

        // The exact kafka-fips FIPS boundary: approved mode requires PBKDF2
        // passwords of at least 14 characters (112 bits).
        ctx.addApproved("pbkdf2/password-13-chars-rejected-approved", () ->
                Expect.mustFail("13-char PBKDF2 password in approved mode", () -> {
                    SecretKeyFactory skf = SecretKeyFactory.getInstance(
                            "PBKDF2WithHmacSHA256", "BCFIPS");
                    skf.generateSecret(new PBEKeySpec("exactly13char".toCharArray(),
                            "0123456789abcdef".getBytes(StandardCharsets.US_ASCII), 4096, 256));
                }));

        ctx.addApproved("pbkdf2/password-14-chars-accepted-approved", () -> {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(
                    "PBKDF2WithHmacSHA256", "BCFIPS");
            byte[] dk = skf.generateSecret(new PBEKeySpec("exactly14chars".toCharArray(),
                    "0123456789abcdef".getBytes(StandardCharsets.US_ASCII), 4096, 256))
                    .getEncoded();
            Expect.assertEquals(32, dk.length, "derived key length");
        });

        ctx.addUnapproved("pbkdf2/short-password-works-unapproved", () -> {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(
                    "PBKDF2WithHmacSHA256", "BCFIPS");
            byte[] dk = skf.generateSecret(new PBEKeySpec("short".toCharArray(),
                    "0123456789abcdef".getBytes(StandardCharsets.US_ASCII), 1000, 256))
                    .getEncoded();
            Expect.assertEquals(32, dk.length, "derived key length");
        });

        // Wycheproof PBKDF2 vectors: password is a byte string; JCA takes
        // char[], so only ASCII passwords translate faithfully.
        VectorFile vf = ctx.vectors("kdf/pbkdf2-sha256-wycheproof.rsp");
        PolicyRejections.Coverage pbkdf2Coverage = new PolicyRejections.Coverage(
                (int) vf.records().stream()
                        .filter(r -> "valid".equals(r.result())).count());
        for (VectorFile.Record rec : vf.records()) {
            ctx.add("pbkdf2-sha256/wycheproof/" + rec.id(), () -> {
                byte[] passwordBytes = rec.bytes("password");
                for (byte b : passwordBytes) {
                    if (b < 0x20 || b > 0x7e) {
                        throw new dev.chainguard.fipstest.harness.SkipException(
                                "non-ASCII password not expressible via PBEKeySpec");
                    }
                }
                char[] password = new String(passwordBytes, StandardCharsets.US_ASCII)
                        .toCharArray();
                byte[] expected = rec.bytes("dk");
                byte[] derived;
                try {
                    SecretKeyFactory skf = SecretKeyFactory.getInstance(
                            "PBKDF2WithHmacSHA256", "BCFIPS");
                    derived = skf.generateSecret(new PBEKeySpec(password, rec.bytes("salt"),
                            rec.intValue("iterationCount"), expected.length * 8)).getEncoded();
                } catch (Throwable t) {
                    if (rec.expectedValid()) {
                        if (!PolicyRejections.isPolicyRejection(t)) {
                            throw new TestFailure("pbkdf2 " + rec.id()
                                    + " valid vector rejected with a non-policy error ("
                                    + rec.comment() + ")", t);
                        }
                        // e.g. approved mode refusing short passwords/salts
                        if ("valid".equals(rec.result())) {
                            pbkdf2Coverage.policyRejected++;
                        }
                        System.out.println("INFO|pbkdf2 " + rec.id()
                                + " valid vector rejected by policy: " + t);
                    }
                    return;
                }
                if (!rec.expectedValid()) {
                    if (java.util.Arrays.equals(expected, derived)) {
                        throw new TestFailure("pbkdf2 " + rec.id()
                                + " invalid vector matched (failure to fail: "
                                + rec.comment() + ")");
                    }
                    return;
                }
                Expect.assertArrayEquals(expected, derived,
                        "pbkdf2 " + rec.id() + " derived key (" + rec.comment() + ")");
                if ("valid".equals(rec.result())) {
                    pbkdf2Coverage.verified++;
                }
            });
        }
        ctx.add("pbkdf2-sha256/wycheproof/coverage-floor", () -> {
            // The unapproved leg computes everything; the approved leg
            // legitimately policy-rejects the short-password vectors, so the
            // floor here is only "at least one verified".
            if (pbkdf2Coverage.verified < 1) {
                throw new TestFailure("pbkdf2: no valid vector was actually verified"
                        + " - coverage floor breached");
            }
        });
    }

    private void registerHkdf(TestContext ctx) throws Exception {
        // RFC 5869 A.1 inline KAT, exercised through the same wiring the
        // vector cases use (extract via HKDF_KEY_BUILDER, then expand).
        ctx.add("hkdf-sha256/rfc5869-a1", () -> {
            byte[] okm = hkdf(FipsKDF.AgreementKDFPRF.SHA256_HMAC,
                    Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                    Hex.decode("000102030405060708090a0b0c"),
                    Hex.decode("f0f1f2f3f4f5f6f7f8f9"), 42);
            Expect.assertArrayEquals(Hex.decode(
                    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                            + "34007208d5b887185865"),
                    okm, "HKDF-SHA256 RFC 5869 A.1");
        });

        VectorFile vf = ctx.vectors("kdf/hkdf-sha256-wycheproof.rsp");
        PolicyRejections.Coverage hkdfCoverage = new PolicyRejections.Coverage(
                (int) vf.records().stream()
                        .filter(r -> "valid".equals(r.result())).count());
        for (VectorFile.Record rec : vf.records()) {
            ctx.add("hkdf-sha256/wycheproof/" + rec.id(), () -> {
                byte[] okm;
                try {
                    okm = hkdf(FipsKDF.AgreementKDFPRF.SHA256_HMAC, rec.bytes("ikm"),
                            rec.bytes("salt"), rec.bytes("info"), rec.intValue("size"));
                } catch (Throwable t) {
                    if (rec.expectedValid()) {
                        if (!PolicyRejections.isPolicyRejection(t)) {
                            throw new TestFailure("hkdf " + rec.id()
                                    + " valid vector rejected with a non-policy error ("
                                    + rec.comment() + ")", t);
                        }
                        if ("valid".equals(rec.result())) {
                            hkdfCoverage.policyRejected++;
                        }
                        System.out.println("INFO|hkdf " + rec.id()
                                + " valid vector rejected by policy: " + t);
                    }
                    return; // rejection is the expected outcome for invalid
                }
                if (!rec.expectedValid()) {
                    // Invalid HKDF records (SizeTooLarge: size > 255*hashLen)
                    // carry an empty okm - comparing against it would be
                    // vacuous. The derivation itself must be REFUSED.
                    throw new TestFailure("hkdf " + rec.id()
                            + " invalid vector computed without error"
                            + " (failure to fail: " + rec.comment() + ", flags="
                            + rec.getOrDefault("flags", "") + ")");
                }
                Expect.assertArrayEquals(rec.bytes("okm"), okm,
                        "hkdf " + rec.id() + " OKM (" + rec.comment() + ")");
                if ("valid".equals(rec.result())) {
                    hkdfCoverage.verified++;
                }
            });
        }
        ctx.add("hkdf-sha256/wycheproof/coverage-floor", () ->
                hkdfCoverage.assertFloor("hkdf-sha256"));
    }

    private void registerKbkdf(TestContext ctx) {
        // SP 800-108 counter-mode KBKDF via the FipsKDF low-level API.
        ctx.add("kbkdf-counter-hmac-sha256/deterministic-and-context-sensitive", () -> {
            byte[] ki = new byte[32];
            for (int i = 0; i < ki.length; i++) {
                ki[i] = (byte) i;
            }
            byte[] fixedInput = "label-and-context".getBytes(StandardCharsets.US_ASCII);

            byte[] first = kbkdfCounter(ki, fixedInput, 32);
            byte[] second = kbkdfCounter(ki, fixedInput, 32);
            Expect.assertArrayEquals(first, second, "KBKDF determinism");

            byte[] other = kbkdfCounter(ki,
                    "different-context".getBytes(StandardCharsets.US_ASCII), 32);
            Expect.assertTrue(!java.util.Arrays.equals(first, other),
                    "KBKDF ignored the fixed input data");

            byte[] longer = kbkdfCounter(ki, fixedInput, 64);
            Expect.assertTrue(java.util.Arrays.equals(first,
                            java.util.Arrays.copyOf(longer, 32)),
                    "KBKDF counter-mode prefix consistency");
        });

        // TLS 1.2 PRF availability probe through the FipsKDF API.
        ctx.add("tls12-prf/deterministic", () -> {
            byte[] secret = new byte[48];
            byte[] seed = "client random server random".getBytes(StandardCharsets.US_ASCII);
            byte[] first = tls12Prf(secret, "master secret", seed, 48);
            byte[] second = tls12Prf(secret, "master secret", seed, 48);
            Expect.assertArrayEquals(first, second, "TLS 1.2 PRF determinism");
            Expect.assertTrue(!java.util.Arrays.equals(first, new byte[48]),
                    "TLS 1.2 PRF produced all zeroes");
        });
    }

    private static byte[] hkdf(FipsKDF.AgreementKDFPRF prf, byte[] ikm, byte[] salt,
                               byte[] info, int size) {
        FipsKDF.HKDFKeyBuilder keyBuilder = FipsKDF.HKDF_KEY_BUILDER.withPrf(prf);
        if (salt.length > 0) {
            keyBuilder = keyBuilder.withSalt(salt);
        }
        FipsKDF.HKDFKey key = keyBuilder.build(ikm);
        KDFCalculator<?> calculator = new FipsKDF.AgreementOperatorFactory()
                .createKDFCalculator(FipsKDF.HKDF.withPRF(prf)
                        .using(key.getKey()).withIV(info));
        byte[] out = new byte[size];
        calculator.generateBytes(out);
        return out;
    }

    private static byte[] kbkdfCounter(byte[] ki, byte[] fixedInput, int size) {
        KDFCalculator<?> calculator = new FipsKDF.CounterModeFactory()
                .createKDFCalculator(FipsKDF.COUNTER_MODE
                        .withPRFAndR(FipsKDF.PRF.SHA256_HMAC, 32)
                        .using(ki, fixedInput));
        byte[] out = new byte[size];
        calculator.generateBytes(out);
        return out;
    }

    private static byte[] tls12Prf(byte[] secret, String label, byte[] seed, int size) {
        KDFCalculator<?> calculator = new FipsKDF.TLSOperatorFactory()
                .createKDFCalculator(FipsKDF.TLS1_2
                        .withPRF(FipsKDF.TLSPRF.SHA256_HMAC)
                        .using(secret, label, seed));
        byte[] out = new byte[size];
        calculator.generateBytes(out);
        return out;
    }
}
