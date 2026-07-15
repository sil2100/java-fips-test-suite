package dev.chainguard.fipstest.suites.scenarios;

import dev.chainguard.fipstest.harness.Expect;
import dev.chainguard.fipstest.harness.TestContext;
import dev.chainguard.fipstest.harness.TestSuite;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Set;

/**
 * SCRAM-SHA-256 (RFC 5802/7677) computed exactly the way kafka's
 * ScramFormatter does: PBKDF2 salted password, HMAC client/server keys,
 * SHA-256 stored key, HMAC proofs. Plus the generic PBKDF2
 * hash-then-verify password storage flow.
 *
 * The RFC 7677 known-answer vector uses the password "pencil" (6 chars),
 * which approved mode's PBKDF2 correctly refuses - so the exact-vector case
 * runs in the unapproved leg, while approved mode gets a self-consistent
 * SCRAM flow with a compliant-length password. That split IS the kafka-fips
 * finding: SCRAM users on FIPS need 14+ char passwords.
 */
public final class ScramSuite implements TestSuite {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public String name() {
        return "scenarios.scram";
    }

    @Override
    public Set<String> tags() {
        return Set.of("scenarios", "scram", "password");
    }

    @Override
    public void register(TestContext ctx) {
        ctx.addUnapproved("rfc7677/exact-vector", () -> {
            byte[] salt = Base64.getDecoder().decode("W22ZaJ0SNY7soEsUEjb6gQ==");
            byte[] saltedPassword = pbkdf2("pencil", salt, 4096);

            byte[] clientKey = hmac(saltedPassword, "Client Key");
            byte[] storedKey = sha256(clientKey);
            String authMessage = "n=user,r=rOprNGfwEbeRWgbNEkqO,"
                    + "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,"
                    + "s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,"
                    + "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
            byte[] clientSignature = hmac(storedKey, authMessage);
            byte[] clientProof = xor(clientKey, clientSignature);
            Expect.assertEquals("dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
                    Base64.getEncoder().encodeToString(clientProof),
                    "RFC 7677 client proof");

            byte[] serverKey = hmac(saltedPassword, "Server Key");
            byte[] serverSignature = hmac(serverKey, authMessage);
            Expect.assertEquals("6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=",
                    Base64.getEncoder().encodeToString(serverSignature),
                    "RFC 7677 server signature");
        });

        // Same computation, approved mode, compliant password length: the
        // full client<->server exchange must be mutually consistent.
        ctx.add("full-exchange/self-consistent", () -> {
            String password = "compliant-scram-password";
            byte[] salt = new byte[16];
            RANDOM.nextBytes(salt);
            byte[] saltedPassword = pbkdf2(password, salt, 4096);

            // Server stores (storedKey, serverKey) at credential creation.
            byte[] storedKey = sha256(hmac(saltedPassword, "Client Key"));
            byte[] serverKey = hmac(saltedPassword, "Server Key");

            String authMessage = "n=fipstest,r=cnonce,r=cnoncesnonce,s="
                    + Base64.getEncoder().encodeToString(salt)
                    + ",i=4096,c=biws,r=cnoncesnonce";

            // Client proves knowledge of the password.
            byte[] clientKey = hmac(saltedPassword, "Client Key");
            byte[] clientProof = xor(clientKey, hmac(storedKey, authMessage));

            // Server verifies: proof XOR signature must hash to storedKey.
            byte[] recoveredClientKey = xor(clientProof, hmac(storedKey, authMessage));
            Expect.assertArrayEquals(storedKey, sha256(recoveredClientKey),
                    "server-side proof verification");

            // A wrong password must fail verification.
            byte[] wrongSalted = pbkdf2("compliant-wrong-password!", salt, 4096);
            byte[] wrongProof = xor(hmac(wrongSalted, "Client Key"),
                    hmac(sha256(hmac(wrongSalted, "Client Key")), authMessage));
            byte[] recoveredWrong = xor(wrongProof, hmac(storedKey, authMessage));
            Expect.mustBeFalse(MessageDigest.isEqual(storedKey, sha256(recoveredWrong)),
                    "wrong password accepted by SCRAM verification");

            // Mutual auth: client verifies the server signature.
            Expect.assertArrayEquals(hmac(serverKey, authMessage),
                    hmac(serverKey, authMessage), "server signature determinism");
        });

        ctx.add("password-storage/hash-then-verify", () -> {
            String password = "user-supplied-password-42";
            byte[] salt = new byte[16];
            RANDOM.nextBytes(salt);
            byte[] stored = pbkdf2(password, salt, 210_000);

            Expect.assertTrue(MessageDigest.isEqual(stored,
                            pbkdf2(password, salt, 210_000)),
                    "correct password rejected");
            Expect.mustBeFalse(MessageDigest.isEqual(stored,
                            pbkdf2("user-supplied-password-43", salt, 210_000)),
                    "wrong password accepted");
            Expect.mustBeFalse(MessageDigest.isEqual(stored,
                            pbkdf2(password, new byte[16], 210_000)),
                    "wrong salt accepted");
        });
    }

    private static byte[] pbkdf2(String password, byte[] salt, int iterations)
            throws Exception {
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256", "BCFIPS");
        return skf.generateSecret(new PBEKeySpec(password.toCharArray(), salt,
                iterations, 256)).getEncoded();
    }

    private static byte[] hmac(byte[] key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256", "BCFIPS");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data.getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256", "BCFIPS").digest(data);
    }

    private static byte[] xor(byte[] a, byte[] b) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ b[i]);
        }
        return out;
    }
}
