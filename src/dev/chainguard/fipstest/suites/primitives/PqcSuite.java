package dev.chainguard.fipstest.suites.primitives;

import dev.chainguard.fipstest.harness.Capabilities;
import dev.chainguard.fipstest.harness.Expect;
import dev.chainguard.fipstest.harness.TestContext;
import dev.chainguard.fipstest.harness.TestSuite;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.List;
import java.util.Set;

/**
 * Post-quantum probes. ML-KEM/ML-DSA/SLH-DSA are roadmapped for the bc-fips
 * 2.2 line, so on 2.1.x every case SKIPs with an explicit message - the same
 * binary will start exercising them the day the provider grows them.
 * The bcpqc-fips jar (LMS/HSS stateful hash signatures) is probed too.
 */
public final class PqcSuite implements TestSuite {

    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public String name() {
        return "primitives.pqc";
    }

    @Override
    public Set<String> tags() {
        return Set.of("primitives", "pqc");
    }

    @Override
    public void register(TestContext ctx) {
        for (String algorithm : List.of("ML-KEM-768", "ML-KEM-1024")) {
            ctx.add(algorithm.toLowerCase() + "/keygen-if-available", () -> {
                Capabilities.require("KeyPairGenerator", algorithm, "BCFIPS");
                KeyPair kp = KeyPairGenerator.getInstance(algorithm, "BCFIPS")
                        .generateKeyPair();
                Expect.assertTrue(kp.getPublic().getEncoded().length > 0,
                        algorithm + " public key encoding");
            });
        }

        for (String algorithm : List.of("ML-DSA-65", "ML-DSA-87")) {
            ctx.add(algorithm.toLowerCase() + "/sign-verify-if-available", () -> {
                Capabilities.require("Signature", algorithm, "BCFIPS");
                KeyPair kp = KeyPairGenerator.getInstance(algorithm, "BCFIPS")
                        .generateKeyPair();
                byte[] message = new byte[48];
                RANDOM.nextBytes(message);

                Signature signer = Signature.getInstance(algorithm, "BCFIPS");
                signer.initSign(kp.getPrivate());
                signer.update(message);
                byte[] signature = signer.sign();

                Signature verifier = Signature.getInstance(algorithm, "BCFIPS");
                verifier.initVerify(kp.getPublic());
                verifier.update(message);
                Expect.assertTrue(verifier.verify(signature), algorithm + " verify");

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

        // Stateful hash signatures from bcpqc-fips (present on the 2.1 line).
        ctx.add("lms/availability-probe", () -> {
            boolean lms = Capabilities.has("Signature", "LMS", "BCFIPS")
                    || Capabilities.hasProvider("BCPQC")
                    && Capabilities.has("Signature", "LMS", "BCPQC");
            System.out.println("INFO|LMS signature availability: " + lms);
        });
    }
}
