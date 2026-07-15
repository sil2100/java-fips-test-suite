package dev.chainguard.fipstest.suites.negative;

import dev.chainguard.fipstest.harness.Capabilities;
import dev.chainguard.fipstest.harness.Expect;
import dev.chainguard.fipstest.harness.TestContext;
import dev.chainguard.fipstest.harness.TestSuite;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.bouncycastle.crypto.CryptoServicesRegistrar;

/**
 * The consolidated approved-mode rejection catalog (absorbs the
 * UNSUPPORTED_CIPHER_MODES map of bcfips-policy-140-3 Test.java, the weak-key
 * rejection from our jmx-exporter FIPS package tests and the kafka
 * FIPS rejection scripts).
 *
 * In approved mode every entry MUST be rejected. In unapproved mode most of
 * these algorithms come back to life (bc-fips registers its "general" package
 * algorithms), which the unapproved leg observes via probe cases - strict
 * unapproved-availability assertions exist only for entries whose behavior is
 * pinned (MD5 is covered in primitives.digest, DESede in primitives.cipher).
 */
public final class ApprovedModeSuite implements TestSuite {

    private static final class Prohibited {
        final String transformation;
        final boolean availableUnapproved;

        Prohibited(String transformation, boolean availableUnapproved) {
            this.transformation = transformation;
            this.availableUnapproved = availableUnapproved;
        }
    }

    /**
     * name -> Cipher transformation, from bcfips-policy Test.java. The
     * availableUnapproved flag records observed bc-fips 2.1.1 behavior: the
     * provider registers its "general" package algorithms when approved-only
     * is off - drift in either direction on a version bump is a finding.
     * (CAST5/SHACAL-2 stay unavailable with these exact transformation
     * strings even in unapproved mode.)
     */
    private static final Map<String, Prohibited> PROHIBITED_CIPHERS = Map.ofEntries(
            Map.entry("blowfish", new Prohibited("Blowfish/CBC/PKCS5Padding", true)),
            Map.entry("aes-eax", new Prohibited("AES/EAX/NoPadding", true)),
            Map.entry("chacha20", new Prohibited("ChaCha20", true)),
            Map.entry("arc4", new Prohibited("ARC4", true)),
            Map.entry("camellia", new Prohibited("Camellia/CBC/PKCS5Padding", true)),
            Map.entry("cast5", new Prohibited("CAST5/CFB8/PKCS5Padding", false)),
            Map.entry("des", new Prohibited("DES/CBC/NoPadding", true)),
            Map.entry("gost28147", new Prohibited("GOST28147/CFB64/NoPadding", true)),
            Map.entry("idea", new Prohibited("IDEA/OFB/NoPadding", true)),
            Map.entry("rc2", new Prohibited("RC2/CTR/NoPadding", true)),
            Map.entry("seed", new Prohibited("SEED/CBC/PKCS5Padding", true)),
            Map.entry("serpent", new Prohibited("Serpent/CBC/NoPadding", true)),
            Map.entry("shacal-2", new Prohibited("SHACAL-2/CTR/PKCS5Padding", false)),
            Map.entry("tripledes-eax", new Prohibited("DESede/EAX/NoPadding", true)),
            Map.entry("twofish", new Prohibited("Twofish/OFB/NoPadding", true)));

    @Override
    public String name() {
        return "negative.approved";
    }

    @Override
    public Set<String> tags() {
        return Set.of("negative", "approved-mode");
    }

    @Override
    public void register(TestContext ctx) {
        for (Map.Entry<String, Prohibited> e : PROHIBITED_CIPHERS.entrySet()) {
            Prohibited p = e.getValue();
            ctx.addApproved("cipher/" + e.getKey() + "/rejected", () ->
                    Expect.mustFail(p.transformation + " in approved mode", () ->
                            Cipher.getInstance(p.transformation, "BCFIPS")));
            ctx.addUnapproved("cipher/" + e.getKey() + "/unapproved-availability", () ->
                    Expect.assertEquals(p.availableUnapproved,
                            Capabilities.has("Cipher", p.transformation, "BCFIPS"),
                            p.transformation + " availability in unapproved mode"));
        }

        // Weak RSA keys (jmx-exporter FIPS test pattern): generation must be refused.
        for (int bits : new int[] {512, 1024}) {
            ctx.addApproved("keygen/rsa-" + bits + "/rejected", () ->
                    Expect.mustFail("RSA-" + bits + " key generation in approved mode", () -> {
                        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BCFIPS");
                        kpg.initialize(bits);
                        kpg.generateKeyPair();
                    }));
        }
        ctx.addUnapproved("keygen/rsa-1024/unapproved-works", () -> {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BCFIPS");
            kpg.initialize(1024);
            Expect.assertTrue(kpg.generateKeyPair() != null, "RSA-1024 keypair");
        });

        // Non-approved elliptic curves: observed bc-fips 2.1.1 behavior is that
        // raw KEY GENERATION for secp256k1/brainpool still succeeds even in
        // approved mode - the provider does not police curve choice at keygen.
        // Enforcement happens at the configuration layer instead
        // (jdk.disabled.namedCurves / jdk.certpath.disabledAlgorithms), which
        // the certpath and TLS suites assert. We pin the provider-level
        // behavior here so a change in a bc-fips update is surfaced.
        for (String curve : new String[] {"secp256k1", "brainpoolP256r1"}) {
            ctx.addApproved("keygen/ec-" + curve + "/permitted-at-provider-level", () -> {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BCFIPS");
                kpg.initialize(new ECGenParameterSpec(curve));
                Expect.assertTrue(kpg.generateKeyPair() != null,
                        "EC " + curve + " keygen (provider-level, config layer disables usage)");
            });
        }

        // Undersized DH.
        ctx.addApproved("keygen/dh-1024/rejected", () ->
                Expect.mustFail("DH-1024 key generation in approved mode", () -> {
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", "BCFIPS");
                    kpg.initialize(1024);
                    kpg.generateKeyPair();
                }));

        // Raw / PKCS#1 v1.5 RSA encryption is not FIPS 140-3 key transport.
        ctx.addApproved("cipher/rsa-raw/rejected", () ->
                Expect.mustFail("raw RSA (NoPadding) in approved mode", () -> {
                    Cipher c = Cipher.getInstance("RSA/NONE/NoPadding", "BCFIPS");
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BCFIPS");
                    kpg.initialize(2048);
                    c.init(Cipher.ENCRYPT_MODE, kpg.generateKeyPair().getPublic());
                    c.doFinal(new byte[32]);
                }));

        ctx.addApproved("cipher/rsa-pkcs1-encrypt/rejected", () ->
                Expect.mustFail("RSA PKCS#1 v1.5 encryption in approved mode", () -> {
                    Cipher c = Cipher.getInstance("RSA/NONE/PKCS1Padding", "BCFIPS");
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BCFIPS");
                    kpg.initialize(2048);
                    c.init(Cipher.ENCRYPT_MODE, kpg.generateKeyPair().getPublic());
                    c.doFinal(new byte[32]);
                }));

        // Weak AES key size requests must be refused by the key generator.
        ctx.add("keygen/aes-64/rejected", () ->
                Expect.mustFail("AES-64 key generation", () -> {
                    KeyGenerator kg = KeyGenerator.getInstance("AES", "BCFIPS");
                    kg.init(64);
                    kg.generateKey();
                }));

        // approved_only from java.security is process-wide: a freshly spawned
        // thread must also observe approved-only mode (it is a per-thread flag
        // whose default comes from the system property).
        ctx.addApproved("mode/approved-only-visible-in-new-thread", () -> {
            AtomicBoolean threadApproved = new AtomicBoolean(false);
            Thread t = new Thread(() ->
                    threadApproved.set(CryptoServicesRegistrar.isInApprovedOnlyMode()));
            t.start();
            t.join(10_000);
            Expect.assertTrue(threadApproved.get(),
                    "new thread does not report approved-only mode");
        });
    }
}
