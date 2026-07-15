package dev.chainguard.fipstest.suites.scenarios;

import dev.chainguard.fipstest.harness.Capabilities;
import dev.chainguard.fipstest.harness.Expect;
import dev.chainguard.fipstest.harness.Mode;
import dev.chainguard.fipstest.harness.TestContext;
import dev.chainguard.fipstest.harness.TestSuite;
import dev.chainguard.fipstest.util.TestCerts;
import dev.chainguard.fipstest.util.TestKeys;

import java.security.KeyPair;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * X.509 chain building and PKIX validation - the certificate machinery every
 * TLS-facing consumer (kafka, zookeeper, elasticsearch, keycloak) rides on.
 * Chains are built with bcpkix and validated with the PKIX CertPathValidator
 * under the FIPS java.security policy.
 */
public final class CertPathSuite implements TestSuite {

    @Override
    public String name() {
        return "scenarios.certpath";
    }

    @Override
    public Set<String> tags() {
        return Set.of("scenarios", "certpath", "x509");
    }

    @Override
    public void register(TestContext ctx) {
        ctx.add("rsa-chain/three-tier-validates", () -> {
            requirePkix();
            Chain chain = Chain.rsa();
            validate(chain.leaf, chain.intermediate, chain.root);
        });

        ctx.add("ec-chain/three-tier-validates", () -> {
            requirePkix();
            Chain chain = Chain.ec();
            validate(chain.leaf, chain.intermediate, chain.root);
        });

        ctx.add("negative/expired-leaf-fails", () -> {
            requirePkix();
            KeyPair rootKey = TestKeys.rsaSign(2048);
            X509Certificate root = TestCerts.selfSignedCa(rootKey,
                    "CN=fipstest Root", "SHA256withRSA");
            KeyPair leafKey = TestKeys.rsaSign(3072);
            X509Certificate expired = TestCerts.expiredLeaf(leafKey.getPublic(),
                    "CN=localhost", rootKey, "CN=fipstest Root", "SHA256withRSA");
            Expect.mustThrow(CertPathValidatorException.class, "expired leaf", () ->
                    validate(expired, root));
        });

        ctx.add("negative/leaf-signed-by-impostor-fails", () -> {
            requirePkix();
            KeyPair rootKey = TestKeys.rsaSign(2048);
            X509Certificate root = TestCerts.selfSignedCa(rootKey,
                    "CN=fipstest Root", "SHA256withRSA");
            // Impostor key signs a leaf that CLAIMS the root as issuer.
            KeyPair impostor = TestKeys.rsaSign(3072);
            KeyPair leafKey = TestKeys.ec("P-256");
            X509Certificate forged = TestCerts.serverLeaf(leafKey.getPublic(),
                    "CN=localhost", impostor, "CN=fipstest Root", "SHA256withRSA");
            Expect.mustThrow(CertPathValidatorException.class, "forged signature", () ->
                    validate(forged, root));
        });

        // SHA-1 signature GENERATION is disallowed under 140-3 approved mode;
        // with approved-only off the chain builds but PKIX still rejects it
        // per jdk.certpath.disabledAlgorithms - two layers, both asserted.
        ctx.addApproved("negative/sha1-cert-signing-rejected-approved", () -> {
            requirePkix(); // capability gate OUTSIDE the expected-failure body
            Expect.mustFail("SHA1withRSA certificate signing in approved mode", () ->
                    TestCerts.selfSignedCa(TestKeys.rsaSign(2048),
                            "CN=sha1-root", "SHA1withRSA"));
        });

        // Observed split: the DEFAULT PKIX validator resolves to BCFIPS,
        // which does NOT consult jdk.certpath.disabledAlgorithms - a SHA-1
        // chain passes it (in unapproved mode, where such a chain can even be
        // built). SUN's PKIX validator enforces the property and rejects the
        // same chain. Both behaviors are pinned; if a bc-fips update starts
        // honoring the property, the first case flags it for review.
        ctx.add("sha1-chain/bcfips-pkix-accepts-config-not-consulted", Set.of(),
                java.util.EnumSet.of(Mode.UNAPPROVED), () -> {
            requirePkix();
            Sha1Chain chain = Sha1Chain.build();
            Expect.assertEquals("BCFIPS",
                    CertPathValidator.getInstance("PKIX").getProvider().getName(),
                    "default PKIX validator provider");
            validate(chain.leaf, chain.root); // pinned: passes on bc-fips 2.1.1
        });

        ctx.add("sha1-chain/sun-pkix-rejects-per-java-security", Set.of(),
                java.util.EnumSet.of(Mode.UNAPPROVED), () -> {
            requirePkix();
            // openjdk-fips >= 25 drops the SUN provider entirely.
            Capabilities.requireProvider("SUN");
            Sha1Chain chain = Sha1Chain.build();
            Expect.mustThrow(CertPathValidatorException.class,
                    "SHA-1 chain through SUN PKIX", () ->
                            validateWith("SUN", chain.leaf, chain.root));
        });

        ctx.add("certificate-factory/bcfips-der-roundtrip", () -> {
            requirePkix();
            X509Certificate cert = TestCerts.selfSignedCa(TestKeys.rsaSign(2048),
                    "CN=roundtrip", "SHA256withRSA");
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BCFIPS");
            X509Certificate parsed = (X509Certificate) cf.generateCertificate(
                    new java.io.ByteArrayInputStream(cert.getEncoded()));
            Expect.assertArrayEquals(cert.getEncoded(), parsed.getEncoded(),
                    "DER round-trip");
            parsed.verify(parsed.getPublicKey());
        });
    }

    private static final class Chain {
        final X509Certificate root;
        final X509Certificate intermediate;
        final X509Certificate leaf;

        private Chain(X509Certificate root, X509Certificate intermediate,
                      X509Certificate leaf) {
            this.root = root;
            this.intermediate = intermediate;
            this.leaf = leaf;
        }

        static Chain rsa() throws Exception {
            KeyPair rootKey = TestKeys.rsaSign(2048);
            KeyPair intKey = TestKeys.rsaSign(3072);
            KeyPair leafKey = TestKeys.ec("P-256");
            X509Certificate root = TestCerts.selfSignedCa(rootKey,
                    "CN=fipstest Root, O=Chainguard", "SHA256withRSA");
            X509Certificate intermediate = TestCerts.intermediateCa(intKey.getPublic(),
                    "CN=fipstest Intermediate, O=Chainguard",
                    rootKey, "CN=fipstest Root, O=Chainguard", "SHA256withRSA");
            X509Certificate leaf = TestCerts.serverLeaf(leafKey.getPublic(),
                    "CN=localhost, O=Chainguard",
                    intKey, "CN=fipstest Intermediate, O=Chainguard", "SHA256withRSA");
            return new Chain(root, intermediate, leaf);
        }

        static Chain ec() throws Exception {
            KeyPair rootKey = TestKeys.ec("P-384");
            KeyPair intKey = TestKeys.ec("P-256");
            KeyPair leafKey = TestKeys.ec("P-256");
            X509Certificate root = TestCerts.selfSignedCa(rootKey,
                    "CN=fipstest EC Root, O=Chainguard", "SHA384withECDSA");
            X509Certificate intermediate = TestCerts.intermediateCa(intKey.getPublic(),
                    "CN=fipstest EC Intermediate, O=Chainguard",
                    rootKey, "CN=fipstest EC Root, O=Chainguard", "SHA384withECDSA");
            X509Certificate leaf = TestCerts.serverLeaf(leafKey.getPublic(),
                    "CN=localhost, O=Chainguard",
                    intKey, "CN=fipstest EC Intermediate, O=Chainguard",
                    "SHA256withECDSA");
            return new Chain(root, intermediate, leaf);
        }
    }

    private static final class Sha1Chain {
        final X509Certificate root;
        final X509Certificate leaf;

        private Sha1Chain(X509Certificate root, X509Certificate leaf) {
            this.root = root;
            this.leaf = leaf;
        }

        static Sha1Chain build() throws Exception {
            KeyPair rootKey = TestKeys.rsaSign(2048);
            X509Certificate root = TestCerts.selfSignedCa(rootKey,
                    "CN=sha1-root", "SHA1withRSA");
            KeyPair leafKey = TestKeys.rsaSign(3072);
            X509Certificate leaf = TestCerts.serverLeaf(leafKey.getPublic(),
                    "CN=localhost", rootKey, "CN=sha1-root", "SHA1withRSA");
            return new Sha1Chain(root, leaf);
        }
    }

    private static void validate(X509Certificate leaf, X509Certificate... issuers)
            throws Exception {
        validateWith(null, leaf, issuers);
    }

    private static void validateWith(String provider, X509Certificate leaf,
                                     X509Certificate... issuers) throws Exception {
        X509Certificate anchor = issuers[issuers.length - 1];
        List<X509Certificate> path = new java.util.ArrayList<>();
        path.add(leaf);
        path.addAll(Arrays.asList(issuers).subList(0, issuers.length - 1));

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        CertPath certPath = cf.generateCertPath(path);
        PKIXParameters params = new PKIXParameters(
                Collections.singleton(new TrustAnchor(anchor, null)));
        params.setRevocationEnabled(false);
        CertPathValidator validator = provider == null
                ? CertPathValidator.getInstance("PKIX")
                : CertPathValidator.getInstance("PKIX", provider);
        validator.validate(certPath, params);
    }

    private static void requirePkix() {
        Capabilities.requireClass("org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder");
    }
}
