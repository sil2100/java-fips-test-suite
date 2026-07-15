package dev.chainguard.fipstest.suites.scenarios;

import dev.chainguard.fipstest.harness.Capabilities;
import dev.chainguard.fipstest.harness.Expect;
import dev.chainguard.fipstest.harness.TestContext;
import dev.chainguard.fipstest.harness.TestSuite;
import dev.chainguard.fipstest.util.TestCerts;
import dev.chainguard.fipstest.util.TestKeys;

import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Set;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

/**
 * CSR issuance flow (bcpkix): generate a PKCS#10 request, verify its
 * self-signature, have a CA sign it, and round-trip everything through PEM -
 * the kafka-fips PEM-based TLS setup in miniature.
 */
public final class CsrSuite implements TestSuite {

    @Override
    public String name() {
        return "scenarios.csr";
    }

    @Override
    public Set<String> tags() {
        return Set.of("scenarios", "csr", "pem", "x509");
    }

    @Override
    public void register(TestContext ctx) {
        ctx.add("pkcs10/generate-verify-issue", () -> {
            requirePkix();
            KeyPair requesterKey = TestKeys.ec("P-256");
            PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(
                    new X500Name("CN=csr-requester, O=Chainguard"),
                    requesterKey.getPublic())
                    .build(new JcaContentSignerBuilder("SHA256withECDSA")
                            .setProvider("BCFIPS").build(requesterKey.getPrivate()));

            Expect.assertTrue(csr.isSignatureValid(
                            new JcaContentVerifierProviderBuilder().setProvider("BCFIPS")
                                    .build(csr.getSubjectPublicKeyInfo())),
                    "CSR self-signature");

            // A tampered CSR must not verify.
            byte[] der = csr.getEncoded();
            der[der.length - 10] ^= 0x01;
            PKCS10CertificationRequest tampered = new PKCS10CertificationRequest(der);
            boolean tamperedOk;
            try {
                tamperedOk = tampered.isSignatureValid(
                        new JcaContentVerifierProviderBuilder().setProvider("BCFIPS")
                                .build(tampered.getSubjectPublicKeyInfo()));
            } catch (Exception e) {
                tamperedOk = false;
            }
            Expect.mustBeFalse(tamperedOk, "tampered CSR signature");

            // CA issues a certificate for the CSR key; issued cert verifies.
            KeyPair caKey = TestKeys.rsaSign(2048);
            X509Certificate ca = TestCerts.selfSignedCa(caKey,
                    "CN=csr-ca, O=Chainguard", "SHA256withRSA");
            X509Certificate issued = TestCerts.serverLeaf(requesterKey.getPublic(),
                    "CN=csr-requester, O=Chainguard",
                    caKey, "CN=csr-ca, O=Chainguard", "SHA256withRSA");
            issued.verify(ca.getPublicKey());
        });

        ctx.add("pem/certificate-and-csr-roundtrip", () -> {
            requirePkix();
            KeyPair kp = TestKeys.ec("P-256");
            X509Certificate cert = TestCerts.selfSignedCa(TestKeys.rsaSign(2048),
                    "CN=pem-test", "SHA256withRSA");
            PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(
                    new X500Name("CN=pem-csr"), kp.getPublic())
                    .build(new JcaContentSignerBuilder("SHA256withECDSA")
                            .setProvider("BCFIPS").build(kp.getPrivate()));

            StringWriter sw = new StringWriter();
            try (JcaPEMWriter writer = new JcaPEMWriter(sw)) {
                writer.writeObject(cert);
                writer.writeObject(csr);
            }
            String pem = sw.toString();
            Expect.assertTrue(pem.contains("BEGIN CERTIFICATE"), "certificate PEM header");
            Expect.assertTrue(pem.contains("BEGIN CERTIFICATE REQUEST"), "CSR PEM header");

            try (PEMParser parser = new PEMParser(new StringReader(pem))) {
                Object first = parser.readObject();
                Object second = parser.readObject();
                Expect.assertTrue(first instanceof X509CertificateHolder,
                        "first PEM object type: " + first.getClass().getName());
                Expect.assertTrue(second instanceof PKCS10CertificationRequest,
                        "second PEM object type: " + second.getClass().getName());
                X509Certificate parsed = new JcaX509CertificateConverter()
                        .setProvider("BCFIPS")
                        .getCertificate((X509CertificateHolder) first);
                Expect.assertArrayEquals(cert.getEncoded(), parsed.getEncoded(),
                        "certificate PEM round-trip");
            }
        });
    }

    private static void requirePkix() {
        Capabilities.requireClass("org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder");
        Capabilities.requireClass("org.bouncycastle.openssl.PEMParser");
    }
}
