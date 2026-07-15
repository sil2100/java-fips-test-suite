package dev.chainguard.fipstest.util;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * bcpkix-based X.509 helpers, mirroring how consumers (kafka's PEM setup,
 * zookeeper/tika keytool flows, keycloak) create their certificates. All
 * signing goes through the BCFIPS provider explicitly.
 */
public final class TestCerts {

    private static final AtomicLong SERIAL = new AtomicLong(0x1000);
    private static final long DAY_MS = 24L * 60 * 60 * 1000;

    private TestCerts() {
    }

    public static X509Certificate selfSignedCa(KeyPair keyPair, String dn, String sigAlg)
            throws Exception {
        return build(keyPair.getPublic(), dn, keyPair, dn, sigAlg, true, false,
                new Date(System.currentTimeMillis() - DAY_MS),
                new Date(System.currentTimeMillis() + 365 * DAY_MS));
    }

    public static X509Certificate intermediateCa(java.security.PublicKey subjectKey,
                                                 String dn, KeyPair issuerKeyPair,
                                                 String issuerDn, String sigAlg)
            throws Exception {
        return build(subjectKey, dn, issuerKeyPair, issuerDn, sigAlg, true, false,
                new Date(System.currentTimeMillis() - DAY_MS),
                new Date(System.currentTimeMillis() + 180 * DAY_MS));
    }

    public static X509Certificate serverLeaf(java.security.PublicKey subjectKey,
                                             String dn, KeyPair issuerKeyPair,
                                             String issuerDn, String sigAlg)
            throws Exception {
        return build(subjectKey, dn, issuerKeyPair, issuerDn, sigAlg, false, true,
                new Date(System.currentTimeMillis() - DAY_MS),
                new Date(System.currentTimeMillis() + 90 * DAY_MS));
    }

    /** Client-auth leaf for mutual TLS. */
    public static X509Certificate clientLeaf(java.security.PublicKey subjectKey,
                                             String dn, KeyPair issuerKeyPair,
                                             String issuerDn, String sigAlg)
            throws Exception {
        return build(subjectKey, dn, issuerKeyPair, issuerDn, sigAlg, false, false,
                new Date(System.currentTimeMillis() - DAY_MS),
                new Date(System.currentTimeMillis() + 90 * DAY_MS));
    }

    /** Leaf whose validity window already ended - for expiry negatives. */
    public static X509Certificate expiredLeaf(java.security.PublicKey subjectKey,
                                              String dn, KeyPair issuerKeyPair,
                                              String issuerDn, String sigAlg)
            throws Exception {
        return build(subjectKey, dn, issuerKeyPair, issuerDn, sigAlg, false, true,
                new Date(System.currentTimeMillis() - 30 * DAY_MS),
                new Date(System.currentTimeMillis() - DAY_MS));
    }

    private static X509Certificate build(java.security.PublicKey subjectKey, String dn,
                                         KeyPair issuerKeyPair, String issuerDn,
                                         String sigAlg, boolean ca, boolean serverAuth,
                                         Date notBefore, Date notAfter) throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Name(issuerDn),
                BigInteger.valueOf(SERIAL.incrementAndGet()),
                notBefore, notAfter,
                new X500Name(dn),
                subjectKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        if (ca) {
            builder.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        } else {
            builder.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        }
        if (serverAuth) {
            builder.addExtension(Extension.extendedKeyUsage, false,
                    new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
            builder.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, "localhost")));
        }
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider("BCFIPS").build(issuerKeyPair.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BCFIPS")
                .getCertificate(holder);
    }
}
