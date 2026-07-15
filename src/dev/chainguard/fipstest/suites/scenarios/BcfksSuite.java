package dev.chainguard.fipstest.suites.scenarios;

import dev.chainguard.fipstest.harness.Capabilities;
import dev.chainguard.fipstest.harness.Expect;
import dev.chainguard.fipstest.harness.TestContext;
import dev.chainguard.fipstest.harness.TestSuite;
import dev.chainguard.fipstest.util.TestCerts;
import dev.chainguard.fipstest.util.TestKeys;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Set;

/**
 * BCFKS keystore lifecycle, distilled from prometheus-jmx-exporter-fips
 * our jmx-exporter FIPS package tests and the kafka/zookeeper BCFKS flows: programmatic
 * creation, private/secret key entries, store/load round-trips, rotation,
 * and integrity negatives (wrong password, corrupted file).
 */
public final class BcfksSuite implements TestSuite {

    private static final char[] PASSWORD = "FipsTest-Store-Passw0rd!".toCharArray();

    @Override
    public String name() {
        return "scenarios.bcfks";
    }

    @Override
    public Set<String> tags() {
        return Set.of("scenarios", "keystore", "bcfks");
    }

    @Override
    public void register(TestContext ctx) {
        ctx.add("private-key-entry/store-load-use", () -> {
            requirePkix();
            KeyPair kp = TestKeys.rsaSign(2048);
            X509Certificate cert = TestCerts.selfSignedCa(kp,
                    "CN=bcfks-test, O=Chainguard", "SHA256withRSA");

            KeyStore store = KeyStore.getInstance("BCFKS", "BCFIPS");
            store.load(null, null);
            store.setKeyEntry("server", kp.getPrivate(), PASSWORD,
                    new Certificate[] {cert});

            byte[] serialized = serialize(store);
            KeyStore reloaded = KeyStore.getInstance("BCFKS", "BCFIPS");
            reloaded.load(new ByteArrayInputStream(serialized), PASSWORD);

            Expect.assertEquals(1, reloaded.size(), "keystore entry count");
            PrivateKey recovered = (PrivateKey) reloaded.getKey("server", PASSWORD);
            Expect.assertTrue(recovered != null, "private key not recovered");

            // The recovered key must actually work.
            Signature signer = Signature.getInstance("SHA256withRSA", "BCFIPS");
            signer.initSign(recovered);
            signer.update("bcfks".getBytes());
            byte[] sig = signer.sign();
            Signature verifier = Signature.getInstance("SHA256withRSA", "BCFIPS");
            verifier.initVerify(reloaded.getCertificate("server").getPublicKey());
            verifier.update("bcfks".getBytes());
            Expect.assertTrue(verifier.verify(sig), "signature with recovered key");
        });

        ctx.add("secret-key-entry/store-load", () -> {
            KeyGenerator kg = KeyGenerator.getInstance("AES", "BCFIPS");
            kg.init(256);
            SecretKey secret = kg.generateKey();

            KeyStore store = KeyStore.getInstance("BCFKS", "BCFIPS");
            store.load(null, null);
            store.setEntry("data-key", new KeyStore.SecretKeyEntry(secret),
                    new KeyStore.PasswordProtection(PASSWORD));

            KeyStore reloaded = KeyStore.getInstance("BCFKS", "BCFIPS");
            reloaded.load(new ByteArrayInputStream(serialize(store)), PASSWORD);
            SecretKey recovered = (SecretKey) reloaded.getKey("data-key", PASSWORD);
            Expect.assertArrayEquals(secret.getEncoded(), recovered.getEncoded(),
                    "secret key round-trip");
        });

        ctx.add("rotation/replace-and-enumerate", () -> {
            requirePkix();
            KeyStore store = KeyStore.getInstance("BCFKS", "BCFIPS");
            store.load(null, null);

            KeyPair oldKey = TestKeys.rsaSign(2048);
            store.setKeyEntry("service", oldKey.getPrivate(), PASSWORD,
                    new Certificate[] {TestCerts.selfSignedCa(oldKey,
                            "CN=old", "SHA256withRSA")});

            KeyPair newKey = TestKeys.rsaSign(3072);
            store.deleteEntry("service");
            store.setKeyEntry("service", newKey.getPrivate(), PASSWORD,
                    new Certificate[] {TestCerts.selfSignedCa(newKey,
                            "CN=new", "SHA256withRSA")});

            Expect.assertEquals(1, store.size(), "entry count after rotation");
            Expect.assertEquals(Collections.singletonList("service"),
                    Collections.list(store.aliases()), "aliases after rotation");
            X509Certificate current = (X509Certificate) store.getCertificate("service");
            Expect.assertTrue(current.getSubjectX500Principal().getName().contains("new"),
                    "rotated certificate not current");
        });

        ctx.add("integrity/wrong-password-rejected", () -> {
            KeyStore store = KeyStore.getInstance("BCFKS", "BCFIPS");
            store.load(null, null);
            KeyGenerator kg = KeyGenerator.getInstance("AES", "BCFIPS");
            kg.init(256);
            store.setEntry("k", new KeyStore.SecretKeyEntry(kg.generateKey()),
                    new KeyStore.PasswordProtection(PASSWORD));
            byte[] serialized = serialize(store);

            KeyStore reloaded = KeyStore.getInstance("BCFKS", "BCFIPS");
            Expect.mustThrow(IOException.class, "BCFKS load with wrong password", () ->
                    reloaded.load(new ByteArrayInputStream(serialized),
                            "not-the-password".toCharArray()));
        });

        ctx.add("integrity/corrupted-file-rejected", () -> {
            KeyStore store = KeyStore.getInstance("BCFKS", "BCFIPS");
            store.load(null, null);
            KeyGenerator kg = KeyGenerator.getInstance("AES", "BCFIPS");
            kg.init(256);
            store.setEntry("k", new KeyStore.SecretKeyEntry(kg.generateKey()),
                    new KeyStore.PasswordProtection(PASSWORD));
            byte[] serialized = serialize(store);
            serialized[serialized.length / 2] ^= 0x01;
            byte[] corrupted = serialized;

            KeyStore reloaded = KeyStore.getInstance("BCFKS", "BCFIPS");
            Expect.mustFail("BCFKS load of corrupted file", () ->
                    reloaded.load(new ByteArrayInputStream(corrupted), PASSWORD));
        });

        // JKS handling depends on the configuration:
        // - JDK <= 21 policy configs keep SUN, so JKS is a full writable store
        // - the openjdk-fips >= 25 packaged config drops SUN and instead sets
        //   org.bouncycastle.jca.enable_jks=true: BCFIPS serves a READ-ONLY,
        //   certificate-only JKS for legacy truststore reading
        ctx.add("interop/jks-provider-and-writability", () -> {
            KeyStore jks;
            try {
                jks = KeyStore.getInstance("JKS");
                jks.load(null, null);
            } catch (Exception e) {
                throw new dev.chainguard.fipstest.harness.SkipException(
                        "JKS keystore type not available in this configuration: " + e);
            }
            String provider = jks.getProvider().getName();
            if ("BCFIPS".equals(provider)) {
                KeyStore readOnly = jks;
                Expect.mustFail("storing via BCFIPS read-only JKS compat", () ->
                        readOnly.store(new ByteArrayOutputStream(), PASSWORD));
            } else {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                jks.store(bos, PASSWORD);
                byte[] jksBytes = bos.toByteArray();
                // The kafka-fips rejection pattern: JKS bytes must not load
                // as BCFKS.
                KeyStore bcfks = KeyStore.getInstance("BCFKS", "BCFIPS");
                Expect.mustFail("JKS bytes loaded as BCFKS", () ->
                        bcfks.load(new ByteArrayInputStream(jksBytes), PASSWORD));
            }
        });

        registerImportedStoreCase(ctx);
    }

    /**
     * JKS -> BCFKS keytool -importkeystore interop (openjdk-fips pattern).
     * run.sh performs the conversion with keytool and passes the result via
     * environment variables; without them the case SKIPs.
     */
    private void registerImportedStoreCase(TestContext ctx) {
        ctx.add("imported/jks-converted-store-loads-and-signs", () -> {
            String path = System.getenv("FIPSTEST_IMPORTED_STORE");
            String pass = System.getenv("FIPSTEST_IMPORTED_STOREPASS");
            if (path == null || pass == null) {
                throw new dev.chainguard.fipstest.harness.SkipException(
                        "FIPSTEST_IMPORTED_STORE not set (keytool interop step not run)");
            }
            KeyStore store = KeyStore.getInstance("BCFKS", "BCFIPS");
            try (java.io.InputStream in = java.nio.file.Files.newInputStream(
                    java.nio.file.Paths.get(path))) {
                store.load(in, pass.toCharArray());
            }
            Expect.assertTrue(store.size() > 0, "imported store is empty");
            String alias = store.aliases().nextElement();
            PrivateKey key = (PrivateKey) store.getKey(alias, pass.toCharArray());
            Expect.assertTrue(key != null, "no key under alias " + alias);

            Signature signer = Signature.getInstance("SHA256withRSA", "BCFIPS");
            signer.initSign(key);
            signer.update("imported".getBytes());
            Expect.assertTrue(signer.sign().length > 0, "signature with imported key");
        });
    }

    private static void requirePkix() {
        Capabilities.requireClass("org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder");
    }

    private static byte[] serialize(KeyStore store) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        store.store(bos, PASSWORD);
        return bos.toByteArray();
    }
}
