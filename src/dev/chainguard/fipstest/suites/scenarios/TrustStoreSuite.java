package dev.chainguard.fipstest.suites.scenarios;

import dev.chainguard.fipstest.harness.Capabilities;
import dev.chainguard.fipstest.harness.Expect;
import dev.chainguard.fipstest.harness.SkipException;
import dev.chainguard.fipstest.harness.TestContext;
import dev.chainguard.fipstest.harness.TestSuite;

import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.Set;

/**
 * System truststore integration (java-cacerts-bcfks package): the converted
 * BCFKS cacerts at /etc/ssl/certs/java/cacerts.bcfks, loaded the way
 * consumers do via -Djavax.net.ssl.trustStoreType=FIPS/BCFKS. SKIPs cleanly
 * outside the packaged runtime.
 */
public final class TrustStoreSuite implements TestSuite {

    /**
     * The converted system truststore: java-cacerts-bcfks ships it as
     * cacerts.bcfks; the jlinked openjdk-fips >= 25 images ship the BCFKS
     * store under the plain cacerts name.
     */
    private static final Path[] CACERT_CANDIDATES = {
            Paths.get("/etc/ssl/certs/java/cacerts.bcfks"),
            Paths.get("/etc/ssl/certs/java/cacerts")};

    @Override
    public String name() {
        return "scenarios.truststore";
    }

    @Override
    public Set<String> tags() {
        return Set.of("scenarios", "truststore");
    }

    @Override
    public void register(TestContext ctx) {
        ctx.add("cacerts-bcfks/loads-and-inits-pkix", () -> {
            Path cacerts = null;
            for (Path candidate : CACERT_CANDIDATES) {
                if (Files.isRegularFile(candidate)) {
                    cacerts = candidate;
                    break;
                }
            }
            if (cacerts == null) {
                throw new SkipException("no system truststore present"
                        + " (java-cacerts-bcfks not installed)");
            }
            // Two packaged layouts exist: cacerts.bcfks (BCFKS format,
            // JDK <= 21 stream) and a legacy-format cacerts read through
            // BCFIPS's read-only JKS compat (org.bouncycastle.jca.enable_jks,
            // JDK >= 25 stream with javax.net.ssl.trustStoreType=JKS).
            KeyStore store = null;
            Exception bcfksFailure = null;
            try (InputStream in = Files.newInputStream(cacerts)) {
                KeyStore candidate = KeyStore.getInstance("BCFKS", "BCFIPS");
                candidate.load(in, null);
                store = candidate;
            } catch (Exception e) {
                bcfksFailure = e;
            }
            if (store == null && Capabilities.has("KeyStore", "JKS", "BCFIPS")) {
                try (InputStream in = Files.newInputStream(cacerts)) {
                    KeyStore candidate = KeyStore.getInstance("JKS", "BCFIPS");
                    candidate.load(in, null);
                    store = candidate;
                }
            }
            if (store == null) {
                // FAIL when the environment DECLARES a FIPS truststore (the
                // .bcfks name, or the JDK >= 25 stream's enable_jks compat) -
                // an unloadable declared truststore is breakage, not a SKIP.
                boolean declared = cacerts.toString().endsWith(".bcfks")
                        || Boolean.parseBoolean(java.security.Security.getProperty(
                                "org.bouncycastle.jca.enable_jks"));
                if (declared) {
                    throw new dev.chainguard.fipstest.harness.TestFailure(
                            cacerts + " is declared as the FIPS truststore but"
                                    + " loads neither as BCFKS nor via BCFIPS JKS"
                                    + " compat", bcfksFailure);
                }
                throw new SkipException(cacerts + " is not a FIPS-managed"
                        + " truststore in this environment: " + bcfksFailure);
            }
            Expect.assertTrue(store.size() > 0, cacerts + " is empty");

            TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
            tmf.init(store);
            X509TrustManager tm = (X509TrustManager) tmf.getTrustManagers()[0];
            Expect.assertTrue(tm.getAcceptedIssuers().length > 0,
                    "no accepted issuers from cacerts.bcfks");
        });

        ctx.add("default-trustmanager/initializes", () -> {
            Capabilities.requireProvider("BCJSSE");
            // TrustManagerFactory.init(null) loads the JVM default truststore
            // honoring javax.net.ssl.trustStoreType - the path every consumer
            // takes implicitly. Outside the packaged runtime the default
            // store may not be BCFKS-compatible; that is a SKIP, not a FAIL.
            TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
            try {
                tmf.init((KeyStore) null);
            } catch (Exception e) {
                throw new SkipException("default truststore not loadable in this"
                        + " environment (expected outside packaged runtime): " + e);
            }
            Expect.assertTrue(tmf.getTrustManagers().length > 0, "no trust managers");
        });
    }
}
