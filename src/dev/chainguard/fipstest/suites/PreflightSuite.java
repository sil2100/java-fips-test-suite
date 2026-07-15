package dev.chainguard.fipstest.suites;

import dev.chainguard.fipstest.harness.Capabilities;
import dev.chainguard.fipstest.harness.Expect;
import dev.chainguard.fipstest.harness.Mode;
import dev.chainguard.fipstest.harness.TestContext;
import dev.chainguard.fipstest.harness.TestSuite;

import javax.net.ssl.SSLContext;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Set;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.fips.FipsStatus;

/**
 * Environment sanity assertions: module state, provider order, java.security
 * wiring. Failures here usually mean the runtime configuration is wrong, not
 * that the provider regressed.
 */
public final class PreflightSuite implements TestSuite {

    @Override
    public String name() {
        return "preflight";
    }

    @Override
    public Set<String> tags() {
        return Set.of("preflight", "smoke");
    }

    @Override
    public void register(TestContext ctx) {
        ctx.add("fips-status/ready", () -> {
            Expect.assertTrue(FipsStatus.isReady(), "FipsStatus.isReady() must be true");
            System.out.println("INFO|FipsStatus: " + FipsStatus.getStatusMessage());
        });

        ctx.add("fips-status/approved-mode-matches-config", () ->
                Expect.assertEquals(ctx.mode() == Mode.APPROVED,
                        CryptoServicesRegistrar.isInApprovedOnlyMode(),
                        "approved-only mode vs --mode"));

        ctx.add("providers/bcfips-is-first", () -> {
            Provider[] providers = Security.getProviders();
            Expect.assertTrue(providers.length > 0, "no security providers installed");
            Expect.assertEquals("BCFIPS", providers[0].getName(),
                    "first security provider");
        });

        ctx.add("providers/bcfips-config-string", () -> {
            String p1 = Security.getProperty("security.provider.1");
            Expect.assertTrue(p1 != null && p1.startsWith(
                            "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider"),
                    "security.provider.1 must be BouncyCastleFipsProvider, got: " + p1);
            Expect.assertTrue(p1.contains("C:HYBRID") || p1.contains("C:DEFRND"),
                    "security.provider.1 must carry a DRBG config (C:HYBRID or C:DEFRND), got: "
                            + p1);
        });

        ctx.add("providers/bcjsse-fips-mode", () -> {
            Capabilities.requireProviderConsistentWithConfig("BCJSSE",
                    "BouncyCastleJsseProvider");
            String p2 = Security.getProperty("security.provider.2");
            Expect.assertTrue(p2 != null
                            && p2.startsWith("org.bouncycastle.jsse.provider.BouncyCastleJsseProvider")
                            && p2.contains("fips:BCFIPS"),
                    "security.provider.2 must be BouncyCastleJsseProvider fips:BCFIPS, got: " + p2);
        });

        // Real consumers rely on the DEFAULT SSLContext being BCJSSE - this is
        // how kafka/zookeeper/elasticsearch end up on FIPS TLS without code changes.
        ctx.add("providers/default-sslcontext-is-bcjsse", () -> {
            Capabilities.requireProviderConsistentWithConfig("BCJSSE",
                    "BouncyCastleJsseProvider");
            SSLContext sslContext = SSLContext.getInstance("TLS");
            Expect.assertEquals("BCJSSE", sslContext.getProvider().getName(),
                    "SSLContext.getInstance(\"TLS\") provider");
        });

        ctx.addApproved("config/default-keystore-type-bcfks", () ->
                Expect.assertTrue("bcfks".equalsIgnoreCase(KeyStore.getDefaultType()),
                        "keystore.type must be bcfks, got: " + KeyStore.getDefaultType()));

        ctx.add("random/strong-instance-works", () -> {
            SecureRandom strong = SecureRandom.getInstanceStrong();
            byte[] buf = new byte[32];
            strong.nextBytes(buf);
            System.out.println("INFO|SecureRandom.getInstanceStrong(): algorithm="
                    + strong.getAlgorithm() + " provider=" + strong.getProvider().getName());
        });

        // Port of bcfips-policy Test.java entropy-source logic: with the jent
        // userspace entropy package the strong algorithm is ENTROPY:BCRNG; with
        // securerandom.source=file:/dev/random it is NativePRNGBlocking:SUN.
        ctx.addApproved("random/strong-algorithm-matches-entropy-config", () -> {
            SecureRandom strong = SecureRandom.getInstanceStrong();
            String source = Security.getProperty("securerandom.source");
            String strongAlgorithms = Security.getProperty("securerandom.strongAlgorithms");
            // Declared-but-missing entropy provider is a broken stack, not a SKIP.
            if (strongAlgorithms != null && strongAlgorithms.contains("BCRNG")
                    && !Capabilities.hasProvider("BCRNG")) {
                throw new dev.chainguard.fipstest.harness.TestFailure(
                        "securerandom.strongAlgorithms declares BCRNG ("
                                + strongAlgorithms + ") but the provider is not"
                                + " installed - broken entropy stack");
            }
            if (Capabilities.hasProvider("BCRNG")
                    && !"file:/dev/random".equals(source)) {
                Expect.assertEquals("ENTROPY", strong.getAlgorithm(),
                        "strong SecureRandom algorithm (jent entropy config)");
                Expect.assertEquals("BCRNG", strong.getProvider().getName(),
                        "strong SecureRandom provider (jent entropy config)");
            } else if ("file:/dev/random".equals(source)) {
                Expect.assertEquals("NativePRNGBlocking", strong.getAlgorithm(),
                        "strong SecureRandom algorithm (kernel entropy config)");
                Expect.assertEquals("SUN", strong.getProvider().getName(),
                        "strong SecureRandom provider (kernel entropy config)");
            } else {
                throw new dev.chainguard.fipstest.harness.SkipException(
                        "no BCRNG provider and no kernel-entropy config - local dev environment");
            }
        });

        ctx.add("random/bcfips-default-drbg", () -> {
            SecureRandom r = SecureRandom.getInstance("DEFAULT", "BCFIPS");
            byte[] buf = new byte[32];
            r.nextBytes(buf);
        });
    }
}
