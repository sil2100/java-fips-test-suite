package dev.chainguard.fipstest.suites.negative;

import dev.chainguard.fipstest.harness.Expect;
import dev.chainguard.fipstest.harness.Mode;
import dev.chainguard.fipstest.harness.TestContext;
import dev.chainguard.fipstest.harness.TestSuite;

import java.security.KeyStore;
import java.security.Security;
import java.util.Set;

/**
 * java.security configuration assertions - the policy layer of the FIPS
 * stack (bcfips-policy-140-3). These catch packaging/config regressions
 * rather than provider regressions.
 */
public final class ConfigPolicySuite implements TestSuite {

    @Override
    public String name() {
        return "negative.config";
    }

    @Override
    public Set<String> tags() {
        return Set.of("negative", "config");
    }

    @Override
    public void register(TestContext ctx) {
        ctx.add("jdk-tls-disabled/legacy-protocols-and-ciphers", () -> {
            String disabled = Security.getProperty("jdk.tls.disabledAlgorithms");
            Expect.assertTrue(disabled != null, "jdk.tls.disabledAlgorithms unset");
            for (String required : new String[] {"TLSv1.1", "SSLv3", "RC4", "DES",
                    "3DES_EDE_CBC", "MD5"}) {
                Expect.assertTrue(disabled.contains(required),
                        "jdk.tls.disabledAlgorithms missing " + required + ": " + disabled);
            }
        });

        ctx.add("certpath-disabled/md5-sha1-weak-keys", () -> {
            String disabled = Security.getProperty("jdk.certpath.disabledAlgorithms");
            Expect.assertTrue(disabled != null, "jdk.certpath.disabledAlgorithms unset");
            for (String required : new String[] {"MD2", "MD5", "SHA1"}) {
                Expect.assertTrue(disabled.contains(required),
                        "jdk.certpath.disabledAlgorithms missing " + required);
            }
        });

        ctx.addApproved("keystore/default-type-bcfks", () ->
                Expect.assertTrue("bcfks".equalsIgnoreCase(KeyStore.getDefaultType()),
                        "keystore.type is " + KeyStore.getDefaultType()));

        ctx.add("sasl/md5-mechanisms-disabled", () -> {
            String disabled = Security.getProperty("jdk.sasl.disabledMechanisms");
            Expect.assertTrue(disabled != null
                            && disabled.contains("DIGEST-MD5")
                            && disabled.contains("CRAM-MD5"),
                    "jdk.sasl.disabledMechanisms missing MD5 mechanisms: " + disabled);
        });

        ctx.add("approved-only/property-matches-mode", () -> {
            String property = Security.getProperty("org.bouncycastle.fips.approved_only");
            boolean expected = ctx.mode() == Mode.APPROVED;
            // The property may also arrive via -D; the registrar is checked in
            // preflight - here we assert the java.security layer agrees.
            if (property != null) {
                Expect.assertEquals(expected, Boolean.parseBoolean(property),
                        "org.bouncycastle.fips.approved_only");
            }
        });

        ctx.add("crypto-policy/unlimited", () ->
                Expect.assertEquals("unlimited", Security.getProperty("crypto.policy"),
                        "crypto.policy"));
    }
}
