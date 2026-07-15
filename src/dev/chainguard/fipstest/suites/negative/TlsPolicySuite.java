package dev.chainguard.fipstest.suites.negative;

import dev.chainguard.fipstest.harness.Capabilities;
import dev.chainguard.fipstest.harness.Expect;
import dev.chainguard.fipstest.harness.TestContext;
import dev.chainguard.fipstest.harness.TestSuite;

import javax.net.ssl.SSLContext;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * TLS policy assertions ported from bcfips-policy Test.java: the cipher
 * suites a FIPS TLS stack must not offer (ChaCha20-Poly1305, CCM-8-less
 * PSK families, CBC-PSK) and the protocol floor. Checked against the ENABLED
 * (default) parameter set of the BCJSSE context.
 */
public final class TlsPolicySuite implements TestSuite {

    /** Port of UNSUPPORTED_TLS_CIPHERS from bcfips-policy Test.java. */
    private static final List<String> PROHIBITED_SUITES = List.of(
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_CCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
            "TLS_DHE_RSA_WITH_AES_256_CCM",
            "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
            "TLS_DHE_RSA_WITH_AES_128_CCM",
            "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
            "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
            "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
            "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_PSK_WITH_AES_128_CBC_SHA",
            "TLS_PSK_WITH_AES_128_CBC_SHA256",
            "TLS_PSK_WITH_AES_128_CCM",
            "TLS_PSK_WITH_AES_128_GCM_SHA256",
            "TLS_PSK_WITH_AES_256_CBC_SHA",
            "TLS_PSK_WITH_AES_256_CCM",
            "TLS_PSK_WITH_AES_256_GCM_SHA384",
            "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
            "TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
            "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
            "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
            "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256");

    @Override
    public String name() {
        return "negative.tls-policy";
    }

    @Override
    public Set<String> tags() {
        return Set.of("negative", "tls");
    }

    @Override
    public void register(TestContext ctx) {
        for (String suite : PROHIBITED_SUITES) {
            ctx.add("suite/" + suite + "/not-enabled", () -> {
                Capabilities.requireProvider("BCJSSE");
                SSLContext context = defaultBcjsseContext();
                Set<String> enabled = Set.of(
                        context.getDefaultSSLParameters().getCipherSuites());
                Expect.assertTrue(!enabled.contains(suite),
                        suite + " present in default cipher suites");
            });
        }

        ctx.add("protocols/tls11-and-older-not-enabled", () -> {
            Capabilities.requireProvider("BCJSSE");
            SSLContext context = defaultBcjsseContext();
            List<String> protocols = Arrays.asList(
                    context.getDefaultSSLParameters().getProtocols());
            for (String legacy : List.of("SSLv3", "TLSv1", "TLSv1.1")) {
                Expect.assertTrue(!protocols.contains(legacy),
                        legacy + " enabled by default: " + protocols);
            }
            Expect.assertTrue(protocols.contains("TLSv1.2")
                            || protocols.contains("TLSv1.3"),
                    "no modern TLS protocol enabled: " + protocols);
        });

        // Pin the supported (not just enabled) view so a provider update that
        // starts advertising a prohibited family is noticed even if disabled.
        ctx.add("suite/chacha20-family-not-supported", () -> {
            Capabilities.requireProvider("BCJSSE");
            SSLContext context = defaultBcjsseContext();
            for (String supported
                    : context.getSupportedSSLParameters().getCipherSuites()) {
                Expect.assertTrue(!supported.contains("CHACHA20"),
                        "CHACHA20 suite advertised as supported: " + supported);
            }
        });
    }

    private static SSLContext defaultBcjsseContext() throws Exception {
        SSLContext context = SSLContext.getInstance("TLS");
        Expect.assertEquals("BCJSSE", context.getProvider().getName(),
                "default SSLContext provider");
        context.init(null, null, null);
        return context;
    }
}
