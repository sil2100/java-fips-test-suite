package dev.chainguard.fipstest.harness;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Availability probing used for capability-gated SKIPs, so the same app runs
 * unchanged against bc-fips 2.0/2.1/2.2 (EdDSA, PQC, KMAC...) and in
 * environments missing optional jars (bctls, bcpkix, bc-rng-jent).
 *
 * Probing instantiates the JCA service - getService()-based lookups miss
 * Cipher transformation strings, so we pay the small instantiation cost.
 */
public final class Capabilities {

    private static final Map<String, Boolean> CACHE = new ConcurrentHashMap<>();

    private Capabilities() {
    }

    public static boolean hasProvider(String provider) {
        return Security.getProvider(provider) != null;
    }

    /**
     * type is a JCA engine class name: MessageDigest, Cipher, Mac, Signature,
     * KeyPairGenerator, KeyGenerator, SecretKeyFactory, KeyFactory,
     * KeyAgreement, KeyStore, SecureRandom, AlgorithmParameters,
     * CertificateFactory, TrustManagerFactory, KeyManagerFactory, SSLContext.
     */
    public static boolean has(String type, String algorithm, String provider) {
        return CACHE.computeIfAbsent(type + "|" + algorithm + "|" + provider,
                k -> probe(type, algorithm, provider));
    }

    public static void require(String type, String algorithm, String provider) {
        if (!hasProvider(provider)) {
            throw new SkipException("provider " + provider + " not installed");
        }
        if (!has(type, algorithm, provider)) {
            throw new SkipException(type + " " + algorithm + " not available from " + provider);
        }
    }

    public static void requireProvider(String provider) {
        if (!hasProvider(provider)) {
            throw new SkipException("provider " + provider + " not installed");
        }
    }

    /**
     * SKIP when the provider is simply not part of this environment, but
     * FAIL when the active java.security DECLARES it and it failed to load -
     * a declared-but-missing provider is a broken FIPS stack, and degrading
     * that to SKIP would mask it.
     */
    public static void requireProviderConsistentWithConfig(String provider,
                                                           String classNameFragment) {
        if (hasProvider(provider)) {
            return;
        }
        for (int i = 1; i <= 20; i++) {
            String declared = Security.getProperty("security.provider." + i);
            if (declared != null && declared.contains(classNameFragment)) {
                throw new TestFailure("provider " + provider
                        + " is declared in java.security (security.provider." + i
                        + ") but is not installed - broken provider stack");
            }
        }
        throw new SkipException("provider " + provider
                + " not configured in this environment");
    }

    /** Gate on a class being present (e.g. bcpkix/bctls classes on the classpath). */
    public static void requireClass(String className) {
        try {
            Class.forName(className);
        } catch (ClassNotFoundException | NoClassDefFoundError e) {
            throw new SkipException("class not available: " + className);
        }
    }

    private static boolean probe(String type, String algorithm, String provider) {
        try {
            switch (type) {
                case "MessageDigest":
                    java.security.MessageDigest.getInstance(algorithm, provider);
                    return true;
                case "Cipher":
                    javax.crypto.Cipher.getInstance(algorithm, provider);
                    return true;
                case "Mac":
                    javax.crypto.Mac.getInstance(algorithm, provider);
                    return true;
                case "Signature":
                    java.security.Signature.getInstance(algorithm, provider);
                    return true;
                case "KeyPairGenerator":
                    java.security.KeyPairGenerator.getInstance(algorithm, provider);
                    return true;
                case "KeyGenerator":
                    javax.crypto.KeyGenerator.getInstance(algorithm, provider);
                    return true;
                case "SecretKeyFactory":
                    javax.crypto.SecretKeyFactory.getInstance(algorithm, provider);
                    return true;
                case "KeyFactory":
                    java.security.KeyFactory.getInstance(algorithm, provider);
                    return true;
                case "KeyAgreement":
                    javax.crypto.KeyAgreement.getInstance(algorithm, provider);
                    return true;
                case "KeyStore":
                    java.security.KeyStore.getInstance(algorithm, provider);
                    return true;
                case "SecureRandom":
                    java.security.SecureRandom.getInstance(algorithm, provider);
                    return true;
                case "SSLContext":
                    javax.net.ssl.SSLContext.getInstance(algorithm, provider);
                    return true;
                default:
                    throw new IllegalArgumentException("unknown JCA type: " + type);
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException
                | javax.crypto.NoSuchPaddingException | java.security.KeyStoreException e) {
            return false;
        }
    }
}
