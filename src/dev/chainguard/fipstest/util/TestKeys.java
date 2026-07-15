package dev.chainguard.fipstest.util;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Cached test key pairs. Key generation is the slowest primitive; suites that
 * need "a key" (not "key generation coverage") share these. Dedicated keygen
 * test cases generate their own.
 */
public final class TestKeys {

    private static final Map<String, KeyPair> CACHE = new ConcurrentHashMap<>();

    private TestKeys() {
    }

    /**
     * RSA keys are cached PER PURPOSE: bc-fips enforces SP 800-56B key-usage
     * separation - a modulus that has been used for encrypt/decrypt (OAEP
     * wrap) is permanently refused for sign/verify and vice versa. A single
     * shared key would poison unrelated suites.
     */
    public static KeyPair rsaSign(int bits) {
        return rsa("sign", bits);
    }

    public static KeyPair rsaWrap(int bits) {
        return rsa("wrap", bits);
    }

    private static KeyPair rsa(String purpose, int bits) {
        return CACHE.computeIfAbsent("RSA-" + purpose + "-" + bits, k -> {
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BCFIPS");
                kpg.initialize(bits);
                return kpg.generateKeyPair();
            } catch (Exception e) {
                throw new IllegalStateException("RSA-" + bits + " test key generation failed", e);
            }
        });
    }

    public static KeyPair ec(String curve) {
        return CACHE.computeIfAbsent("EC-" + curve, k -> {
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BCFIPS");
                kpg.initialize(new ECGenParameterSpec(curve));
                return kpg.generateKeyPair();
            } catch (Exception e) {
                throw new IllegalStateException("EC " + curve + " test key generation failed", e);
            }
        });
    }

    public static KeyPair eddsa(String algorithm) {
        return CACHE.computeIfAbsent(algorithm, k -> {
            try {
                return KeyPairGenerator.getInstance(algorithm, "BCFIPS").generateKeyPair();
            } catch (Exception e) {
                throw new IllegalStateException(algorithm + " test key generation failed", e);
            }
        });
    }
}
