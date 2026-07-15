package dev.chainguard.fipstest.suites.primitives;

import dev.chainguard.fipstest.harness.Expect;
import dev.chainguard.fipstest.harness.TestContext;
import dev.chainguard.fipstest.harness.TestSuite;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.List;
import java.util.Set;

/**
 * Block cipher (non-AEAD) coverage: AES mode x key size x padding round-trip
 * matrix (absorbs our FIPS image test suite symmetric coverage), provider identity
 * assertions, and Triple-DES mode-conditional behavior.
 */
public final class CipherSuite implements TestSuite {

    private static final int[] KEY_SIZES = {128, 192, 256};

    /** Modes that operate on whole blocks - tested with NoPadding on aligned data. */
    private static final List<String> UNPADDED_MODES = List.of("ECB", "CBC", "CFB8", "CFB128", "OFB", "CTR");

    /** Paddings exercised on the classic block modes. */
    private static final List<String> PADDINGS = List.of(
            "PKCS5Padding", "PKCS7Padding", "ISO10126-2Padding",
            "X9.23Padding", "ISO7816-4Padding", "TBCPadding");

    private static final SecureRandom RANDOM = new SecureRandom();

    @Override
    public String name() {
        return "primitives.cipher";
    }

    @Override
    public Set<String> tags() {
        return Set.of("primitives", "cipher", "aes");
    }

    @Override
    public void register(TestContext ctx) {
        for (int keySize : KEY_SIZES) {
            for (String mode : UNPADDED_MODES) {
                String transformation = "AES/" + mode + "/NoPadding";
                ctx.add("aes/k" + keySize + "/" + mode + "/NoPadding/roundtrip", () ->
                        roundTrip(transformation, keySize, 64));
            }
            for (String padding : PADDINGS) {
                for (String mode : List.of("ECB", "CBC")) {
                    String transformation = "AES/" + mode + "/" + padding;
                    ctx.add("aes/k" + keySize + "/" + mode + "/" + padding + "/roundtrip", () ->
                            roundTrip(transformation, keySize, 37)); // deliberately unaligned
                }
            }
        }

        // Decrypting tampered CBC ciphertext with PKCS5 padding is not
        // guaranteed to throw (padding may accidentally validate) - that is
        // exactly why unauthenticated modes get no bit-flip tests in ACVP.
        // What we CAN assert: a wrong key never yields the plaintext back.
        ctx.add("aes/wrong-key-never-decrypts-to-plaintext", () -> {
            SecretKey key = generateAesKey(256);
            SecretKey wrongKey = generateAesKey(256);
            byte[] iv = new byte[16];
            RANDOM.nextBytes(iv);
            byte[] plaintext = new byte[64];
            RANDOM.nextBytes(plaintext);

            Cipher enc = Cipher.getInstance("AES/CBC/NoPadding", "BCFIPS");
            enc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] ciphertext = enc.doFinal(plaintext);

            Cipher dec = Cipher.getInstance("AES/CBC/NoPadding", "BCFIPS");
            dec.init(Cipher.DECRYPT_MODE, wrongKey, new IvParameterSpec(iv));
            byte[] decrypted = dec.doFinal(ciphertext);
            Expect.assertTrue(!java.util.Arrays.equals(plaintext, decrypted),
                    "wrong key produced the original plaintext");
        });

        // SP 800-38A appendix F known answers (AES-256, four blocks) for the
        // feedback/counter modes - round-trips alone are self-canceling and
        // would miss a wrong-answer regression in the mode wiring.
        registerSp800_38aKats(ctx);

        // AES known answer inline: FIPS 197 appendix C.3 (AES-256, ECB, single block).
        ctx.add("aes/k256/ECB/fips197-kat", () -> {
            byte[] key = dev.chainguard.fipstest.util.Hex.decode(
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            byte[] pt = dev.chainguard.fipstest.util.Hex.decode("00112233445566778899aabbccddeeff");
            byte[] expected = dev.chainguard.fipstest.util.Hex.decode("8ea2b7ca516745bfeafc49904b496089");
            Cipher c = Cipher.getInstance("AES/ECB/NoPadding", "BCFIPS");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
            Expect.assertArrayEquals(expected, c.doFinal(pt), "AES-256 FIPS 197 KAT");
        });

        // Triple-DES: transformation stays resolvable (Test.java asserts this),
        // but under FIPS 140-3 approved mode ENCRYPTION with it must be
        // rejected at runtime; with approved-only off it still round-trips.
        ctx.addApproved("desede/encrypt-rejected-approved", () -> {
            Throwable rejection = Expect.mustFail("DESede encryption in approved mode", () -> {
                Cipher c = Cipher.getInstance("DESede/ECB/NoPadding", "BCFIPS");
                SecretKey key = generateDesEdeKey();
                c.init(Cipher.ENCRYPT_MODE, key);
                c.doFinal(new byte[24]);
            });
            System.out.println("INFO|DESede encrypt rejection: " + rejection);
        });

        ctx.addUnapproved("desede/roundtrip-unapproved", () -> {
            Cipher enc = Cipher.getInstance("DESede/ECB/NoPadding", "BCFIPS");
            SecretKey key = generateDesEdeKey();
            byte[] plaintext = new byte[24];
            RANDOM.nextBytes(plaintext);
            enc.init(Cipher.ENCRYPT_MODE, key);
            byte[] ciphertext = enc.doFinal(plaintext);
            Cipher dec = Cipher.getInstance("DESede/ECB/NoPadding", "BCFIPS");
            dec.init(Cipher.DECRYPT_MODE, key);
            Expect.assertArrayEquals(plaintext, dec.doFinal(ciphertext), "DESede round-trip");
        });
    }

    /** SP 800-38A appendix F: AES-256 key, standard IV, four plaintext blocks. */
    private static final String SP800_38A_KEY =
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    private static final String SP800_38A_IV = "000102030405060708090a0b0c0d0e0f";
    private static final String SP800_38A_CTR_IV = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    private static final String SP800_38A_PT =
            "6bc1bee22e409f96e93d7e117393172a" + "ae2d8a571e03ac9c9eb76fac45af8e51"
                    + "30c81c46a35ce411e5fbc1191a0a52ef" + "f69f2445df4f9b17ad2b417be66c3710";

    private void registerSp800_38aKats(TestContext ctx) {
        // (transformation, iv, expected ciphertext) - F.2.6, F.3.16, F.4.6, F.5.6
        String[][] kats = {
                {"AES/CBC/NoPadding", SP800_38A_IV,
                        "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
                                + "9cfc4e967edb808d679f777bc6702c7d"
                                + "39f23369a9d9bacfa530e26304231461"
                                + "b2eb05e2c39be9fcda6c19078c6a9d1b"},
                {"AES/CFB128/NoPadding", SP800_38A_IV,
                        "dc7e84bfda79164b7ecd8486985d3860"
                                + "39ffed143b28b1c832113c6331e5407b"
                                + "df10132415e54b92a13ed0a8267ae2f9"
                                + "75a385741ab9cef82031623d55b1e471"},
                {"AES/OFB/NoPadding", SP800_38A_IV,
                        "dc7e84bfda79164b7ecd8486985d3860"
                                + "4febdc6740d20b3ac88f6ad82a4fb08d"
                                + "71ab47a086e86eedf39d1c5bba97c408"
                                + "0126141d67f37be8538f5a8be740e484"},
                {"AES/CTR/NoPadding", SP800_38A_CTR_IV,
                        "601ec313775789a5b7a7f504bbf3d228"
                                + "f443e3ca4d62b59aca84e990cacaf5c5"
                                + "2b0930daa23de94ce87017ba2d84988d"
                                + "dfc9c58db67aada613c2dd08457941a6"}};
        for (String[] kat : kats) {
            String transformation = kat[0];
            String iv = kat[1];
            String expected = kat[2];
            String mode = transformation.split("/")[1].toLowerCase();
            ctx.add("aes/k256/" + mode + "/sp800-38a-kat", () -> {
                Cipher enc = Cipher.getInstance(transformation, "BCFIPS");
                enc.init(Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(dev.chainguard.fipstest.util.Hex.decode(
                                SP800_38A_KEY), "AES"),
                        new IvParameterSpec(dev.chainguard.fipstest.util.Hex.decode(iv)));
                Expect.assertArrayEquals(
                        dev.chainguard.fipstest.util.Hex.decode(expected),
                        enc.doFinal(dev.chainguard.fipstest.util.Hex.decode(SP800_38A_PT)),
                        transformation + " SP 800-38A encrypt KAT");

                Cipher dec = Cipher.getInstance(transformation, "BCFIPS");
                dec.init(Cipher.DECRYPT_MODE,
                        new SecretKeySpec(dev.chainguard.fipstest.util.Hex.decode(
                                SP800_38A_KEY), "AES"),
                        new IvParameterSpec(dev.chainguard.fipstest.util.Hex.decode(iv)));
                Expect.assertArrayEquals(
                        dev.chainguard.fipstest.util.Hex.decode(SP800_38A_PT),
                        dec.doFinal(dev.chainguard.fipstest.util.Hex.decode(expected)),
                        transformation + " SP 800-38A decrypt KAT");
            });
        }
    }

    private static void roundTrip(String transformation, int keySize, int plaintextLen)
            throws Exception {
        SecretKey key = generateAesKey(keySize);
        Cipher enc = Cipher.getInstance(transformation, "BCFIPS");
        Expect.assertEquals("BCFIPS", enc.getProvider().getName(), "cipher provider");

        byte[] plaintext = new byte[plaintextLen];
        RANDOM.nextBytes(plaintext);

        Cipher dec = Cipher.getInstance(transformation, "BCFIPS");
        if (transformation.contains("/ECB/")) {
            enc.init(Cipher.ENCRYPT_MODE, key);
            byte[] ciphertext = enc.doFinal(plaintext);
            dec.init(Cipher.DECRYPT_MODE, key);
            Expect.assertArrayEquals(plaintext, dec.doFinal(ciphertext),
                    transformation + " round-trip");
        } else {
            byte[] iv = new byte[16];
            RANDOM.nextBytes(iv);
            enc.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] ciphertext = enc.doFinal(plaintext);
            dec.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            Expect.assertArrayEquals(plaintext, dec.doFinal(ciphertext),
                    transformation + " round-trip");
        }
    }

    private static SecretKey generateAesKey(int bits) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES", "BCFIPS");
        kg.init(bits);
        return kg.generateKey();
    }

    private static SecretKey generateDesEdeKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("DESede", "BCFIPS");
        kg.init(168);
        return kg.generateKey();
    }
}
