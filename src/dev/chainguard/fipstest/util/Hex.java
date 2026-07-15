package dev.chainguard.fipstest.util;

/** Minimal hex codec - no dependencies, usable from any suite. */
public final class Hex {

    private static final char[] DIGITS = "0123456789abcdef".toCharArray();

    private Hex() {
    }

    public static String encode(byte[] data) {
        char[] out = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            out[i * 2] = DIGITS[(data[i] >> 4) & 0xf];
            out[i * 2 + 1] = DIGITS[data[i] & 0xf];
        }
        return new String(out);
    }

    public static byte[] decode(String hex) {
        String s = hex.trim();
        if (s.length() % 2 != 0) {
            throw new IllegalArgumentException("odd-length hex string: " + s.length());
        }
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(s.charAt(i * 2), 16);
            int lo = Character.digit(s.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("invalid hex at offset " + (i * 2));
            }
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }
}
