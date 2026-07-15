package dev.chainguard.fipstest.harness;

/**
 * The provider operation mode the application is running under. Mirrors the
 * org.bouncycastle.fips.approved_only setting of the active java.security
 * configuration. The kernel-entropy configuration variant is still APPROVED
 * mode; it is detected separately via the securerandom.source property.
 */
public enum Mode {
    APPROVED,
    UNAPPROVED;

    public static Mode fromString(String s) {
        switch (s.toLowerCase()) {
            case "approved":
                return APPROVED;
            case "unapproved":
                return UNAPPROVED;
            default:
                throw new IllegalArgumentException("unknown mode: " + s);
        }
    }
}
