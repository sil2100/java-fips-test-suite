package dev.chainguard.fipstest.suites.primitives;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.crypto.fips.FipsUnapprovedOperationError;

/**
 * Shared classifier for the Wycheproof drivers: which exceptions count as a
 * legitimate FIPS parameter-policy rejection of a cryptographically VALID
 * vector (e.g. approved mode refusing short GCM IVs, short PBKDF2 passwords,
 * undersized KW inputs). Anything else thrown on a valid record is a provider
 * failure and must FAIL the case - a blanket-tolerant driver would let a
 * provider that throws on a whole parameter corner pass the file.
 */
final class PolicyRejections {

    private PolicyRejections() {
    }

    static boolean isPolicyRejection(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c instanceof FipsUnapprovedOperationError
                    || c instanceof InvalidAlgorithmParameterException
                    || c instanceof InvalidKeySpecException
                    || c instanceof InvalidKeyException) {
                return true;
            }
        }
        return false;
    }

    /** Wraps counters shared between a vector file's cases and its floor case. */
    static final class Coverage {
        final int validTotal;
        int verified;
        int policyRejected;

        Coverage(int validTotal) {
            this.validTotal = validTotal;
        }

        void assertFloor(String label) {
            if (validTotal == 0) {
                return;
            }
            if (verified < 1) {
                throw new dev.chainguard.fipstest.harness.TestFailure(label
                        + ": no valid vector was actually verified (" + policyRejected
                        + "/" + validTotal + " policy-rejected) - coverage floor breached");
            }
            if (policyRejected >= validTotal) {
                throw new dev.chainguard.fipstest.harness.TestFailure(label
                        + ": every valid vector was policy-rejected - coverage floor breached");
            }
        }
    }
}
