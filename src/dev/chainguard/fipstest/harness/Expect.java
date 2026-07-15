package dev.chainguard.fipstest.harness;

import java.util.Arrays;

/**
 * Assertion helpers. The central idea (borrowed from ACVP/libacvp) is the
 * disposition model: an operation that is EXPECTED to be rejected passing
 * through unrejected is a test failure - "failure to fail is failure".
 *
 * All helpers accept bodies throwing Throwable because bc-fips signals
 * approved-mode violations with FipsUnapprovedOperationError, an Error.
 */
public final class Expect {

    private Expect() {
    }

    public static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new TestFailure(message);
        }
    }

    public static void assertEquals(Object expected, Object actual, String what) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new TestFailure(what + ": expected <" + expected + "> got <" + actual + ">");
        }
    }

    public static void assertArrayEquals(byte[] expected, byte[] actual, String what) {
        if (!Arrays.equals(expected, actual)) {
            throw new TestFailure(what + ": byte arrays differ (expected "
                    + summarize(expected) + ", got " + summarize(actual) + ")");
        }
    }

    /** The action must throw an instance of expected (or a subclass). */
    public static void mustThrow(Class<? extends Throwable> expected, String what, TestCase.Body action) {
        try {
            action.run();
        } catch (SkipException e) {
            throw e; // capability gate inside the body - propagate as SKIP
        } catch (Throwable t) {
            if (expected.isInstance(t)) {
                return;
            }
            throw new TestFailure(what + ": expected " + expected.getSimpleName()
                    + " but got " + t.getClass().getName() + ": " + t.getMessage(), t);
        }
        throw new TestFailure(what + ": expected " + expected.getSimpleName()
                + " but the operation succeeded (failure to fail)");
    }

    /**
     * The action must be rejected with some Throwable; used where the exact
     * rejection type varies across provider versions (getInstance vs init vs
     * doFinal, NoSuchAlgorithmException vs FipsUnapprovedOperationError).
     * The rejection is logged by the runner via the returned Throwable.
     */
    public static Throwable mustFail(String what, TestCase.Body action) {
        try {
            action.run();
        } catch (SkipException | TestFailure e) {
            // Harness signals are never a crypto rejection: a capability gate
            // firing inside the body must SKIP the case, and a nested
            // assertion failure must FAIL it - not satisfy the expectation.
            throw e;
        } catch (Throwable t) {
            // A sandbox permission problem is a broken test environment, not
            // a crypto rejection - never let it satisfy an expected failure.
            for (Throwable c = t; c != null; c = c.getCause()) {
                if (c instanceof java.security.AccessControlException) {
                    throw new TestFailure(what
                            + ": test environment permission problem", t);
                }
            }
            return t;
        }
        throw new TestFailure(what + ": expected the operation to be rejected"
                + " but it succeeded (failure to fail)");
    }

    /** The action must complete without throwing; wraps the Throwable as a failure. */
    public static void mustSucceed(String what, TestCase.Body action) {
        try {
            action.run();
        } catch (Throwable t) {
            throw new TestFailure(what + ": expected success but got "
                    + t.getClass().getName() + ": " + t.getMessage(), t);
        }
    }

    /** A verification operation (Signature.verify, MAC compare) must report false. */
    public static void mustBeFalse(boolean verifyResult, String what) {
        if (verifyResult) {
            throw new TestFailure(what + ": verification unexpectedly succeeded (failure to fail)");
        }
    }

    private static String summarize(byte[] b) {
        if (b == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(b.length * 2 + 16);
        sb.append(b.length).append(" bytes: ");
        for (int i = 0; i < Math.min(b.length, 16); i++) {
            sb.append(String.format("%02x", b[i]));
        }
        if (b.length > 16) {
            sb.append("...");
        }
        return sb.toString();
    }
}
