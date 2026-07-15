package dev.chainguard.fipstest.harness;

/** Thrown by a test case body to signal a capability-gated SKIP. */
public class SkipException extends RuntimeException {
    public SkipException(String reason) {
        super(reason);
    }
}
