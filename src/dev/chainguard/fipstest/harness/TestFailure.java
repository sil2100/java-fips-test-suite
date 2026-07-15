package dev.chainguard.fipstest.harness;

/** Thrown by assertion helpers when a test expectation is not met. */
public class TestFailure extends RuntimeException {
    public TestFailure(String message) {
        super(message);
    }

    public TestFailure(String message, Throwable cause) {
        super(message, cause);
    }
}
