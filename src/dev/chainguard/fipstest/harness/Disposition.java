package dev.chainguard.fipstest.harness;

/** Outcome of a single test case. */
public enum Disposition {
    /** Case ran and met its expectations (including expected failures that did fail). */
    PASS,
    /** Case ran and did not meet its expectations. */
    FAIL,
    /** Case could not run in this environment (missing algorithm/jar/file), by design. */
    SKIP,
    /** Harness-level problem (bad vectors, suite registration crash) - not a crypto result. */
    ERROR,
    /** Case is tagged known-fail and failed, as currently expected (tracked, not fatal). */
    XFAIL,
    /** Case is tagged known-fail but passed - the annotation is stale, treated as fatal. */
    XPASS
}
