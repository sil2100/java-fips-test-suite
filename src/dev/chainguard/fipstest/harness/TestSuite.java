package dev.chainguard.fipstest.harness;

import java.util.Collections;
import java.util.Set;

/**
 * A group of related test cases. Implementations generate their case matrix
 * in register() by calling ctx.add(...) - one call per parameterized case.
 *
 * To add a new suite: implement this interface and add one line to
 * Registry.allSuites().
 */
public interface TestSuite {

    /** Hierarchical name, e.g. "primitives.aead" or "scenarios.tls". */
    String name();

    /** Tags applied to every case of this suite, in addition to per-case tags. */
    default Set<String> tags() {
        return Collections.emptySet();
    }

    /** Generate and register the case matrix. Must not perform crypto itself. */
    void register(TestContext ctx) throws Exception;
}
