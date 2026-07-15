package dev.chainguard.fipstest.harness;

import dev.chainguard.fipstest.util.VectorFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Passed to TestSuite.register(): carries run configuration and collects the
 * registered cases for the suite currently being registered.
 */
public final class TestContext {

    /** How many iterations Monte Carlo style tests should run. */
    public enum MctDepth { REDUCED, FULL }

    private final Mode mode;
    private final Path vectorsDir;
    private final MctDepth mctDepth;
    private final List<TestCase> cases = new ArrayList<>();

    public TestContext(Mode mode, Path vectorsDir, MctDepth mctDepth) {
        this.mode = mode;
        this.vectorsDir = vectorsDir;
        this.mctDepth = mctDepth;
    }

    /** The mode of the current run; suites may consult it while building the matrix. */
    public Mode mode() {
        return mode;
    }

    public MctDepth mctDepth() {
        return mctDepth;
    }

    /** Register a case that runs in every mode. */
    public void add(String name, TestCase.Body body) {
        add(name, Set.of(), EnumSet.allOf(Mode.class), body);
    }

    /** Register a case restricted to the given modes. */
    public void add(String name, EnumSet<Mode> modes, TestCase.Body body) {
        add(name, Set.of(), modes, body);
    }

    public void add(String name, Set<String> tags, EnumSet<Mode> modes, TestCase.Body body) {
        cases.add(new TestCase(name, tags, modes, body));
    }

    /** Convenience: case only meaningful under approved-only mode. */
    public void addApproved(String name, TestCase.Body body) {
        add(name, Set.of(), EnumSet.of(Mode.APPROVED), body);
    }

    /** Convenience: case only meaningful with approved-only disabled. */
    public void addUnapproved(String name, TestCase.Body body) {
        add(name, Set.of(), EnumSet.of(Mode.UNAPPROVED), body);
    }

    /**
     * Load a vector file relative to the vectors directory. A missing or
     * malformed file throws, which the runner reports as a suite-level ERROR -
     * vectors must never go missing silently.
     */
    public VectorFile vectors(String relativePath) throws IOException {
        Path p = vectorsDir.resolve(relativePath);
        if (!Files.isRegularFile(p)) {
            throw new IOException("vector file not found: " + p);
        }
        return VectorFile.parse(p);
    }

    List<TestCase> drainCases() {
        List<TestCase> copy = new ArrayList<>(cases);
        cases.clear();
        return copy;
    }
}
