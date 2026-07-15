package dev.chainguard.fipstest.harness;

import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.Set;

/** A single named, tagged test case with the modes it applies to. */
public final class TestCase {

    /** Test body; may throw anything, including Error (FipsUnapprovedOperationError). */
    @FunctionalInterface
    public interface Body {
        void run() throws Throwable;
    }

    private final String name;
    private final Set<String> tags;
    private final EnumSet<Mode> modes;
    private final Body body;

    public TestCase(String name, Set<String> tags, EnumSet<Mode> modes, Body body) {
        this.name = name;
        this.tags = Collections.unmodifiableSet(new LinkedHashSet<>(tags));
        this.modes = modes;
        this.body = body;
    }

    public String name() {
        return name;
    }

    public Set<String> tags() {
        return tags;
    }

    /** Modes in which this case is meaningful; the runner silently filters others. */
    public EnumSet<Mode> modes() {
        return modes;
    }

    public Body body() {
        return body;
    }

    public boolean knownFail() {
        return tags.contains("known-fail");
    }
}
