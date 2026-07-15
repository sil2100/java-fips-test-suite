package dev.chainguard.fipstest.harness;

import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Iterates suites and cases, applies filters, catches Throwable per case
 * (FipsUnapprovedOperationError extends Error) and maps outcomes to
 * dispositions. One case's Error never kills the run.
 */
public final class Runner {

    private final TestContext ctx;
    private final Reporter reporter;
    private final List<Pattern> includes;
    private final List<Pattern> excludes;
    private final Set<String> tagFilter;
    private final boolean failFast;
    private final boolean listOnly;

    public Runner(TestContext ctx, Reporter reporter, List<Pattern> includes,
                  List<Pattern> excludes, Set<String> tagFilter, boolean failFast,
                  boolean listOnly) {
        this.ctx = ctx;
        this.reporter = reporter;
        this.includes = includes;
        this.excludes = excludes;
        this.tagFilter = tagFilter;
        this.failFast = failFast;
        this.listOnly = listOnly;
    }

    /** Compile a shell-style glob (* and ?) into a regex Pattern. */
    public static Pattern glob(String g) {
        StringBuilder sb = new StringBuilder();
        for (char c : g.toCharArray()) {
            switch (c) {
                case '*':
                    sb.append(".*");
                    break;
                case '?':
                    sb.append('.');
                    break;
                default:
                    sb.append(Pattern.quote(String.valueOf(c)));
            }
        }
        return Pattern.compile(sb.toString());
    }

    public void run(List<TestSuite> suites) {
        outer:
        for (TestSuite suite : suites) {
            List<TestCase> cases;
            try {
                suite.register(ctx);
                cases = ctx.drainCases();
            } catch (Throwable t) {
                ctx.drainCases();
                reporter.suiteError(suite.name(), t);
                continue;
            }
            for (TestCase tc : cases) {
                if (!selected(suite, tc)) {
                    continue;
                }
                if (listOnly) {
                    System.out.println(suite.name() + "/" + tc.name()
                            + (tc.tags().isEmpty() ? "" : " " + tc.tags()));
                    continue;
                }
                if (runCase(suite, tc) && failFast) {
                    break outer;
                }
            }
        }
    }

    private boolean selected(TestSuite suite, TestCase tc) {
        if (!tc.modes().contains(ctx.mode())) {
            return false;
        }
        String full = suite.name() + "/" + tc.name();
        if (!includes.isEmpty()
                && includes.stream().noneMatch(p -> p.matcher(full).matches())) {
            return false;
        }
        if (excludes.stream().anyMatch(p -> p.matcher(full).matches())) {
            return false;
        }
        if (!tagFilter.isEmpty()) {
            boolean tagged = tc.tags().stream().anyMatch(tagFilter::contains)
                    || suite.tags().stream().anyMatch(tagFilter::contains)
                    || tagFilter.contains(suite.name())
                    || tagFilter.contains(topLevel(suite.name()));
            if (!tagged) {
                return false;
            }
        }
        return true;
    }

    private static String topLevel(String suiteName) {
        int dot = suiteName.indexOf('.');
        return dot < 0 ? suiteName : suiteName.substring(0, dot);
    }

    /** Returns true when the case outcome is fatal (for --fail-fast). */
    private boolean runCase(TestSuite suite, TestCase tc) {
        long start = System.nanoTime();
        Disposition d;
        String detail = null;
        Throwable failure = null;
        try {
            tc.body().run();
            d = tc.knownFail() ? Disposition.XPASS : Disposition.PASS;
            if (d == Disposition.XPASS) {
                detail = "known-fail case passed - remove the stale known-fail tag";
            }
        } catch (SkipException e) {
            d = Disposition.SKIP;
            detail = e.getMessage();
        } catch (Throwable t) {
            d = tc.knownFail() ? Disposition.XFAIL : Disposition.FAIL;
            detail = t.getClass().getSimpleName() + ": " + t.getMessage();
            failure = t;
        }
        long millis = (System.nanoTime() - start) / 1_000_000;
        reporter.result(d, suite.name(), tc.name(), millis, detail, failure);
        return d == Disposition.FAIL || d == Disposition.XPASS || d == Disposition.ERROR;
    }
}
