package dev.chainguard.fipstest;

import dev.chainguard.fipstest.harness.Mode;
import dev.chainguard.fipstest.harness.Registry;
import dev.chainguard.fipstest.harness.Reporter;
import dev.chainguard.fipstest.harness.Runner;
import dev.chainguard.fipstest.harness.TestContext;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Comprehensive BC-FIPS provider test application.
 *
 * Usage:
 *   java dev.chainguard.fipstest.Main [--mode=approved|unapproved]
 *        [--include=GLOB[,GLOB]] [--exclude=GLOB[,GLOB]] [--tags=TAG[,TAG]]
 *        [--vectors=DIR] [--mct=reduced|full] [--list] [--fail-fast] [--verbose]
 *
 * Exit codes: 0 clean, 1 test failures, 2 harness/config error.
 */
public final class Main {

    private Main() {
    }

    public static void main(String[] args) {
        Mode mode = Mode.APPROVED;
        List<Pattern> includes = new ArrayList<>();
        List<Pattern> excludes = new ArrayList<>();
        Set<String> tags = new LinkedHashSet<>();
        Path vectorsDir = Paths.get("vectors");
        TestContext.MctDepth mct = TestContext.MctDepth.REDUCED;
        boolean list = false;
        boolean failFast = false;
        boolean verbose = false;

        for (String arg : args) {
            if (arg.startsWith("--mode=")) {
                mode = Mode.fromString(arg.substring(7));
            } else if (arg.startsWith("--include=")) {
                for (String g : arg.substring(10).split(",")) {
                    includes.add(Runner.glob(g));
                }
            } else if (arg.startsWith("--exclude=")) {
                for (String g : arg.substring(10).split(",")) {
                    excludes.add(Runner.glob(g));
                }
            } else if (arg.startsWith("--tags=")) {
                for (String t : arg.substring(7).split(",")) {
                    tags.add(t.trim());
                }
            } else if (arg.startsWith("--vectors=")) {
                vectorsDir = Paths.get(arg.substring(10));
            } else if (arg.startsWith("--mct=")) {
                mct = "full".equalsIgnoreCase(arg.substring(6))
                        ? TestContext.MctDepth.FULL : TestContext.MctDepth.REDUCED;
            } else if (arg.equals("--list")) {
                list = true;
            } else if (arg.equals("--fail-fast")) {
                failFast = true;
            } else if (arg.equals("--verbose")) {
                verbose = true;
            } else {
                System.err.println("unknown argument: " + arg);
                System.exit(2);
            }
        }

        Reporter reporter = new Reporter(System.out, verbose);

        if (!list && !preflight(mode, vectorsDir, reporter)) {
            System.exit(2);
        }

        TestContext ctx = new TestContext(mode, vectorsDir, mct);
        Runner runner = new Runner(ctx, reporter, includes, excludes, tags, failFast, list);
        runner.run(Registry.allSuites());

        if (list) {
            return;
        }
        reporter.finish();
        if (reporter.totalCount() == 0) {
            // Filters that match nothing must never look like success.
            System.err.println("CONFIG ERROR: no test cases were selected"
                    + " (check --include/--exclude/--tags)");
            System.exit(2);
        }
        System.exit(reporter.exitCode());
    }

    /**
     * Hard environment gate, run before any suite: a broken setup must be a
     * clear exit 2, not a cascade of confusing test failures.
     */
    private static boolean preflight(Mode mode, Path vectorsDir, Reporter reporter) {
        Provider bcfips = Security.getProvider("BCFIPS");
        if (bcfips == null) {
            System.err.println("CONFIG ERROR: BCFIPS provider is not installed. "
                    + "Check --module-path/-cp for bc-fips.jar and the active "
                    + "java.security configuration (security.provider.1).");
            return false;
        }
        reporter.info("BCFIPS provider version: " + bcfips.getVersionStr());

        boolean ready;
        try {
            ready = org.bouncycastle.crypto.fips.FipsStatus.isReady();
        } catch (Throwable t) {
            System.err.println("CONFIG ERROR: FipsStatus.isReady() check failed: " + t);
            return false;
        }
        if (!ready) {
            System.err.println("CONFIG ERROR: FipsStatus.isReady() returned false "
                    + "- module self-tests did not complete.");
            return false;
        }

        boolean approvedOnly =
                org.bouncycastle.crypto.CryptoServicesRegistrar.isInApprovedOnlyMode();
        if (approvedOnly != (mode == Mode.APPROVED)) {
            System.err.println("CONFIG ERROR: --mode=" + mode
                    + " but CryptoServicesRegistrar.isInApprovedOnlyMode()=" + approvedOnly
                    + ". The java.security configuration does not match the requested mode.");
            return false;
        }

        if (!Files.isDirectory(vectorsDir)) {
            System.err.println("CONFIG ERROR: vectors directory not found: "
                    + vectorsDir.toAbsolutePath()
                    + " (pass --vectors=DIR)");
            return false;
        }

        reporter.info("mode=" + mode + " approvedOnly=" + approvedOnly
                + " vectors=" + vectorsDir.toAbsolutePath());
        return true;
    }
}
