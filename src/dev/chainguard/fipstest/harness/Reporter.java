package dev.chainguard.fipstest.harness;

import java.io.PrintStream;
import java.util.EnumMap;
import java.util.Map;

/**
 * Emits one machine-readable line per case plus a FINAL summary:
 *
 *   RESULT|PASS|primitives.aead|aes-gcm/k256/t128/roundtrip|12ms|
 *   RESULT|SKIP|primitives.pqc|ml-kem-768/probe|0ms|algorithm not available
 *   FINAL|total=142|pass=140|fail=0|skip=2|xfail=0|xpass=0|error=0
 *
 * Exit codes: 0 = clean, 1 = FAIL/XPASS present, 2 = harness/config error.
 */
public final class Reporter {

    private final PrintStream out;
    private final boolean verbose;
    private final Map<Disposition, Integer> counts = new EnumMap<>(Disposition.class);
    private int total;

    public Reporter(PrintStream out, boolean verbose) {
        this.out = out;
        this.verbose = verbose;
        for (Disposition d : Disposition.values()) {
            counts.put(d, 0);
        }
    }

    public void result(Disposition d, String suite, String caseName, long millis,
                       String detail, Throwable t) {
        total++;
        counts.merge(d, 1, Integer::sum);
        String note = detail == null ? "" : detail.replace('\n', ' ').replace('|', '/');
        out.println("RESULT|" + d + "|" + suite + "|" + caseName + "|" + millis + "ms|" + note);
        if (t != null && (verbose || d == Disposition.FAIL || d == Disposition.ERROR
                || d == Disposition.XPASS)) {
            t.printStackTrace(out);
        }
    }

    public void suiteError(String suite, Throwable t) {
        total++;
        counts.merge(Disposition.ERROR, 1, Integer::sum);
        out.println("RESULT|ERROR|" + suite + "|<registration>|0ms|" + t);
        t.printStackTrace(out);
    }

    public void info(String message) {
        out.println("INFO|" + message);
    }

    public void finish() {
        out.println("FINAL|total=" + total
                + "|pass=" + counts.get(Disposition.PASS)
                + "|fail=" + counts.get(Disposition.FAIL)
                + "|skip=" + counts.get(Disposition.SKIP)
                + "|xfail=" + counts.get(Disposition.XFAIL)
                + "|xpass=" + counts.get(Disposition.XPASS)
                + "|error=" + counts.get(Disposition.ERROR));
    }

    public int exitCode() {
        if (counts.get(Disposition.ERROR) > 0) {
            return 2;
        }
        if (counts.get(Disposition.FAIL) > 0 || counts.get(Disposition.XPASS) > 0) {
            return 1;
        }
        return 0;
    }

    public boolean hasFailures() {
        return exitCode() != 0;
    }

    public int totalCount() {
        return total;
    }
}
