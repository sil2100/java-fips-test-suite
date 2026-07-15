package dev.chainguard.fipstest.harness;

import dev.chainguard.fipstest.suites.PreflightSuite;
import dev.chainguard.fipstest.suites.negative.ApprovedModeSuite;
import dev.chainguard.fipstest.suites.primitives.AeadSuite;
import dev.chainguard.fipstest.suites.primitives.CipherSuite;
import dev.chainguard.fipstest.suites.primitives.DigestSuite;
import dev.chainguard.fipstest.suites.primitives.DrbgSuite;
import dev.chainguard.fipstest.suites.primitives.EcdsaSuite;
import dev.chainguard.fipstest.suites.primitives.EdDsaSuite;
import dev.chainguard.fipstest.suites.primitives.KdfSuite;
import dev.chainguard.fipstest.suites.primitives.KeyAgreementSuite;
import dev.chainguard.fipstest.suites.primitives.KeyWrapSuite;
import dev.chainguard.fipstest.suites.primitives.MacSuite;
import dev.chainguard.fipstest.suites.primitives.PqcSuite;
import dev.chainguard.fipstest.suites.primitives.RsaSuite;
import dev.chainguard.fipstest.suites.scenarios.BcfksSuite;
import dev.chainguard.fipstest.suites.scenarios.CertPathSuite;
import dev.chainguard.fipstest.suites.scenarios.CsrSuite;
import dev.chainguard.fipstest.suites.scenarios.EnvelopeSuite;
import dev.chainguard.fipstest.suites.negative.ConfigPolicySuite;
import dev.chainguard.fipstest.suites.negative.TlsPolicySuite;
import dev.chainguard.fipstest.suites.scenarios.JwsSuite;
import dev.chainguard.fipstest.suites.scenarios.ScramSuite;
import dev.chainguard.fipstest.suites.scenarios.TlsSuite;
import dev.chainguard.fipstest.suites.scenarios.TrustStoreSuite;

import java.util.List;

/**
 * The single place suites are registered. Deliberately an explicit,
 * compile-checked list (not ServiceLoader, not classpath scanning): a
 * forgotten registration is visible here and in --list output, and the
 * mechanism behaves identically on the classpath and the module path.
 *
 * Adding a test suite = add the class + one line here.
 */
public final class Registry {

    private Registry() {
    }

    public static List<TestSuite> allSuites() {
        return List.of(
                new PreflightSuite(),
                new DigestSuite(),
                new MacSuite(),
                new CipherSuite(),
                new AeadSuite(),
                new KeyWrapSuite(),
                new RsaSuite(),
                new EcdsaSuite(),
                new EdDsaSuite(),
                new KeyAgreementSuite(),
                new KdfSuite(),
                new DrbgSuite(),
                new PqcSuite(),
                new BcfksSuite(),
                new CertPathSuite(),
                new CsrSuite(),
                new JwsSuite(),
                new EnvelopeSuite(),
                new ScramSuite(),
                new TlsSuite(),
                new TrustStoreSuite(),
                new ApprovedModeSuite(),
                new TlsPolicySuite(),
                new ConfigPolicySuite());
    }
}
