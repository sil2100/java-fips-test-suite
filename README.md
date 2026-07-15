# BC-FIPS comprehensive test application

A self-contained, zero-dependency Java test application that exercises the
Bouncy Castle Java FIPS provider stack (BCFIPS / BCJSSE / bcpkix) the way our
packaged consumers do. Its purpose is validating bc-fips version updates
(e.g. 2.1.1 -> 2.1.3) in our apk packaging: not just "is the algorithm there", but
known-answer tests, real operation round-trips, consumer-shaped scenarios
(TLS, keystores, token signing, SCRAM, envelope encryption) and expected
FAILURES (approved-mode rejections, tampered-data verification).

Java 11 source, plain javac build, no Maven, no JUnit. Runs on the whole
JDK 11/17/21/25 FIPS matrix, on the module path and the classpath.

## Quick start (local development)

```
scripts/fetch-jars.sh 2.1.1        # bc-fips family from Maven Central -> lib/
JAVA_HOME=/path/to/jdk ./run.sh    # full matrix
```

To A/B a provider update:

```
scripts/fetch-jars.sh 2.1.1 && ./run.sh   # baseline
scripts/fetch-jars.sh 2.1.3 && ./run.sh   # candidate
```

To validate packages built by a packaging PR (presubmit APK repository),
installed via apk into the jdk-fips image exactly as the PR intends
(needs docker + authenticated chainctl):

```
scripts/run-presubmit.sh <presubmit-repo-url> \
    bouncycastle-fips-preview
```

In the packaged FIPS runtime (jdk-fips/jre-fips images, melange test
environment) the defaults pick up `/usr/share/java/bouncycastle-fips` and
`/usr/lib/jvm/jdk-fips-config` automatically; just run `./run.sh`.

### run.sh environment knobs

| Variable | Default | Meaning |
|---|---|---|
| `JAVA_HOME` | javac on PATH | JDK to compile/run with |
| `BCFIPS_DIR` | `/usr/share/java/bouncycastle-fips`, else `./lib` | provider jars |
| `FIPS_CONFIG_DIR` | `/usr/lib/jvm/jdk-fips-config`, else `./conf` | security configs |
| `LAUNCH_MODE` | `both` | `module`, `classpath` or `both` |
| `RUN_MODES` | all | comma list of `approved,kernel-entropy,unapproved` |
| `APP_ARGS` | empty | extra app args, e.g. `--tags=tls --mct=full` |

The matrix: approved mode on the module path AND the classpath (Quarkus-style
consumers use the classpath), the kernel-entropy java.security variant, and
the unapproved variant where mode-conditional expectations invert (algorithms
that MUST be rejected in approved mode MUST work with approved-only off).
A JKS -> BCFKS `keytool -importkeystore` interop step runs after the matrix.

### Application CLI

```
java dev.chainguard.fipstest.Main [--mode=approved|unapproved]
     [--include=GLOB[,GLOB]] [--exclude=GLOB] [--tags=TAG[,TAG]]
     [--vectors=DIR] [--mct=reduced|full] [--list] [--fail-fast] [--verbose]
```

Output is one greppable line per case plus a summary:

```
RESULT|PASS|primitives.aead|aes-gcm/k256/t128/roundtrip|12ms|
RESULT|SKIP|primitives.pqc|ml-kem-768/keygen-if-available|0ms|not available...
FINAL|total=3476|pass=3427|fail=0|skip=49|xfail=0|xpass=0|error=0
```

Exit codes: `0` clean, `1` test failures, `2` harness/configuration error
(BC jars missing, mode mismatch, vectors dir missing). Dispositions:
`PASS`, `FAIL`, `SKIP` (capability-gated, e.g. PQC on bc-fips 2.1.x),
`ERROR` (harness problem), `XFAIL`/`XPASS` (cases tagged `known-fail`).

The disposition model follows ACVP: an operation that is EXPECTED to be
rejected and is not rejected is a FAILURE ("failure to fail is failure").

## Adding a test

1. Implement `dev.chainguard.fipstest.harness.TestSuite` (or extend an
   existing suite): generate named cases in `register()` via `ctx.add(...)`,
   `ctx.addApproved(...)`, `ctx.addUnapproved(...)`.
2. Add ONE line to `harness/Registry.java`. That is the whole registration -
   deliberately explicit and compile-checked.
3. Use `Expect.*` helpers for assertions and expected failures, and
   `Capabilities.require(...)` to SKIP cleanly where an algorithm/jar may be
   absent (keeps the app runnable against bc-fips 2.0/2.1/2.2).
4. Vector-driven cases: put `.rsp` files under `vectors/` (format documented
   in `vectors/README.md`, with provenance headers), load them with
   `ctx.vectors("dir/file.rsp")`.

## Suites

- `preflight` - FipsStatus, approved-mode wiring, provider order, DRBG config.
- `primitives.digest` - SHA-1/2/3 + SHAKE availability, CAVP short/long KATs,
  CAVP Monte Carlo (reduced 4 checkpoints, `--mct=full` all 100), negative
  availability (MD5/GOST/RIPEMD... from BCFIPS in approved mode; available in
  unapproved mode via the provider's general set).
- `primitives.mac` - HMAC family, Wycheproof HMAC/CMAC vectors, GMAC, KMAC
  (gated), truncated/wrong-tag negatives.
- `primitives.cipher` - AES mode x key x padding round-trip matrix, FIPS 197
  KAT, Triple-DES mode-conditional behavior.
- `primitives.aead` - AES-GCM parameter matrix, NIST + Wycheproof vectors
  (incl. wrong-tag decrypt rows), the full tamper set, AES-CCM, EAX/ChaCha20
  rejections.
- `primitives.keywrap` - AESKW/AESKWP (Wycheproof RFC 3394/5649 vectors),
  RSA-OAEP key transport, corrupt-blob negatives.
- `primitives.rsa` - keygen, PKCS#1v1.5 + PSS matrix with tamper negatives,
  Wycheproof verification vectors, key-usage separation (wrap-then-sign is
  refused - a real consumer pitfall), OAEP mode-conditional (key transport
  only in approved mode).
- `primitives.ecdsa` - P-256/384/521 x SHA-2 matrix, k-reuse smoke,
  Wycheproof DER-malleability vectors.
- `primitives.eddsa` - Ed25519/Ed448 (the 2.1.x headline addition; gated),
  determinism, Wycheproof vectors.
- `primitives.keyagreement` - ECDH curves, DH-2048, Wycheproof invalid-point
  vectors (rejection required, silent wrong secrets are the failure mode).
- `primitives.kdf` - PBKDF2 (incl. the approved-mode 14-char password
  boundary kafka hit), HKDF via FipsKDF (RFC 5869 + Wycheproof), SP 800-108
  KBKDF, TLS 1.2 PRF.
- `primitives.drbg` - FipsDRBG matrix, deterministic pinned outputs (see
  note below), SP 800-90A single-request cap, uniqueness/independence smoke.
- `primitives.pqc` - ML-KEM/ML-DSA probes; SKIP on 2.1.x, active on 2.2+.
- `scenarios.bcfks` - keystore lifecycle, rotation, integrity negatives,
  JKS interop (jmx-exporter/zookeeper/openjdk-fips patterns).
- `scenarios.certpath`/`scenarios.csr` - bcpkix chain building, PKIX
  validation with expiry/forgery/SHA-1 negatives, PKCS#10 + PEM round-trips.
- `scenarios.jws` - RS/PS/ES token signing incl. the JOSE DER<->raw pitfall,
  alg-confusion and length-manipulation negatives (keycloak pattern).
- `scenarios.envelope` - streaming AES-GCM + wrapped DEKs (KMS pattern).
- `scenarios.scram` - RFC 7677 exact vector (unapproved leg - the vector's
  6-char password is itself a FIPS violation, which IS the kafka finding),
  self-consistent exchange in approved mode.
- `scenarios.tls` - in-process BCJSSE client<->server: TLS 1.3/1.2, mTLS,
  HTTPS client, protocol/suite rejections, Ed25519-credential rejection.
- `scenarios.truststore` - cacerts.bcfks (packaged runtime; SKIPs locally).
- `negative.approved` - the consolidated rejection catalog with unapproved
  availability counterparts (drift in either direction is surfaced).
- `negative.tls-policy` - prohibited suite list, protocol floor.
- `negative.config` - java.security policy layer assertions.

## Provider behaviors pinned by this suite (bc-fips 2.1.1)

Documented findings the suite asserts; a change on update = investigate:

- RSA key-usage separation: a modulus used for encrypt/decrypt is permanently
  refused for sign/verify (and vice versa), in BOTH modes.
- RSA-OAEP `Cipher` is WRAP/UNWRAP-only in approved mode.
- GCM encryption requires IVs >= 12 bytes (approved); short-IV Wycheproof
  records are rejected by policy (logged, not failed).
- Sub-32-bit CCM tag sizes are accepted at the JCA layer (Wycheproof flags
  them policy-invalid; tolerated + logged).
- EC keygen for secp256k1/brainpool succeeds even in approved mode - curve
  policing happens at the certpath/TLS config layer, not keygen.
- The default PKIX CertPathValidator resolves to BCFIPS and does NOT consult
  `jdk.certpath.disabledAlgorithms` (SUN's does) - SHA-1 chains pass BC's
  validator in unapproved mode.
- The DRBG caps single generate requests at 262144 bits.
- DRBG KATs cannot be replayed through the public API: every EntropySource is
  wrapped by the module's continuous health test (by design). The module runs
  its own SP 800-90A KATs at power-on (checked via `FipsStatus.isReady()`);
  our `pinned/` DRBG cases record deterministic-entropy outputs from 2.1.1
  instead - a mismatch means seeding plumbing changed, review and re-pin.
- PBKDF2 approved mode: password >= 14 chars, salt >= 16 bytes.

Packaged JDK >= 25 stream (openjdk-fips-25/26 images; verified in
jdk-fips/jre-fips:latest with bc-fips 2.1.1-r5, JDK 26):

- The FIPS java.security is jlinked into the JDK; no /usr/lib/jvm/
  jdk-fips-config escape hatches exist (run.sh CONFIG_STYLE=baked: approved
  runs with NO overrides, unapproved uses conf/overlay-unapproved.java.security,
  kernel-entropy leg not applicable).
- The plain SUN provider is dropped entirely. Consequences the suite pins:
  - org.bouncycastle.jsse.enable_md5=true exposes MD5 from BCFIPS even in
    approved mode (FIPS 140-3 IG 2.4.A, non-security use).
  - org.bouncycastle.jca.enable_jks=true makes BCFIPS serve a READ-ONLY,
    certificate-only JKS - legacy truststores are readable, JKS creation is
    impossible (keytool JKS interop degrades to a documented skip).
  - The system truststore is a legacy-format cacerts read through that JKS
    compat (javax.net.ssl.trustStoreType=JKS), not a BCFKS file.
- SecureRandom.getInstanceStrong() = ENTROPY/BCRNG (bc-rng-jent userspace
  entropy), exercised for real in the images.

## Parity with the legacy harnesses

Everything asserted by the `bcfips-policy-140-3` package Test.java
and the jre-fips image's Java test suite maps to named cases:

| Legacy assertion | Case(s) here |
|---|---|
| FipsStatus.isReady | preflight/fips-status/ready |
| supported digests available | primitives.digest/\*/available |
| unsupported digests rejected | primitives.digest/\*/rejected-approved |
| MD5 via SUN default lookup | primitives.digest/MD5/default-lookup-follows-java-security |
| unsupported cipher modes rejected | negative.approved/cipher/\*/rejected |
| supported cipher modes available | primitives.cipher/aes/\* (full round-trips) |
| prohibited TLS suites | negative.tls-policy/suite/\* |
| default SSLContext = BCJSSE | preflight/providers/default-sslcontext-is-bcjsse |
| SecureRandom = ENTROPY/BCRNG or NativePRNGBlocking | preflight/random/strong-algorithm-matches-entropy-config |
| BCFIPS provider config string | preflight/providers/bcfips-config-string |
| RSA keygen uniqueness (125 keys) | primitives.drbg/statistical/rsa-keygen-uniqueness (10 reduced / 125 full) |
| strong instances differ | primitives.drbg/statistical/strong-instances-independent |
| unapproved config run must behave differently | entire unapproved leg with inverted expectations |
| DumpInfo | run.sh diagnostic step |
| AES all modes round-trip (jre-fips) | primitives.cipher + primitives.aead |
| AESKW/AESKWP/RSA-OAEP wrap, non-FIPS KW rejected (jre-fips) | primitives.keywrap/\* |
| FipsDRBG usage (jre-fips) | primitives.drbg/live/\* |
| truststore creation (jre-fips) | scenarios.bcfks + scenarios.truststore |

## Packaged usage (melange)

This repository is packaged as the `java-fips-test-suite` apk (in our
packaging repository, built via git-checkout of a
tagged release), which installs `src/`, `vectors/`, `conf/` and `run.sh` to
`/usr/lib/java-fips-test-suite/`. The `java-fips/comprehensive` melange test
pipeline copies that tree into a temp dir and runs `./run.sh` with the
JDK/distro selected by pipeline inputs - same contract as
`java-fips/algorithms`. Consumers add one `uses:` line; heavyweight consumers
filter, e.g. kafka: `app-args: --tags=tls,scram,keystore`.

run.sh auto-detects the environment: packaged escape-hatch configs
(JDK <= 21 policy packages), baked jlinked config (openjdk-fips >= 25), or
the local `conf/` replicas. Under a security manager (JDK <= 23, packaged)
it additionally applies `conf/pipeline-extra.policy` for the suite's own
permissions (vector reads, loopback TLS) on top of the base BC-FJA grants.

Release flow: tag `vX.Y.Z` here, bump the `
java-fips-test-suite` package (version + expected-commit; update.github
monitoring picks tags up automatically).

The pipeline requires a `bcfips-policy-140-3-j<N>` package, which exists for
JDK 11/17/21. The jlinked openjdk-fips >= 25 packages instead add the suite
directly in their test stanza (java-fips-test-suite in the environment,
run.sh with the FIPS JDK's JAVA_HOME - baked style needs no policy package).

## Repo layout

- `src/dev/chainguard/fipstest/` - harness, util, suites (see Adding a test)
- `vectors/` - curated CAVP/Wycheproof vectors (.rsp format, provenance headers)
- `scripts/convert_wycheproof.py`, `scripts/curate_cavp_sha.py` - offline
  vector maintenance tools (never run at test time)
- `scripts/fetch-jars.sh` - local-dev provider download
- `conf/` - local replicas of the bcfips-policy java.security configs + policy
- `run.sh` - the matrix driver
