#!/usr/bin/env bash
# Compile and run the BC-FIPS test application across the full run matrix:
# approved (module-path and classpath), kernel-entropy, unapproved.
#
# Environment knobs:
#   JAVA_HOME        JDK to use (required unless a JDK java is on PATH)
#   BCFIPS_DIR       dir with bc-fips jars
#                    (default: /usr/share/java/bouncycastle-fips, else ./lib)
#   FIPS_CONFIG_DIR  packaged escape-hatch configs
#                    (default: /usr/lib/jvm/jdk-fips-config; ./conf locally)
#   LAUNCH_MODE      module|classpath|both   (default: both)
#   RUN_MODES        comma list from: approved,kernel-entropy,unapproved
#                    (default: all)
#   APP_ARGS         extra args passed to the app (e.g. --tags=aead --mct=full)
#
# Exit code: non-zero if any leg of the matrix fails.

set -o errexit -o nounset -o pipefail

cd "$(dirname "$0")"

JAVA_HOME="${JAVA_HOME:-}"
if [[ -z "$JAVA_HOME" ]]; then
    if command -v javac >/dev/null 2>&1; then
        JAVA_HOME="$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")"
    else
        echo "ERROR: JAVA_HOME not set and no javac on PATH" >&2
        exit 2
    fi
fi

JAVAC="$JAVA_HOME/bin/javac"
JAVA="$JAVA_HOME/bin/java"
[[ -x "$JAVAC" ]] || { echo "ERROR: $JAVAC not found (JRE-only install?)" >&2; exit 2; }

JAVA_MAJOR="$("$JAVA" -version 2>&1 | sed -n 's/.*version "\([0-9]*\).*/\1/p' | head -1)"
echo "INFO: JAVA_HOME=$JAVA_HOME (major=$JAVA_MAJOR)"

# Locate the provider jars.
if [[ -z "${BCFIPS_DIR:-}" ]]; then
    if [[ -d /usr/share/java/bouncycastle-fips ]]; then
        BCFIPS_DIR=/usr/share/java/bouncycastle-fips
    elif [[ -d ./lib ]]; then
        BCFIPS_DIR=./lib
    else
        echo "ERROR: no BCFIPS_DIR; run scripts/fetch-jars.sh for local development" >&2
        exit 2
    fi
fi
BCFIPS_DIR="$(readlink -f "$BCFIPS_DIR")"
echo "INFO: BCFIPS_DIR=$BCFIPS_DIR"
ls "$BCFIPS_DIR"/*.jar >/dev/null 2>&1 || { echo "ERROR: no jars in $BCFIPS_DIR" >&2; exit 2; }

# Security configuration style:
# - packaged: the JDK's java.security is already the FIPS one; escape hatches
#   are applied additively via -Djava.security.properties=<file>
# - baked: FIPS config is jlinked into the JDK itself (openjdk-fips >= 25
#   images) and no escape-hatch files exist; approved runs bare, unapproved
#   uses the minimal overlay from ./conf, kernel-entropy is not applicable
#   (its NativePRNGBlocking fallback needs the SUN provider these JDKs drop)
# - local: full-replace configs from ./conf via -Djava.security.properties==<file>
if [[ -n "${FIPS_CONFIG_DIR:-}" && -f "${FIPS_CONFIG_DIR:-}/unapproved.java.security" ]]; then
    CONFIG_STYLE=packaged
elif [[ -f /usr/lib/jvm/jdk-fips-config/unapproved.java.security && -d /usr/share/java/bouncycastle-fips ]]; then
    FIPS_CONFIG_DIR=/usr/lib/jvm/jdk-fips-config
    CONFIG_STYLE=packaged
elif [[ -d /usr/share/java/bouncycastle-fips ]] \
        && grep -qs "BouncyCastleFipsProvider" "$JAVA_HOME/conf/security/java.security"; then
    FIPS_CONFIG_DIR="$(readlink -f ./conf)"
    CONFIG_STYLE=baked
else
    FIPS_CONFIG_DIR="$(readlink -f ./conf)"
    CONFIG_STYLE=local
fi
echo "INFO: CONFIG_STYLE=$CONFIG_STYLE FIPS_CONFIG_DIR=$FIPS_CONFIG_DIR"

LAUNCH_MODE="${LAUNCH_MODE:-both}"
case "$LAUNCH_MODE" in
    module|classpath|both) ;;
    *) echo "ERROR: LAUNCH_MODE must be module, classpath or both (got: $LAUNCH_MODE)" >&2
       exit 2 ;;
esac
RUN_MODES="${RUN_MODES:-approved,kernel-entropy,unapproved}"
APP_ARGS="${APP_ARGS:-}"
VECTORS="$(readlink -f ./vectors)"

# The legacy security manager flag used by the existing pipeline, dropped on
# new JDKs where the security manager is gone. In the packaged environment
# the base java.policy only carries the BC-FJA grants, so the suite's own
# permissions (vector reads, loopback TLS) come from an additive policy file.
SECURITY_FLAGS=""
if [[ "$JAVA_MAJOR" -le 23 ]]; then
    SECURITY_FLAGS="-Djava.security.manager=default"
    if [[ "$CONFIG_STYLE" == packaged && -f ./conf/pipeline-extra.policy ]]; then
        SECURITY_FLAGS="$SECURITY_FLAGS -Djava.security.policy=$PWD/conf/pipeline-extra.policy"
    fi
fi

echo "INFO: compiling"
mkdir -p out
find src -name '*.java' > out/sources.txt
# Baked-config images set JDK_JAVAC_OPTIONS (module-path with only the core
# module); mixing that with our classpath compile breaks bcpkix resolution.
JDK_JAVAC_OPTIONS="" "$JAVAC" --release 11 -d out/classes -cp "$BCFIPS_DIR/*" @out/sources.txt

# security_props <variant> -> echoes the -Djava.security.properties flag (or nothing)
security_props() {
    local variant="$1"
    if [[ "$CONFIG_STYLE" == packaged ]]; then
        case "$variant" in
            approved) ;; # base config already active
            kernel-entropy)
                echo "-Djava.security.properties=$FIPS_CONFIG_DIR/kernel-entropy.java.security" ;;
            unapproved)
                echo "-Djava.security.properties=$FIPS_CONFIG_DIR/unapproved.java.security" ;;
        esac
    elif [[ "$CONFIG_STYLE" == baked ]]; then
        case "$variant" in
            approved) ;; # jlinked config already active
            unapproved)
                echo "-Djava.security.properties=$FIPS_CONFIG_DIR/overlay-unapproved.java.security" ;;
        esac
    else
        case "$variant" in
            approved)
                echo "-Djava.security.properties==$FIPS_CONFIG_DIR/local.java.security" ;;
            kernel-entropy)
                echo "-Djava.security.properties==$FIPS_CONFIG_DIR/local-kernel-entropy.java.security" ;;
            unapproved)
                echo "-Djava.security.properties==$FIPS_CONFIG_DIR/local-unapproved.java.security" ;;
        esac
    fi
}

FAILED=0

run_leg() {
    local variant="$1" launch="$2"
    local mode=approved
    [[ "$variant" == unapproved ]] && mode=unapproved

    local props
    props="$(security_props "$variant")"

    local -a cmd=("$JAVA")
    [[ -n "$SECURITY_FLAGS" ]] && cmd+=($SECURITY_FLAGS)
    [[ -n "$props" ]] && cmd+=("$props")
    # Expanded by the policy files (policy.expandProperties=true).
    cmd+=("-Dfipstest.conf=$FIPS_CONFIG_DIR" "-Dfipstest.base=$PWD" "-Dfipstest.lib=$BCFIPS_DIR")

    if [[ "$launch" == module ]]; then
        cmd+=(--module-path "$BCFIPS_DIR" --add-modules ALL-MODULE-PATH -cp out/classes)
    else
        cmd+=(-cp "out/classes:$BCFIPS_DIR/*")
    fi
    cmd+=(dev.chainguard.fipstest.Main "--mode=$mode" "--vectors=$VECTORS")
    [[ -n "$APP_ARGS" ]] && cmd+=($APP_ARGS)

    echo
    echo "=== leg: variant=$variant launch=$launch mode=$mode ==="
    echo "CMD: ${cmd[*]}"
    if timeout 900 "${cmd[@]}"; then
        echo "=== leg OK: $variant/$launch ==="
    else
        echo "=== leg FAILED: $variant/$launch ==="
        FAILED=1
    fi
}

launches=()
[[ "$LAUNCH_MODE" == module || "$LAUNCH_MODE" == both ]] && launches+=(module)
[[ "$LAUNCH_MODE" == classpath || "$LAUNCH_MODE" == both ]] && launches+=(classpath)

IFS=',' read -ra variants <<< "$RUN_MODES"
for variant in "${variants[@]}"; do
    case "$variant" in
        approved)
            for l in "${launches[@]}"; do run_leg approved "$l"; done ;;
        kernel-entropy)
            if [[ "$CONFIG_STYLE" == baked ]]; then
                echo "INFO: kernel-entropy leg not applicable to baked-config JDKs, skipping"
            else
                run_leg "$variant" "${launches[0]}"
            fi ;;
        unapproved)
            # config variants only need one launch flavor
            run_leg "$variant" "${launches[0]}" ;;
        *)
            echo "ERROR: unknown RUN_MODES entry: $variant" >&2; exit 2 ;;
    esac
done

# JKS -> BCFKS keytool -importkeystore interop (the openjdk-fips migration
# pattern). Generates a legacy JKS store (kafka-style approved_only bypass for
# the generation only), converts it to BCFKS with the BC provider, then has
# the app load and use the converted store.
KEYTOOL="$JAVA_HOME/bin/keytool"
if [[ -x "$KEYTOOL" ]]; then
    echo
    echo "=== keytool JKS->BCFKS interop ==="
    INTEROP_DIR="$(mktemp -d)"
    INTEROP_PASS="FipsTest-Import-Pass1!"
    if "$KEYTOOL" -genkeypair -alias imported -keyalg RSA -keysize 2048 \
            -sigalg SHA256withRSA -dname "CN=imported" -validity 30 \
            -keystore "$INTEROP_DIR/legacy.jks" -storetype JKS \
            -storepass "$INTEROP_PASS" -keypass "$INTEROP_PASS" \
            -J-Djava.security.properties=/dev/null 2>/dev/null; then
        approved_props="$(security_props approved)"
        if "$KEYTOOL" -importkeystore \
                -srckeystore "$INTEROP_DIR/legacy.jks" -srcstoretype JKS \
                -srcstorepass "$INTEROP_PASS" \
                -destkeystore "$INTEROP_DIR/imported.bcfks" -deststoretype BCFKS \
                -deststorepass "$INTEROP_PASS" -providername BCFIPS \
                ${approved_props:+-J$approved_props} \
                -J--module-path -J"$BCFIPS_DIR" -J--add-modules -JALL-MODULE-PATH; then
            echo "conversion OK, verifying converted store in the app"
            if FIPSTEST_IMPORTED_STORE="$INTEROP_DIR/imported.bcfks" \
               FIPSTEST_IMPORTED_STOREPASS="$INTEROP_PASS" \
               "$JAVA" ${approved_props:+"$approved_props"} \
                   "-Dfipstest.conf=$FIPS_CONFIG_DIR" "-Dfipstest.base=$PWD" \
                   "-Dfipstest.lib=$BCFIPS_DIR" \
                   -cp "out/classes:$BCFIPS_DIR/*" dev.chainguard.fipstest.Main \
                   --mode=approved "--vectors=$VECTORS" \
                   "--include=scenarios.bcfks/imported/*"; then
                echo "=== keytool interop OK ==="
            else
                echo "=== keytool interop FAILED (app verification) ==="
                FAILED=1
            fi
        else
            echo "=== keytool interop FAILED (importkeystore) ==="
            FAILED=1
        fi
    else
        echo "WARN: JKS generation unavailable in this environment, interop skipped"
    fi
    rm -rf "$INTEROP_DIR"
fi

# Diagnostic dump of the entropy utility when bc-rng-jent is present.
if ls "$BCFIPS_DIR"/bc-rng-jent*.jar >/dev/null 2>&1; then
    echo
    echo "=== DumpInfo (diagnostic) ==="
    "$JAVA" --module-path "$BCFIPS_DIR" --add-modules ALL-MODULE-PATH \
        org.bouncycastle.entropy.util.DumpInfo || echo "WARN: DumpInfo failed (non-fatal)"
fi

echo
if [[ "$FAILED" -ne 0 ]]; then
    echo "OVERALL: FAILED"
    exit 1
fi
echo "OVERALL: OK"
