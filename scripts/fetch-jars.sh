#!/usr/bin/env bash
# LOCAL DEVELOPMENT ONLY: fetch the BC-FIPS provider family jars from Maven
# Central into ./lib so the test app can run outside the packaged FIPS
# runtime. In the packaged runtime the jars come from the bouncycastle-fips
# packages at /usr/share/java/bouncycastle-fips.
#
# Usage: scripts/fetch-jars.sh [bc-fips-version]
#   bc-fips-version defaults to 2.1.1 (the currently packaged pin).
#
# The companion jar versions track what the apk packages ship; bump alongside.
# bc-rng-jent is NOT on Maven Central (apk-only package) - entropy cases
# SKIP in local runs by design.

set -o errexit -o nounset -o pipefail

cd "$(dirname "$0")/.."

BC_FIPS_VERSION="${1:-2.1.1}"
BCTLS_VERSION="${BCTLS_VERSION:-2.1.23}"
BCPKIX_VERSION="${BCPKIX_VERSION:-2.1.10}"
BCUTIL_VERSION="${BCUTIL_VERSION:-2.1.6}"

BASE="https://repo1.maven.org/maven2/org/bouncycastle"

mkdir -p lib
rm -f lib/*.jar

fetch() {
    local artifact="$1" version="$2" canonical="$3"
    local url="$BASE/$artifact/$version/$artifact-$version.jar"
    echo "fetching $url"
    curl -fsSL -o "lib/$canonical" "$url"

    # Verify against the repository-published digest (.sha256 for newer
    # artifacts, .sha1 as fallback for older ones).
    local expected actual
    if expected="$(curl -fsSL "$url.sha256" 2>/dev/null)"; then
        actual="$(sha256sum "lib/$canonical" | cut -d' ' -f1)"
    elif expected="$(curl -fsSL "$url.sha1" 2>/dev/null)"; then
        actual="$(sha1sum "lib/$canonical" | cut -d' ' -f1)"
    else
        echo "ERROR: no published digest found for $url" >&2
        exit 1
    fi
    expected="$(echo "$expected" | tr -d '[:space:]' | cut -c1-${#actual})"
    if [[ "$expected" != "$actual" ]]; then
        echo "ERROR: digest mismatch for $canonical: expected $expected got $actual" >&2
        exit 1
    fi
    echo "  digest OK ($actual)"
}

fetch bc-fips "$BC_FIPS_VERSION" bc-fips.jar
fetch bctls-fips "$BCTLS_VERSION" bctls-fips.jar
fetch bcpkix-fips "$BCPKIX_VERSION" bcpkix-fips.jar
fetch bcutil-fips "$BCUTIL_VERSION" bcutil-fips.jar

echo
echo "fetched into lib/:"
ls -la lib/
echo
echo "sha256 (record these when pinning a new version):"
sha256sum lib/*.jar
