#!/usr/bin/env bash
# Run the full test matrix against BC-FIPS packages from a presubmit
# APK repository, inside the jdk-fips image - i.e. against the packages
# exactly as a PR would install them.
#
# Usage:
#   scripts/run-presubmit.sh <presubmit-repo-url> [package...]
#
# Example:
#   scripts/run-presubmit.sh \
#     <presubmit-repo-url> \
#     bouncycastle-fips-preview
#
# Requirements: docker, chainctl (authenticated), access to
# cgr.dev/chainguard-private/jdk-fips:latest-dev.

set -o errexit -o nounset -o pipefail

cd "$(dirname "$0")/.."

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <presubmit-repo-url> [package...]" >&2
    exit 2
fi

REPO_URL="$1"
shift
PACKAGES=("${@:-bouncycastle-fips-preview}")
IMAGE="${FIPSTEST_IMAGE:-cgr.dev/chainguard-private/jdk-fips:latest-dev}"

echo "INFO: presubmit repo: $REPO_URL"
echo "INFO: packages: ${PACKAGES[*]}"
echo "INFO: image: $IMAGE"

TOKEN="$(chainctl auth token --audience apk.cgr.dev)"
# Exported and passed to docker by NAME ONLY so the token never appears in
# docker's argv (visible in ps/procfs) - docker reads the value from our env.
export AUTH_REPO="${REPO_URL/https:\/\//https:\/\/user:${TOKEN}@}"

docker run --rm --user root -v "$PWD:/work" -w /work \
    -e AUTH_REPO -e PACKAGES="${PACKAGES[*]}" \
    -e HOST_UIDGID="$(id -u):$(id -g)" \
    --entrypoint bash "$IMAGE" -c '
set -e
echo "=== bouncycastle packages before:"
apk list --installed 2>/dev/null | grep bouncycastle || true
echo "=== installing from presubmit repo:"
# shellcheck disable=SC2086
apk add --repository "$AUTH_REPO" --allow-untrusted $PACKAGES
echo "=== bouncycastle packages after:"
apk list --installed 2>/dev/null | grep bouncycastle || true
echo "=== running the matrix:"
rc=0
JAVA_HOME=/usr/lib/jvm/default-jvm ./run.sh || rc=$?
chown -R "$HOST_UIDGID" /work/out 2>/dev/null || true
exit $rc'
