#!/usr/bin/env bash
# Reproduce issue #35 with published v0.7.0/v0.7.1, then exercise the fixed caller.
# Usage: bash scripts/qualify_self_update_service_restart.sh /path/to/patched/sbh
# The supplied binary must run on Debian 12 and match the Docker host's CPU.
# Requires Docker and network access. All installation writes occur inside fresh
# disposable containers; no host service or installation is changed.
#
# Repeated updates and loaded-service/error cases are in the offline Rust suite:
#   cargo test --locked --test self_update_service_restart
#   cargo test --locked --lib daemon::service::executable::tests
# The Rust suite uses a systemctl shim, not a booted systemd instance.
set -euo pipefail

if [[ $# != 1 || ! -f $1 ]]; then
    printf 'Usage: %s /path/to/patched/sbh\n' "$0" >&2
    exit 1
fi
command -v docker >/dev/null || { printf 'Docker is required.\n' >&2; exit 1; }
patched=$(realpath -- "$1")
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
installer="$script_dir/install.sh"
[[ -f $installer ]] || { printf 'Run from a repository checkout containing scripts/install.sh.\n' >&2; exit 1; }

for scenario in default custom system; do
    printf '\n=== Debian 12 published-release qualification: %s ===\n' "$scenario"
    docker run --rm -i \
        --mount "type=bind,source=$patched,target=/qualification/sbh,readonly" \
        --mount "type=bind,source=$installer,target=/qualification/install.sh,readonly" \
        -e "SCENARIO=$scenario" debian:12-slim bash -s <<'CONTAINER'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    ca-certificates curl xz-utils tar coreutils grep sed python3 procps
export HOME=/root
case "$SCENARIO" in
    default) destination="$HOME/.local/bin"; expected_baseline=2; install_args=() ;;
    custom) destination=/opt/sbhprev; expected_baseline=2; install_args=(--dest "$destination") ;;
    system) destination=/usr/local/bin; expected_baseline=0; install_args=(--dest "$destination") ;;
    *) exit 90 ;;
esac
# Fresh containers are essential: a system copy masks the bug in user/custom runs.
[[ ! -e /usr/local/bin/sbh && ! -e /usr/bin/sbh ]]
bash /qualification/install.sh --quiet --version v0.7.0 "${install_args[@]}"
export PATH="$destination:$PATH"
binary="$destination/sbh"
"$binary" --version | grep -F '0.7.0'
set +e
"$binary" update --version v0.7.1 --json > /tmp/baseline.json 2> /tmp/baseline.stderr
baseline_exit=$?
set -e
cat /tmp/baseline.json
cat /tmp/baseline.stderr >&2
python3 - "$baseline_exit" "$expected_baseline" /tmp/baseline.json <<'PY'
import json, sys
actual, expected = map(int, sys.argv[1:3])
with open(sys.argv[3], encoding="utf-8") as stream:
    report = json.load(stream)
assert actual == expected, (actual, expected, report)
assert report["applied"] is True, report
assert report["success"] is (expected == 0), report
assert report["service_restart"]["status"] == ("skipped" if expected == 0 else "failed"), report
if expected:
    assert "could not locate sbh binary" in report["service_restart"]["error"], report
PY
"$binary" --version | grep -F '0.7.1'

# The code that performs the handoff belongs to the running updater. Installing
# a fixed binary cannot retroactively fix the old updater's final restart step.
# Run the patched caller explicitly against the same published target instead.
cp /qualification/sbh "$binary"
chmod 755 "$binary"
printf 'Patched caller: '
"$binary" --version
set +e
"$binary" update --version v0.7.1 --force --json > /tmp/patched.json 2> /tmp/patched.stderr
patched_exit=$?
set -e
cat /tmp/patched.json
cat /tmp/patched.stderr >&2
python3 - "$patched_exit" "$binary" /tmp/patched.json <<'PY'
import json, sys
with open(sys.argv[3], encoding="utf-8") as stream:
    report = json.load(stream)
assert int(sys.argv[1]) == 0, (sys.argv[1], report)
assert report["applied"] is True and report["success"] is True, report
assert report["install_path"] == sys.argv[2], report
assert report["service_restart"]["status"] == "skipped", report
PY
"$binary" --version | grep -F '0.7.1'
printf 'PASS: %s (published baseline exit %s; patched caller exit %s)\n' \
    "$SCENARIO" "$baseline_exit" "$patched_exit"
CONTAINER
done
