#!/usr/bin/env bash
# Reproduce issue #35 with published v0.7.0/v0.7.1, then exercise the fixed caller.
# Usage: bash scripts/qualify_self_update_service_restart.sh [--systemd] /path/to/patched/sbh
# The supplied binary must run on Debian 12 and match the Docker host's CPU.
# Requires Docker and network access. All installation writes occur inside fresh
# disposable containers; no host service or installation is changed.
#
# --systemd explicitly opts into privileged containers with private cgroup
# namespaces, booted systemd and real SBH daemons. It tests absent, disabled-but-
# running and runtime-enabled services at user-local/custom paths. PID changes,
# live executable hashes, unchanged units and daemon ping establish activation.
# This mode uses the patched caller to install published v0.7.1, not vice versa.
#
# Repeated updates and loaded-service/error cases are in the offline Rust suite:
#   cargo test --locked --test self_update_service_restart
#   cargo test --locked --lib daemon::service::executable::tests
# The Rust suite uses a systemctl shim, not a booted systemd instance.
set -euo pipefail

live_systemd=false
if [[ ${1-} == --systemd ]]; then
    live_systemd=true
    shift
fi
if [[ $# != 1 || ! -f $1 ]]; then
    printf 'Usage: %s [--systemd] /path/to/patched/sbh\n' "$0" >&2
    exit 1
fi
command -v docker >/dev/null || { printf 'Docker is required.\n' >&2; exit 1; }
patched=$(realpath -- "$1")

# Explicit opt-in: boot actual systemd in privileged disposable containers.
# No host service files or host cgroup directories are mounted into them.
if [[ $live_systemd == true ]]; then
    artifacts=$(mktemp -d "${TMPDIR:-/tmp}/sbh-systemd-qualification.XXXXXX")
    container_id=
    scenario_dir=
    cleanup_systemd_container() {
        if [[ -n $container_id ]]; then
            docker logs "$container_id" > "$scenario_dir/container.log" 2>&1 || true
            docker exec "$container_id" journalctl -u sbh.service --no-pager \
                > "$scenario_dir/service.log" 2>&1 || true
            docker cp "$container_id:/qualification-results/." "$scenario_dir/" 2>/dev/null || true
            docker stop -t 15 "$container_id" >/dev/null 2>&1 || true
            container_id=
        fi
    }
    trap cleanup_systemd_container EXIT
    for scenario in default custom custom-space; do
        scenario_dir="$artifacts/$scenario"
        mkdir -p "$scenario_dir"
        container_id=$(docker run --rm -d --privileged --cgroupns=private \
            --tmpfs /run --tmpfs /run/lock --stop-signal SIGRTMIN+3 \
            --mount "type=bind,source=$patched,target=/qualification/sbh,readonly" \
            -e "SCENARIO=$scenario" -e container=docker \
            debian:12-slim bash -c '
                set -eu
                export DEBIAN_FRONTEND=noninteractive
                apt-get update -qq
                apt-get install -y -qq --no-install-recommends \
                    systemd systemd-sysv dbus ca-certificates curl xz-utils tar coreutils python3
                exec /sbin/init
            ')
        booted=false
        for ((attempt = 0; attempt < 300; attempt++)); do
            if docker exec "$container_id" sh -c \
                'test "$(cat /proc/1/comm)" = systemd && systemctl show --property=Version --value >/dev/null' \
                >/dev/null 2>&1; then
                booted=true
                break
            fi
            [[ $(docker inspect -f '{{.State.Running}}' "$container_id" 2>/dev/null) == true ]] || break
            sleep 1
        done
        if [[ $booted != true ]]; then
            printf 'FAIL: systemd did not boot; evidence: %s\n' "$scenario_dir" >&2
            exit 1
        fi
        docker exec -i "$container_id" bash -s <<'SYSTEMD_CONTAINER'
set -euo pipefail
export HOME=/root LC_ALL=C
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
[[ $(cat /proc/1/comm) == systemd ]]
case "$SCENARIO" in
    default) binary=/root/.local/bin/sbh ;;
    custom) binary=/opt/sbhprev/sbh ;;
    custom-space) binary='/opt/sbh custom/sbh' ;;
    *) exit 90 ;;
esac
results=/qualification-results
state=/qualification-state
config="$state/config.toml"
unit=/etc/systemd/system/sbh.service
mkdir -p "$(dirname "$binary")" "$results" "$state/empty-scan-root"
cat > "$config" <<'CONFIG'
[paths]
ballast_dir = "/qualification-state/ballast"
jsonl_log = "/qualification-state/activity.jsonl"
sqlite_db = "/qualification-state/activity.sqlite3"
state_file = "/qualification-state/state.json"
[ballast]
file_count = 1
file_size_bytes = 1048576
[pressure]
poll_interval_ms = 500
maintenance_interval_secs = 3600
[scanner]
dry_run = true
include_user_temp_dir = false
catalog_roots_on_pressured_device = false
root_paths = ["/qualification-state/empty-scan-root"]
cross_devices = false
[notifications]
enabled = false
CONFIG
assert_update() {
    local output=$1 expected=$2
    python3 - "$output" "$binary" "$expected" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as stream:
    report = json.load(stream)
assert report["applied"] is True and report["success"] is True, report
assert report["install_path"] == sys.argv[2], report
assert report["service_restart"]["status"] == sys.argv[3], report
assert report["service_restart"]["scope"] == "system", report
PY
}
wait_for_daemon() {
    local output=$1
    for ((attempt = 0; attempt < 120; attempt++)); do
        if systemctl is-active --quiet sbh.service && \
            timeout 2 "$binary" --config "$config" --json daemon ping > "$output" 2>/dev/null; then
            return 0
        fi
        sleep 0.25
    done
    systemctl status sbh.service --no-pager >&2 || true
    journalctl -u sbh.service --no-pager >&2 || true
    return 1
}
# With a real manager but no unit, a successful update must still exit zero.
[[ $(systemctl show sbh.service --property=LoadState --value) == not-found ]]
cp /qualification/sbh "$binary"
chmod 755 "$binary"
timeout 180 "$binary" --config "$config" update --version v0.7.1 --force --json \
    > "$results/unloaded.json" 2> "$results/unloaded.stderr"
assert_update "$results/unloaded.json" skipped
cat > "$unit" <<UNIT
[Unit]
Description=Disposable SBH self-update qualification
[Service]
Type=simple
ExecStart="$binary" daemon --config "$config"
Restart=no
TimeoutStartSec=30
TimeoutStopSec=15
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
for policy in disabled enabled-runtime; do
    systemctl stop sbh.service
    # Always use the fixed caller; the released target is deliberately different.
    cp /qualification/sbh "$binary"
    chmod 755 "$binary"
    if [[ $policy == enabled-runtime ]]; then
        systemctl enable --runtime sbh.service
    else
        systemctl disable sbh.service
    fi
    systemctl start sbh.service
    wait_for_daemon "$results/$policy-before-ping.json"
    before_pid=$(systemctl show sbh.service --property=MainPID --value)
    before_sha=$(sha256sum "/proc/$before_pid/exe" | cut -d ' ' -f1)
    before_unit=$(sha256sum "$unit")
    before_policy=$(systemctl is-enabled sbh.service || true)
    [[ $before_policy == "$policy" ]]
    timeout 180 "$binary" --config "$config" update --version v0.7.1 --force --json \
        > "$results/$policy-update.json" 2> "$results/$policy-update.stderr"
    assert_update "$results/$policy-update.json" restarted
    wait_for_daemon "$results/$policy-after-ping.json"
    after_pid=$(systemctl show sbh.service --property=MainPID --value)
    after_sha=$(sha256sum "/proc/$after_pid/exe" | cut -d ' ' -f1)
    installed_sha=$(sha256sum "$binary" | cut -d ' ' -f1)
    [[ $before_pid -gt 1 && $after_pid -gt 1 && $before_pid != "$after_pid" ]]
    [[ $after_sha == "$installed_sha" && $after_sha != "$before_sha" ]]
    [[ $(readlink "/proc/$after_pid/exe") == "$binary" ]]
    [[ $(sha256sum "$unit") == "$before_unit" ]]
    [[ $(systemctl is-enabled sbh.service || true) == "$before_policy" ]]
    "$binary" --version | grep -F '0.7.1'
    python3 - "$SCENARIO" "$policy" "$before_pid" "$after_pid" "$before_sha" "$after_sha" \
        > "$results/$policy-activation.json" <<'PY'
import json, sys
print(json.dumps(dict(zip(
    ["location", "enablement", "before_pid", "after_pid", "before_sha256", "after_sha256"],
    sys.argv[1:],
)), indent=2))
PY
    systemctl stop sbh.service
    printf 'PASS: live systemd %s / %s; PID %s -> %s\n' \
        "$SCENARIO" "$policy" "$before_pid" "$after_pid"
done
SYSTEMD_CONTAINER
        cleanup_systemd_container
    done
    trap - EXIT
    printf 'Live-systemd qualification evidence: %s\n' "$artifacts"
    exit 0
fi

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
