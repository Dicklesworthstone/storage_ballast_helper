#!/usr/bin/env bash
# scripts/dsr_native_checks.sh — run the native Linux quality-gate stages for
# this exact commit on a dsr build host.
#
# sbh does not use GitHub Actions. This replaces the btrfs-compression,
# systemd-namespace and source-root-safety workflows: it ships
# `git archive HEAD` (the commit, never the working tree) to HOST over ssh,
# runs `scripts/quality-gate.sh --stage native-btrfs` and
# `--stage native-systemd` there (source-root runs with the ordinary stages),
# prints both stage logs, and removes its remote directory. dsr runs it as a
# required check of storage_ballast_helper (`required_checks` in
# ~/.config/dsr/repos.yaml on the dsr host), so `dsr quality` and
# `dsr fallback` stop on a failure, even with --skip-checks.
#
# Usage: scripts/dsr_native_checks.sh [HOST]   (default: $SBH_NATIVE_HOST, else trj)
#
# trj is the default: dsr's Linux build host with the room for two fresh
# cargo target dirs and a 1 GiB Btrfs image (ts1's root sat at 100% on
# 2026-10-19).
#
# HOST needs: Linux, passwordless sudo, systemd, btrfs-progs, a C compiler,
# and rustup (the toolchain in rust-toolchain.toml is installed on demand).
# Exit: 0 both stages passed, 1 a stage failed, 2 the host could not be set up.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST="${1:-${SBH_NATIVE_HOST:-trj}}"
REV="$(git -C "${ROOT}" rev-parse HEAD)"
# Relative to the remote home directory: never /tmp on a shared build host.
REMOTE="sbh-native-checks-${REV:0:12}-$$"

say() { echo "== $*"; }

say "native checks of ${REV} on ${HOST}"
if ! git -C "${ROOT}" archive --format=tar HEAD \
    | ssh -o BatchMode=yes "${HOST}" "mkdir '${REMOTE}' && tar -x -C '${REMOTE}'"; then
    echo "dsr_native_checks: could not ship ${REV} to ${HOST}" >&2
    exit 2
fi

rc=0
for stage in native-btrfs native-systemd; do
    say "${stage}"
    if ! ssh -o BatchMode=yes "${HOST}" \
        "cd '${REMOTE}' && SBH_QG_LOG_DIR=\"\$PWD/qg-logs\" ./scripts/quality-gate.sh --local --no-color --stage ${stage}"; then
        rc=1
    fi
    ssh -o BatchMode=yes "${HOST}" "cat '${REMOTE}/qg-logs/stages/${stage}.log'" || true
done

ssh -o BatchMode=yes "${HOST}" "rm -r '${REMOTE}'" \
    || echo "dsr_native_checks: could not remove ~/${REMOTE} on ${HOST}" >&2

if [[ ${rc} -eq 0 ]]; then
    say "PASS: native-btrfs and native-systemd at ${REV} on ${HOST}"
else
    say "FAIL: a native stage failed at ${REV} on ${HOST} (logs above)"
fi
exit "${rc}"
