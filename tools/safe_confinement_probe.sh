#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/tools/safe_confinement_probe.c"
OUTDIR="${1:-$ROOT/test-results}"
MODE="${2:-host}"
mkdir -p "$OUTDIR"
OUTDIR="$(cd "$OUTDIR" && pwd)"
BIN="$OUTDIR/safe_confinement_probe"
LOG="$OUTDIR/safe-confinement-$(date -u +%Y%m%dT%H%M%SZ).log"

cc -std=c11 -O2 -Wall -Wextra -Wpedantic -static "$SRC" -o "$BIN"

set +e
if [[ "$MODE" == "sandbox" ]]; then
  sudo -n "$ROOT/target/release/Nuk4sd" \
    --vault 0 --run "$BIN" --no-fuse --no-preflight --no-net \
    --seccomp-strict --max-procs 32 --max-mem 1 --max-filesize 8 \
    --max-fds 64 --dev minimal --ro "$OUTDIR" --audit --verbose >"$LOG" 2>&1
  rc=$?
else
  "$BIN" >"$LOG" 2>&1
  rc=$?
fi
set -e
printf 'mode=%s\nexit_code=%s\nlog=%s\n' "$MODE" "$rc" "$LOG"
cat "$LOG"
exit "$rc"
