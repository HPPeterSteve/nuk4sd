#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT_DIR/tools/diagnose_tmp.c"
OUT_DIR="${OUT_DIR:-$ROOT_DIR/test-results}"
OUT_BIN="${OUT_BIN:-$OUT_DIR/diagnose_tmp}"
TARGET="${1:-/tmp}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT="${REPORT:-$OUT_DIR/diagnose_tmp-$STAMP.log}"

mkdir -p -- "$OUT_DIR"

gcc -std=c11 -O2 -Wall -Wextra -Werror -D_FILE_OFFSET_BITS=64 \
  "$SRC" -o "$OUT_BIN"

{
  printf 'command='; printf '%q ' "$OUT_BIN" "$TARGET"; printf '\n'
  printf 'timestamp_utc=%s\n' "$STAMP"
  "$OUT_BIN" "$TARGET"
} 2>&1 | tee "$REPORT"

printf 'diagnostic_binary=%s\n' "$OUT_BIN"
printf 'diagnostic_report=%s\n' "$REPORT"
