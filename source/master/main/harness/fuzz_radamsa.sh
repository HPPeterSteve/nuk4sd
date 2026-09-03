#!/bin/bash
# Fuzzing de alta intensidade da CLI do Nuk4sd com radamsa.
# Cada input mutado é executado como argv do binário instrumentado (debug com
# informações de debug, mas sem ASAN no link — monitoramos crashes/TB via
# timeout e exit codes). Crashes são salvos em $OUT.
set -u
BIN="${1:?uso: $0 <binario>}"
CORPUS_DIR="${2:?corpus dir}"
OUT="${3:?out dir}"
ITERS="${4:-5000}"
TIMEOUT_MS=2000

mkdir -p "$OUT"
# Corpus inicial
mkdir -p "$CORPUS_DIR"
cat > "$CORPUS_DIR/vault_ls" <<'EOF'
--ls
EOF
cat > "$CORPUS_DIR/new_vault" <<'EOF'
--new vaultfuzz
EOF
cat > "$CORPUS_DIR/vault_info" <<'EOF'
--vault 1 --info
EOF
cat > "$CORPUS_DIR/run" <<'EOF'
--vault 1 --run /bin/true
EOF
cat > "$CORPUS_DIR/mount" <<'EOF'
--vault 1 --mount
EOF
cat > "$CORPUS_DIR/worm" <<'EOF'
--vault 1 --worm-status
EOF
cat > "$CORPUS_DIR/export" <<'EOF'
--vault 1 --export --dest /tmp/dest
EOF
cat > "$CORPUS_DIR/longpath" <<'EOF'
--new $(python3 -c "print('A'*4000)")
EOF
cat > "$CORPUS_DIR/nullish" <<'EOF'
--new $'\x00\x01\x02' --path /tmp/$'\xff\xfe'
EOF

crash_n=0
total=0
hung=0
echo "[*] Iniciando fuzzing radamsa: $ITERS iterações em $BIN"
for ((i=1; i<=ITERS; i++)); do
    base=$(ls "$CORPUS_DIR" | shuf -n 1)
    input=$(radamsa "$CORPUS_DIR/$base" 2>/dev/null) || continue
    [ -z "$input" ] && continue
    total=$((total + 1))

    # Executa via timeout; capture exit code e dmesg/segfault
    eval set -- "$input" 2>/dev/null || continue
    ( timeout $((TIMEOUT_MS/1000)) "$BIN" "$@" >/dev/null 2>"$OUT/tmp.err" ) &
    pid=$!
    wait $pid
    rc=$?
    if [ $rc -gt 128 ]; then
        crash_n=$((crash_n + 1))
        printf '%s\n' "$input" > "$OUT/crash_$crash_n"
        echo "[!] CRASH #$crash_n (rc=$rc) | input base=$base"
        [ $crash_n -ge 20 ] && { echo "20 crashes coletados, continuando..."; }
    elif [ $rc -eq 124 ]; then
        hung=$((hung + 1))
        printf '%s\n' "$input" > "$OUT/hang_$hung"
    fi
    if [ $((total % 500)) -eq 0 ]; then
        echo "[*] progress: $total inputs | crashes=$crash_n hangs=$hung"
    fi
done
echo "[+] Fim: total=$total crashes=$crash_n hangs=$hung"
