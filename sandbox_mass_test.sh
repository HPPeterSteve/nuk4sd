#!/bin/bash
# sandbox_mass_test.sh — Nuk4sd 0.9.26 — Bateria de testes em massa
#
# Uso: sudo ./sandbox_mass_test.sh <vault_id>
# Ex:  sudo ./sandbox_mass_test.sh 1
#
# O script lança cada aplicativo com o preset correto por 5 segundos,
# mata o processo e registra o resultado em sandbox_mass_test.log.

VAULT_ID="${1:-1}"
LOG="sandbox_mass_test.log"
NUK="./target/release/Nuk4sd"
TIMEOUT_SEC=5

if [[ $EUID -ne 0 ]]; then
    echo "⚠  Execute como root: sudo $0 $VAULT_ID"
    exit 1
fi

if [[ ! -x "$NUK" ]]; then
    echo "⚠  Binário não encontrado em $NUK — compile primeiro: cargo build --release"
    exit 1
fi

echo "=== Nuk4sd 0.9.26 — Bateria de Testes em Massa ===" | tee "$LOG"
echo "Data: $(date)" | tee -a "$LOG"
echo "Vault ID: $VAULT_ID" | tee -a "$LOG"
echo "" | tee -a "$LOG"

PASS=0
FAIL=0
SKIP=0

run_test() {
    local APP="$1"
    local PRESET="$2"
    local EXTRA_FLAGS="$3"
    local BINARY_PATH

    BINARY_PATH=$(which "$APP" 2>/dev/null)
    if [[ -z "$BINARY_PATH" ]]; then
        echo "  ⊘  SKIP   | $APP — não encontrado no PATH" | tee -a "$LOG"
        ((SKIP++))
        return
    fi

    echo "" | tee -a "$LOG"
    echo "──────────────────────────────────────────────" | tee -a "$LOG"
    echo "  APP:     $APP ($BINARY_PATH)" | tee -a "$LOG"
    echo "  PRESET:  $PRESET" | tee -a "$LOG"
    echo "  FLAGS:   $EXTRA_FLAGS" | tee -a "$LOG"

    # Roda em background, captura stderr, mata após TIMEOUT_SEC
    TMPOUT=$(mktemp)
    timeout --kill-after=2 "$TIMEOUT_SEC" \
        $NUK --vault "$VAULT_ID" --run "$BINARY_PATH" \
             --preset "$PRESET" $EXTRA_FLAGS \
        > /dev/null 2> "$TMPOUT" &
    BGPID=$!
    sleep "$TIMEOUT_SEC"

    # Tenta matar graciosamente; se já saiu sozinho, registra o exit code
    if kill -0 "$BGPID" 2>/dev/null; then
        kill "$BGPID" 2>/dev/null
        wait "$BGPID" 2>/dev/null
        EXIT_CODE=$?
        STATUS="RUNNING→KILLED (OK — app não crashou)"
        echo "  STATUS:  ✔  $STATUS" | tee -a "$LOG"
        ((PASS++))
    else
        wait "$BGPID" 2>/dev/null
        EXIT_CODE=$?
        if [[ $EXIT_CODE -eq 0 || $EXIT_CODE -eq 1 ]]; then
            STATUS="SAIU CEDO (exit=$EXIT_CODE)"
            echo "  STATUS:  ⚠  $STATUS" | tee -a "$LOG"
            ((FAIL++))
        else
            STATUS="CRASH (exit=$EXIT_CODE)"
            echo "  STATUS:  ✖  $STATUS" | tee -a "$LOG"
            ((FAIL++))
        fi
    fi

    echo "  EXIT CODE: $EXIT_CODE" | tee -a "$LOG"

    # Mostra as últimas 10 linhas de stderr relevantes
    FATAL_LINES=$(grep -E "(FATAL|ERROR|seccomp|SIGSYS|execvp|pivot_root)" "$TMPOUT" | tail -5)
    if [[ -n "$FATAL_LINES" ]]; then
        echo "  ERROS FATAIS:" | tee -a "$LOG"
        echo "$FATAL_LINES" | sed 's/^/    /' | tee -a "$LOG"
    fi

    # Mostra flags detectadas pelo preflight scanner
    PREFLIGHT=$(grep -i "preflight\|autodetect\|detected\|auto-bind" "$TMPOUT" | tail -5)
    if [[ -n "$PREFLIGHT" ]]; then
        echo "  PREFLIGHT:" | tee -a "$LOG"
        echo "$PREFLIGHT" | sed 's/^/    /' | tee -a "$LOG"
    fi

    rm -f "$TMPOUT"
}

echo "=== Iniciando testes ===" | tee -a "$LOG"

# Helper: limpa stale FUSE mount entre rodadas
cleanup_fuse() {
    fusermount -u /tmp/nuk4sd_test_vault 2>/dev/null || true
    # Aguarda kernel liberar o mountpoint
    sleep 1
}

# ── Aplicações de teste ──────────────────────────────────────────────────────

run_test "firefox"      "browser"  "--no-net"; cleanup_fuse
run_test "libreoffice"  "office"   ""; cleanup_fuse
run_test "evince"       "office"   ""; cleanup_fuse
run_test "celluloid"    "media"    ""; cleanup_fuse
run_test "code"         "dev"      ""; cleanup_fuse
run_test "gimp"         "office"   ""; cleanup_fuse
run_test "vlc"          "media"    "--no-net"; cleanup_fuse
run_test "obs"          "browser"  ""; cleanup_fuse
run_test "gedit"        "dev"      ""; cleanup_fuse
run_test "eog"          "office"   ""; cleanup_fuse
run_test "nautilus"     "office"   ""; cleanup_fuse
run_test "gnome-calculator" "office" ""; cleanup_fuse

# ── Testes de segurança: path traversal ─────────────────────────────────────
echo "" | tee -a "$LOG"
echo "════" | tee -a "$LOG"
echo "=== Testes de Segurança ===" | tee -a "$LOG"

echo "" | tee -a "$LOG"
echo "  TEST: Path Traversal --ro ../../etc/shadow" | tee -a "$LOG"
TMPOUT=$(mktemp)
$NUK --vault "$VAULT_ID" --run /bin/ls --ro "../../etc/shadow" \
    > /dev/null 2> "$TMPOUT"
if grep -q "escapes vault jail\|refusing\|EPERM" "$TMPOUT"; then
    echo "  STATUS:  ✔  BLOQUEADO (path traversal corretamente recusado)" | tee -a "$LOG"
else
    echo "  STATUS:  ✖  NÃO BLOQUEADO — auditoria necessária!" | tee -a "$LOG"
fi
rm -f "$TMPOUT"
cleanup_fuse

echo "" | tee -a "$LOG"
echo "  TEST: Blacklist ~/.ssh com expansão de tilde" | tee -a "$LOG"
TMPOUT=$(mktemp)
$NUK --vault "$VAULT_ID" --run /bin/ls --blacklist ~/.ssh \
    > /dev/null 2> "$TMPOUT"
if grep -q "blacklist\|BIND_BLACKLIST\|tmpfs" "$TMPOUT"; then
    echo "  STATUS:  ✔  blacklist aplicado" | tee -a "$LOG"
else
    echo "  STATUS:  ⚠  blacklist não confirmado no log" | tee -a "$LOG"
fi
rm -f "$TMPOUT"

# ── Resumo ──────────────────────────────────────────────────────────────────
echo "" | tee -a "$LOG"
echo "════" | tee -a "$LOG"
echo "=== RESUMO ===" | tee -a "$LOG"
echo "  PASS:  $PASS" | tee -a "$LOG"
echo "  FAIL:  $FAIL" | tee -a "$LOG"
echo "  SKIP:  $SKIP" | tee -a "$LOG"
echo "" | tee -a "$LOG"
echo "Log completo: $(pwd)/$LOG" | tee -a "$LOG"