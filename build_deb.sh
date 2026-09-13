#!/usr/bin/env bash
# ==============================================================================
# build_deb.sh - Compila o Nuk4sd e gera o pacote .deb com SquashFS e Desktop
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo "  Iniciando build do pacote .deb Nuk4sd"
echo "=========================================="

# 1. Verifica se o cargo e cargo-deb estão instalados
if ! command -v cargo &>/dev/null; then
    echo "[-] Erro: Rust/Cargo não encontrado. Instale com: curl https://sh.rustup.rs -sSf | sh"
    exit 1
fi

if ! command -v cargo-deb &>/dev/null; then
    echo "[*] Instalando cargo-deb..."
    cargo install cargo-deb
fi

# 2. Verifica se o SquashFS está presente
SQUASHFS_FILE="runtime/ubuntu24_04.squashfs"
if [ ! -f "$SQUASHFS_FILE" ]; then
    echo "[-] Erro: Imagem runtime '$SQUASHFS_FILE' não encontrada!"
    exit 1
fi
echo "[+] Runtime SquashFS detectado: $SQUASHFS_FILE ($(du -h "$SQUASHFS_FILE" | cut -f1))"

# 3. Compilação do binário em modo release (se executado em Linux)
if [ "$(uname -s)" = "Linux" ]; then
    echo "[*] Compilando binário Nuk4sd em modo Release (Linux)..."
    cargo build --release
else
    echo "[!] Não está no Linux. Verificando se o binário Linux pré-compilado existe em target/release/Nuk4sd..."
    if [ ! -f "target/release/Nuk4sd" ]; then
        echo "[-] Erro: target/release/Nuk4sd não encontrado para empacotar."
        exit 1
    fi
fi

# 4. Geração do pacote .deb
echo "[*] Gerando pacote .deb com cargo-deb..."
cargo deb --no-build --no-strip

echo "=========================================="
echo "  Pacote .deb gerado com sucesso!"
echo "  Localização: $(ls -t target/debian/*.deb | head -n 1)"
echo "=========================================="
echo "Para instalar no Debian / Ubuntu / Mint:"
echo "  sudo apt install ./$(ls -t target/debian/*.deb | head -n 1)"
echo "=========================================="
