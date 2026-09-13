# ==============================================================================
# build_deb.ps1 - Gera o pacote .deb no Windows usando cargo-deb
# ==============================================================================
param (
    [switch]$Fast = $false
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Gerador de Pacote .deb Nuk4sd (Windows)" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# Verifica se o binário Linux pré-compilado está no target
if (-not (Test-Path "target\release\Nuk4sd")) {
    if (Test-Path "..\Nuk4sd (2)") {
        Write-Host "[*] Copiando binário Linux pré-compilado '..\Nuk4sd (2)' para target\release\Nuk4sd..." -ForegroundColor Yellow
        New-Item -ItemType Directory -Force -Path "target\release" | Out-Null
        Copy-Item "..\Nuk4sd (2)" "target\release\Nuk4sd"
    } else {
        Write-Error "target\release\Nuk4sd não encontrado! Certifique-se de compilar o binário para Linux."
        exit 1
    }
}

$squashfs = "runtime\ubuntu24_04.squashfs"
if (-not (Test-Path $squashfs)) {
    Write-Error "Imagem runtime '$squashfs' não encontrada!"
    exit 1
}

Write-Host "[+] Imagem SquashFS detectada: $squashfs" -ForegroundColor Green

Write-Host "[*] Gerando pacote .deb com cargo-deb..." -ForegroundColor Yellow
if ($Fast) {
    cargo deb --no-build --no-strip --fast
} else {
    cargo deb --no-build --no-strip
}

$debFiles = Get-ChildItem "target\debian\*.deb" | Sort-Object LastWriteTime -Descending
if ($debFiles.Count -gt 0) {
    $latestDeb = $debFiles[0]
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host "  Pacote .deb gerado com sucesso!" -ForegroundColor Green
    Write-Host "  Arquivo: $($latestDeb.FullName)" -ForegroundColor Green
    Write-Host "  Tamanho: $([math]::Round($latestDeb.Length / 1MB, 2)) MB" -ForegroundColor Green
    Write-Host "==========================================" -ForegroundColor Green
}
