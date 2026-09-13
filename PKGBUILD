# Maintainer: Pedro <pedro@local>
# ==============================================================================
# PKGBUILD - Pacote nativo para Arch Linux / Manjaro / EndeavourOS
# Para compilar e instalar no Arch:
#   makepkg -si
# ==============================================================================

pkgname=nuk4sd
pkgver=0.9.30
pkgrel=1
pkgdesc="Isolamento de processos, sandbox seguro e cofre criptografado com runtime SquashFS"
arch=('x86_64')
url="https://github.com/hppetersteve/nuk4sd"
license=('MPL-2.0')
depends=(
    'fuse3'
    'openssl'
    'libseccomp'
    'libcap'
    'argon2'
    'squashfs-tools'
)
makedepends=(
    'rust'
    'cargo'
    'gcc'
    'pkgconf'
)
provides=('nuk4sd')
conflicts=('nuk4sd')
install=nuk4sd.install

build() {
    cd "$srcdir/.."
    echo "[*] Compilando Nuk4sd para Arch Linux..."
    cargo build --release
}

package() {
    cd "$srcdir/.."

    # 1. Instala o binário no PATH global
    install -Dm755 "target/release/Nuk4sd" "$pkgdir/usr/bin/nuk4sd"

    # 2. Instala a imagem do runtime SquashFS
    install -Dm644 "runtime/ubuntu24_04.squashfs" \
        "$pkgdir/usr/share/nuk4sd/runtime/ubuntu24_04.squashfs"

    # 3. Instala o lançador do desktop (.desktop)
    install -Dm644 "assets/nuk4sd.desktop" \
        "$pkgdir/usr/share/applications/nuk4sd.desktop"

    # 4. Documentação
    install -Dm644 "README.md" \
        "$pkgdir/usr/share/doc/$pkgname/README.md"
}
