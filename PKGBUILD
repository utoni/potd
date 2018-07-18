pkgname=potd
pkgver=c19cb7e39a80fab15429da599d7b8c85224fde96
pkgrel=1
pkgdesc="A hgih scalable SSH/TCP honeypot."
arch=('i686' 'x86_64')
url="https://github.com/lnslbrty/potd"
license=('BSD-3')
depends=('libssh' 'libseccomp')
source=('https://github.com/lnslbrty/potd/archive/c19cb7e39a80fab15429da599d7b8c85224fde96.zip')
md5sums=('5b2619cc88f2a8c117029880de10ffcf')

build() {
    cd "${srcdir}/${pkgname}-${pkgver}"
    ./autogen.sh
    ./configure --prefix=/usr
    make
}

package() {
    cd "${srcdir}/${pkgname}-${pkgver}"
    make DESTDIR=$pkgdir install
}
