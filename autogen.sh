#!/bin/sh

set -e
set -x

if ! autoreconf -fi; then
    aclocal
    autoheader
    autoconf
    automake --foreign --add-missing --force-missing --copy
fi
