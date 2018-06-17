#!/bin/sh

set -e
set -x

aclocal
autoheader
autoconf
automake --foreign --add-missing --force-missing --copy
