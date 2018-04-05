#!/bin/sh

set -e
set -x

aclocal
autoheader
automake --add-missing
autoconf
