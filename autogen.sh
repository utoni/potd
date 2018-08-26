#!/bin/sh

set -e
set -x

if ! autoreconf -fi; then
    aclocal
    autoheader
    autoconf
    automake --foreign --add-missing --force-missing --copy
fi

set +x
printf "\n%s\n" "You can now run \`./configure\` and \`make\`."
printf "%s\n" "  (or run only \`make\` if potd is already configured)"
