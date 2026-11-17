#!/usr/bin/env bash
# Compile and run the anti-forensic DESTROY logic test against the in-tree C
# libraries using the host compiler. Logic test only; not a hardware check.
#
#   bash tests/antiforensic/run.sh [build-dir-with-libs]
#
# build-dir defaults to a sibling storage-sim build. It must contain the static
# libraries libbp_storage.a, libbp_control.a and libadiantum.a (produced by
# configuring tests/storage with CMake).
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
libdir="${1:-$root/build/antiforensic-host}"

if [ ! -f "$libdir/storage/libbp_storage.a" ]; then
    echo "Configuring/building in-tree libraries in $libdir ..."
    cmake -S "$root/tests/storage" -B "$libdir" -G Ninja -DCMAKE_BUILD_TYPE=Debug >/dev/null
    cmake --build "$libdir" >/dev/null
fi

cc -std=c11 -Wall -Wextra -O1 \
    -I"$root/Storage" -I"$root/Control" -I"$root/Crypto" \
    "$root/tests/antiforensic/test_destroy.c" \
    "$libdir/storage/libbp_storage.a" \
    "$libdir/control/libbp_control.a" \
    "$libdir/crypto/libadiantum.a" \
    -o "$libdir/test_destroy"
"$libdir/test_destroy"
