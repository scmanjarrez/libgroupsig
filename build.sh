#!/bin/bash

set -x

usage() {
    echo "Usage: $0 [--keep-ext][--sha2|sha3|hw|hw3]"
    echo "  --keep-ext: do not rebuild external libraries, i.e. mcl, gtest"
    echo "  --debug: compile with debug symbols"
    echo "  --gtest: compile GTEST suite"
    echo "  --sha2: compile using SHA2 in PS16 (SW). Default BLAKE"
    echo "  --sha3: compile using SHA3 in PS16/KTY04 (SW)"
    echo "  --hw/hw3: compile using SHA2/SHA3 (HW) in PS16/KTY04, requires PYNQ"
}

keep_ext() {
    mv build/external build/mclproject-prefix build/gtest-project-prefix /tmp
    rm -rf build && mkdir build
    mv /tmp/external /tmp/mclproject-prefix /tmp/gtest-project-prefix build
}

rebuild() {
    rm -rf build && mkdir build
}

build() {
    [ -n "$DEBUG" ] && debug="-DCMAKE_BUILD_TYPE=DEBUG" && verbose="VERBOSE=1"
    [ -n "$GTEST" ] && gtest="-DUSE_GTEST=ON"
    [ -n "$SHA2" ] && sha2="-DSHA2=1"
    [ -n "$SHA3" ] && sha3="-DSHA3=1"
    [ -n "$HW" ] && hw="-DHW=1"
    [ -n "$HW3" ] && hw3="-DHW3=1"
    [[ "$(uname -a)" =~ (arm|aarch) ]] && comp="-DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++"
    cd build && cmake $gtest $comp $debug $sha2 $sha3 $hw $hw3 .. \
        && make $verbose
}

for arg in "$@"; do
    [[ "$arg" == -h || "$arg" == --help ]] && usage && exit
    [[ "$arg" == --debug ]] && DEBUG=1
    [[ "$arg" == --gtest ]] && GTEST=1
    [[ "$arg" == --keep-ext ]] && KEEPEXT=1
    [[ "$arg" == --sha2 ]] && SHA2=1
    [[ "$arg" == --sha3 ]] && SHA3=1
    [[ "$arg" == --hw ]] && HW=1
    [[ "$arg" == --hw3 ]] && HW=1 && HW3=1
done

[ -n "$KEEPEXT" ] && keep_ext || rebuild
build
