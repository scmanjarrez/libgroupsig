#!/bin/bash

usage() {
    echo "Usage: $0 [--keep-mcl][--hw]"
    echo "  --keep-mcl: do not rebuild mcl"
    echo "  --hw: compile using hw functions"
}

keep_mcl() {
    mv build/external build/mclproject-prefix /tmp
    rm -rf build && mkdir build
    mv /tmp/external /tmp/mclproject-prefix build
}

rebuild() {
    rm -rf build && mkdir build
}

build() {
    local hw
    if [ -z $HW ]; then
        hw=
    else
        hw="-DHW=1"
    fi
    local arch=$(uname -m)
    local comp
    if [[ "$arch" == arm* ]] || [[ "$arch" == aarch* ]]; then
        comp="-DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++"
    else
        comp=
    fi
    cd build && cmake $comp -DCMAKE_BUILD_TYPE=DEBUG -DALL=1 $hw .. && make VERBOSE=1
}

if [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
    usage
    exit
fi

if [ "$1" == "--keep-mcl" ] || [ "$2" == "--keep-mcl" ]; then
    KEEPMCL=1
fi
if [ "$1" == "--hw" ] || [ "$2" == "--hw" ]; then
    HW=1
fi

if [ -n "$KEEPMCL" ]; then
    keep_mcl
else
    rebuild
fi
build
