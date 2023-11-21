#!/bin/bash

usage() {
    echo "Usage: $0 [--keep-mcl][--hw]"
    echo "  --keep-mcl: do not rebuild mcl"
    echo "  --blake: compile using BLAKE hash function (SW). Default SHA2"
    echo "  --sha3: compile using SHA3 hash function (SW)"
    echo "  --hw/hw3: compile using HW SHA2/SHA3 hash functions"
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
    local blake
    if [ -z $BLAKE ]; then
        blake=""
    else
        blake="-DBLAKE=1"
    fi
    local sha3
    if [ -z $SHA3 ]; then
        sha3=""
    else
        sha3="-DSHA3=1"
    fi
    local hw
    if [ -z $HW ]; then
        hw=
    else
        hw="-DHW=1"
    fi
    if [ -z $HW3 ]; then
        hw3=
    else
        hw3="-DHW3=1"
    fi
    local arch=$(uname -m)
    local comp
    if [[ "$arch" == arm* ]] || [[ "$arch" == aarch* ]]; then
        comp="-DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++"
    else
        comp=
    fi
    cd build && cmake $comp -DCMAKE_BUILD_TYPE=DEBUG -DALL=1 $blake $sha3 $hw $hw3 .. \
        && make VERBOSE=1
}

if [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
    usage
    exit
fi

if [ "$1" == "--keep-mcl" ] || [ "$2" == "--keep-mcl" ]; then
    KEEPMCL=1
fi
if [ "$1" == "--blake" ] || [ "$2" == "--blake" ]; then
    BLAKE=1
fi
if [ "$1" == "--sha3" ] || [ "$2" == "--sha3" ]; then
    SHA3=1
fi
if [ "$1" == "--hw" ] || [ "$2" == "--hw" ]; then
    HW=1
fi
if [ "$1" == "--hw3" ] || [ "$2" == "--hw3" ]; then
    HW=1
    HW3=1
fi

if [ -n "$KEEPMCL" ]; then
    keep_mcl
else
    rebuild
fi
build
