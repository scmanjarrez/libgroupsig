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
    if [ -z $HW ]; then
        local hw=
    else
        local hw="-DHW=1"
    fi
    cd build && cmake -DCMAKE_BUILD_TYPE=DEBUG -DALL=1 $hw .. && make VERBOSE=1
}

if [ $# -gt 1 ]; then
    if [ "$1" != "--keep-mcl" ] && [ "$1" != "--hw" ] \
           && [ "$1" != "-h" ] && [ "$1" != "--help" ]; then
        usage
        exit 1
    fi
    if [ "$1" == "--keep-mcl" ] || [ "$2" == "--keep-mcl" ]; then
        KEEPMCL=1
    fi
    if [ "$1" == "--hw" ] || [ "$2" == "--hw" ]; then
        HW=1
    fi
fi

if [ -n "$KEEPMCL" ]; then
    keep_mcl
else
    rebuild
fi
build
