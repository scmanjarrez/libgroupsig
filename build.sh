#!/bin/bash

usage() {
    echo "Usage: $0 [--keep-mcl]"
    echo "  --keep-mcl: do not rebuild mcl"
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
    cd build && cmake -DCMAKE_BUILD_TYPE=DEBUG -DALL=1 .. && make VERBOSE=1
}

if [ $# -eq 1 ]; then
    if [ "$1" != "--keep-mcl" ] \
           && [ "$1" != "-h" ] && [ "$1" != "--help" ]; then
        usage
        exit 1
    elif [ "$1" == "--keep-mcl" ]; then
        KEEPMCL=1
    else
        usage
        exit
    fi
fi

if [ -n "$KEEPMCL" ]; then
    keep_mcl
else
    rebuild
fi
build
