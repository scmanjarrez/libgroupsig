#!/bin/bash

rm -rf build && mkdir build
cd build && cmake -DCMAKE_BUILD_TYPE=DEBUG -DALL=1 .. && make VERBOSE=1
