#!/usr/bin/env bash

gcc -g -o sha_hw sha_hw.c -L/home/xilinx/openssl-3.0.2 -I../../src/hw -L../../build/lib -lcrypto -lpynq -lgroupsig -lcma -lpthread
