#!/bin/bash

export PATH=/usr/local/opt/llvm/bin:$PATH

export LLVM_PROFILE_FILE="isa.profraw"

clang++ -std=c++17 -ISpike_cov/include -LSpike_cov/lib -fprofile-instr-generate -fcoverage-mapping -lriscv isa_test_coverage.cpp -o isa_test_coverage

./isa_test_coverage isa-test/* 

llvm-profdata merge -sparse isa.profraw -o isa.profdata

llvm-cov report \
    -object Spike_cov/lib/libriscv.so \
    -object Spike_cov/lib/libdisasm.a \
    -object Spike_cov/lib/libfesvr.a \
    -object Spike_cov/lib/libcustomext.so \
    -object Spike_cov/lib/libsoftfloat.so \
    ./isa_test_coverage -instr-profile isa.profdata > isa_test_coverage.txt

llvm-cov export -format=lcov \
    -object Spike_cov/lib/libriscv.so \
    -object Spike_cov/lib/libdisasm.a \
    -object Spike_cov/lib/libfesvr.a \
    -object Spike_cov/lib/libcustomext.so \
    -object Spike_cov/lib/libsoftfloat.so \
    ./isa_test_coverage -instr-profile isa.profdata > isa_test_coverage.lcov
