#!/bin/bash

export PATH=/usr/local/opt/llvm/bin:$PATH

export LLVM_PROFILE_FILE="$1.profraw"

clang++ -std=c++17 -ISpike_cov/include -LSpike_cov/lib -fprofile-instr-generate -fcoverage-mapping -lriscv fuzzer_$1.cpp standAloneFuzzTargetMain.cpp -o $1_coverage

./$1_coverage corpus_$1/* 

llvm-profdata merge -sparse $1.profraw -o $1.profdata

llvm-cov report \
    -object Spike_cov/lib/libriscv.so \
    -object Spike_cov/lib/libdisasm.a \
    -object Spike_cov/lib/libfesvr.a \
    -object Spike_cov/lib/libcustomext.so \
    -object Spike_cov/lib/libsoftfloat.so \
    ./$1_coverage -instr-profile $1.profdata > $1_coverage.txt

llvm-cov export -format=lcov \
    -object Spike_cov/lib/libriscv.so \
    -object Spike_cov/lib/libdisasm.a \
    -object Spike_cov/lib/libfesvr.a \
    -object Spike_cov/lib/libcustomext.so \
    -object Spike_cov/lib/libsoftfloat.so \
    ./$1_coverage -instr-profile $1.profdata > $1_coverage.lcov
