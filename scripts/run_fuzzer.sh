#!/bin/bash

# Clear content of the compileRes

> compileRes.txt

# Compile and run the fuzzer

export PATH=/usr/local/opt/llvm/bin:$PATH

clang++ -g -fsanitize=fuzzer,address,undefined --std=c++17 -ISpike/include/ -LSpike/lib fuzzer_$1.cpp -lriscv -o fuzz_$1

START=`date +%s`

#Run the loop for 1 hour

while [ $(( $(date +%s) - 10800 )) -lt $START ]; do
    # Debug use
    #./fuzz_$1 -runs=20 -timeout=60 corpus_$1 > /dev/null

    ./fuzz_$1 -max_total_time=10800 -timeout=30 corpus_$1 > /dev/null

    TIMEOUT_FILENAME=`ls | grep timeout-`
    SLOW_FILENAME=`ls | grep slow-unit-`

    mv $TIMEOUT_FILENAME timeouts/$TIMEOUT_FILENAME
    mv $SLOW_FILENAME timeouts/$SLOW_FILENAME

    echo "Rerunning fuzzer..."
done

# Count the successful compilation and simulation

echo "Compilation statistics"

sort < compileRes.txt | uniq -c