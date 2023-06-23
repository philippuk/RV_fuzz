#!/bin/bash

riscv64-unknown-elf-gcc -Wl,-Ttext=0x80000000 -nostdlib -o rvemu_input rvemu.s 2> /dev/null

riscv64-unknown-elf-objcopy -O binary rvemu_input rvemu_input.text

log_file="rvemu_reg_output.txt"

./rvemu/target/release/rvemu-cli -k rvemu_input.text > "$log_file"

return_code=$?

if [ $return_code != 0 ]; then
    echo "RVEMU: Crash / Timeout"
fi

mcause=$(grep "mcause" "$log_file" | awk -F'=' '{print $2}' | awk '{print $1}')

if [ "$mcause" == "0x1" ]; then
    echo "RVEMU: Did not reach the end of program."
fi

# Read the content of the file into an array of lines
IFS=$'\n' read -d '' -r -a lines < "$log_file"

> "$log_file"

# Iterate over the lines
for line in "${lines[@]}"; do
    for (( i=0; i<${#line}; i++ )); do
    # Check if the character is an equal sign
    if [[ "${line:i:1}" == "=" ]]; then
        substring="${line:i+1:18}"
        echo "$substring" | sed -e 's/^[[:space:]]*//' >> "$log_file"
    fi
    done
done