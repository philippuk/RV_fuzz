#!/bin/bash

riscv64-unknown-elf-gcc -Wl,-Ttext=0x80000000 -nostdlib -o forvis_input forvis.s 2> /dev/null

# read the end pc value

end_pc=$(riscv64-unknown-elf-objdump --disassemble=main forvis_input | grep "nop" | cut -d: -f1 | tail -n 1 | sed -e 's/^[[:space:]]*//')

end_pc_hex="0x${end_pc}"

log_file="forvis_reg_output.txt"

./forvis_exe  --arch RV64IMAFDC  --tohost --verbosity=2  --n 10000 ./boot_ROM_RV64.hex32 ./forvis_input | grep -A 27 $end_pc_hex | head -n 28 > "$log_file"

return_code=$?

if [ $return_code != 0 ]; then
    echo "FORVIS: Crash / Timeout"
fi

if [ ! -s "$log_file" ]; then
    echo "FORVIS: Did not reach the end of program."
    ./forvis_exe  --arch RV64IMAFDC  --tohost --verbosity=2  --n 10000 ./boot_ROM_RV64.hex32 ./forvis_input | grep -A 27 'inum:[0-9]*' | tail -n 28 > "$log_file"
    echo $(head -n 1 "$log_file")
fi

# Read the content of the file into an array of lines
IFS=$'\n' read -d '' -r -a lines < "$log_file"

> "$log_file"

# Iterate over the lines
for i in "${!lines[@]}"; do
    line="${lines[i]}"

    if (( i >= 2 && i <= 9 )); then
        index=(11 34 58 82)
        for ind in "${index[@]}"; do
            substring="${line:ind:19}"
            echo "$substring" >> "$log_file"
        done
    fi

    if (( i >= 10 && i <= 17 )); then
        index=(11 39 67 95)
        for ind in "${index[@]}"; do
            substring="${line:ind:19}"
            echo "$substring" >> "$log_file"
        done
    fi
done