#!/bin/bash

clang++ -g --std=c++17 -ISpike/include/ -LSpike/lib disasm.cpp -lriscv -o disasm

log_file="disasm.log"

> "$log_file"

# Set the directory to read files from
dir="corpus_$1"

# Loop through each file in the folder
for file in "$dir"/*; do
    if [[ -f "$file" ]]; then
        echo "Processing file: $file"
        ./disasm -n "$file" | tail -n +2 | awk '{print $1}' >> $log_file
    fi
done

uniq_instr_file="unique.log"

tmp_file=$(mktemp)

sort "$log_file" | uniq -c > "$uniq_instr_file"

# Filter pseudoinstructions
original=("addi"
    "addiw"
    "sltu"
    "bge"
    "jal"
    "jalr"
    "csrrs"
    "csrrw"
    "csrrs"
    "csrrc"
    "csrrwi"
    "csrrsi"
    "csrrci"
    "blt"
    "bne"
    "beq"
)

synonym=("nop"
    "sext\.w"
    "snez"
    "bgez"
    "j"
    "jr"
    "csrr"
    "csrw"
    "csrs"
    "csrc"
    "csrwi"
    "csrsi"
    "csrci"
    "bltz"
    "bnez"
    "beqz"
)

unknown=("li"
    "zext\.w"
    "unimp"
)

for ((i=0; i<${#original[@]}; i++)); do
    output=$(grep -w "${original[$i]}" "$uniq_instr_file")
    if [ -n "$output" ]; then
        syn="${synonym[$i]}"
        grep -v -w "$syn" "$uniq_instr_file" > "$tmp_file"
        mv "$tmp_file" "$uniq_instr_file"
    fi
done

for instr in "${unknown[@]}"; do
    grep -v -w "$instr" "$uniq_instr_file" > "$tmp_file"
    mv "$tmp_file" "$uniq_instr_file"
done

wc -l "$uniq_instr_file" 