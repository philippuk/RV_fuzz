#!/bin/bash

# Compile the binary 

riscv64-unknown-elf-g++ -Wl,-Ttext=0x80000000 -march=rv64imafd spike.s -o spike_input 2> /dev/null

# read the end pc value

end_pc=$(riscv64-unknown-elf-objdump --disassemble=main spike_input | grep "nop" | cut -d: -f1 | tail -n 1)

# replace the end pc value into the cmd txt

sed -e "1s/.*/until pc 0 ${end_pc// /}/" -i '' read_reg_cmd.txt

log_file="spike_reg_output.txt"

# simulate using spike

function run_cmd { 
    cmd="$1"; timeout=30;
    ( 
        eval "$cmd" &
        child=$!
        trap -- "" SIGTERM 
        (       
                sleep $timeout
                kill $child 2> /dev/null 
        ) &     
        wait $child
    )
}

function run_spike {
    spike -d --debug-cmd=read_reg_cmd.txt pk spike_input 2> spike_reg_output.txt
}

run_cmd "run_spike"

return_code=$?

if [ $return_code -eq 255 ]; then
    echo "SPIKE: Did not reach the end of program."
    spike -d --debug-cmd=read_reg_cmd.txt pk spike_input > "$log_file"
    # Read the content of the file into an array of lines
    IFS=$'\n' read -d '' -r -a lines < "$log_file"

    > "$log_file"

    # Iterate over the lines
    for i in "${!lines[@]}"; do
        line="${lines[i]}"

        if (( i >= 1 && i <= 8 )); then
            index=(3 23 43 63)
            for ind in "${index[@]}"; do
                substring="${line:ind:16}"
                echo "$substring" >> "$log_file"
            done
        fi
    done

    # Create a temporary file to store the modified content
    tmp_file=$(mktemp)

    tail -n 31 "$log_file" > "$tmp_file"

    # Overwrite the original file with the modified content
    mv "$tmp_file" "$log_file"
elif [ $return_code != 0 ]; then
    echo "SPIKE: Crash / Timeout"
fi
