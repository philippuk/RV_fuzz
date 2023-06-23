#!/bin/bash

riscv64-unknown-elf-gcc -Wl,-Ttext=0x80000000 -nostdlib -o sail_input sail.s 2> /dev/null

# Define the log file path
log_file="sail.log"

# Run your program and redirect the output to a file
./sail-riscv/c_emulator/riscv_sim_RV64 sail_input > "$log_file" 2>&1 &

# Get the process ID (PID) of your_program
pid=$!

# Continuously monitor the output file
while : ; do
  # Check if the specific word is found in the log file
  executed_instr=$(grep -o '\[[0-9]\+\]' sail.log | sed 's/\[//;s/\]//' | tail -n 1)
  if grep -q "trapping" "$log_file"; then
    echo "SAIL: Stopping program execution."
    kill $pid
    break
  elif [ $(($executed_instr)) -gt 10000 ] && [ -n "$executed_instr" ]; then
    echo "SAIL: Exceed execution limit. Stopping program execution."
    kill $pid 
    break
  fi
  sleep 1  # Adjust the sleep duration as needed
done

return_code=$?

if [ $return_code != 0 ]; then
    echo "SAIL: Crash / Timeout"
fi

cut_file()
{
  # Create a temporary file to store the modified content
  tmp_file=$(mktemp)

  # Copy lines up to the last occurrence of "c.nop" to the temporary file
  head -n "$1" "$log_file" > "$tmp_file"

  # Overwrite the original file with the modified content
  mv "$tmp_file" "$log_file"
}

last_line_number=$(($(grep -n '\[[0-9]*\]' "$log_file" | cut -d: -f1 | tail -n 1)+20))

cut_file $last_line_number

# Find the line number of the last occurrence of "c.nop"
last_line_number=$(grep -n "c.nop" "$log_file" | tail -1 | cut -d ":" -f 1)

if [[ -z "$last_line_number" ]]; then
  echo "SAIL: Did not reach the end of program."
  echo $(grep '\[[0-9]*\]' "$log_file"| tail -1)
else
  cut_file $last_line_number
fi

regs=("x1" "x2" "x3" "x4" "x5" "x6" "x7" "x8" "x9" "x10"
      "x11" "x12" "x13" "x14" "x15" "x16" "x17" "x18" "x19" "x20"
      "x21" "x22" "x23" "x24" "x25" "x26" "x27" "x28" "x29" "x30"
      "x31" "f0" "f1" "f2" "f3" "f4" "f5" "f6" "f7" "f8" "f9" "f10"
      "f11" "f12" "f13" "f14" "f15" "f16" "f17" "f18" "f19" "f20"
      "f21" "f22" "f23" "f24" "f25" "f26" "f27" "f28" "f29" "f30"
      "f31")

> sail_reg_output.txt

for reg in "${regs[@]}"; do
  output=$(grep "$reg <-" "$log_file" | tail -1 | cut -d ":" -f 1) 
  echo $output >> sail_reg_output.txt
done