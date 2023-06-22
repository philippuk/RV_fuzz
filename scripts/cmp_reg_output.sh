#!/bin/bash

clang++ -g --std=c++17 -ISpike/include/ -LSpike/lib disasm.cpp -lriscv -o disasm

clang++ --std=c++11 cmp_reg_output.cpp -o cmp_reg_output

read_reg()
{
  echo "Reading file: $1"

  #filtering testcases already known to be defective
  tmp_file=$(mktemp)
  ./disasm -o "$1" 2>&1 | tee -a "$tmp_file"
  filter1=$(grep -F ".s" "$tmp_file")
  filter2=$(grep "fclass" "$tmp_file")
  filter3=$(grep "sc.w" "$tmp_file")
  rm "$tmp_file"
  if [ -n "$filter1" ]; then  
    echo "Filtered : .s instructions"
    return 0
  elif [ -n "$filter2" ]; then 
    echo "Filtered : fclass instructions"
    return 0
  elif [ -n "$filter3" ]; then 
    echo "Filtered : sc.w instructions"
    return 0
  fi
  
  echo "Running Spike..."
  ./read_spike_reg.sh
  echo "Running Forvis..."
  ./read_forvis_reg.sh
  echo "Running RVEMU..."
  ./read_rvemu_reg.sh
  echo "Running Sail..."
  ./read_sail_reg.sh
  echo "Comparing output..."
  ./cmp_reg_output

  echo
}

while getopts ":fd" opt; do
  case $opt in
    d)
      shift $((OPTIND - 1))
      dir="$1"
      counter=0
      for file in "$dir"/*
      do
        if [ -f "$file" ]; then
          read_reg "$file"
        fi
        if (( counter % 100 == 0 )); then
          echo "Testcase processed: $counter" >&2
        fi
        counter=$((counter+1))
      done
      ;;
    f)
      shift $((OPTIND - 1))
      read_reg "$1"
      ;;
    \?)
      echo "Invalid option: -$OPTARG"
      ;;
  esac
done


