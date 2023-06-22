#include <string>
#include <cstdint>
#include <iostream>
#include <stdlib.h>
#include <fstream>
#include <sys/wait.h>
#include <random>
#include <algorithm>

#include "instructions.hpp"
#include "utilities.hpp"

std::string temp_asm = init_asm();
size_t nop_pos = temp_asm.find("#APP") + 4;
std::string bin_path = "/Users/ppuk/Downloads/FYP_fuzzing/template";

// The fuzz target.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) 
{
  int ret = compile_data(Data, Size, temp_asm, nop_pos);

  //Logging compilation results
  std::ofstream compileRes("compileRes.txt", std::ofstream::app);
  compileRes << ret << std::endl;
  compileRes.close();

  //Reject input the the compilation fails
  if(ret == 256)
  {
    return -1;
  }

  //Spike simulation configuration
  run_spike(bin_path);

  return 0;
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                                          size_t MaxSize, unsigned int Seed) {

  srand(Seed);

  std::mt19937 gen(Seed); // seed the generator
  std::uniform_int_distribution<> distr(0, 3); 

  int mutation = distr(gen);

  const size_t array_size = Size / sizeof(uint32_t);
  const size_t max_array_size = MaxSize / sizeof(uint32_t);
  uint32_t* data_as_instr = reinterpret_cast<uint32_t *>(Data);

  if (array_size == 0)
  {
    //Generate Instruction when Size allows
    if (max_array_size >= 1)
    {
      data_as_instr[0] = genInstr();
      return sizeof(uint32_t);
    }
  }

  /*
    Swap to default case when:
    - Add new instruction that would exceed the maxsize
    - Delete an instruction causing the instruction size to be zero
  */
  if ((mutation == 2) && (array_size + 1 > max_array_size))
  {
    mutation = 0;
  }
  else if ((mutation == 3) && (array_size <= 1))
  {
    mutation = 0;
  }
  
  int ind = rangeSelector(0, array_size-1);

  switch(mutation) {
    case 0:
    {
      //Mutate one of the instrutions opcode
      uint8_t opcode = static_cast<uint8_t> (data_as_instr[ind] & 0x0000007F);
      opcode = mutate_opcode_v2(opcode);
      data_as_instr[ind] = (data_as_instr[ind] & 0xFFFFFF80)| (uint32_t) opcode;
      return Size;
    }
    case 1:
    {
      //Mutate one of the instrutions other than opcode
      uint32_t imm = rangeSelector(0,0x1FFFFFF);
      data_as_instr[ind] = (data_as_instr[ind] & 0x0000007F)| (imm << 7) ;
      return Size;
    }
    case 2:
    {
      //Add new command if MaxSize allowed
      std::vector<uint32_t> new_data;
      for (int i = 0; i < array_size ; ++i)
      {
        if (ind == i)
          new_data.push_back(genInstr());
        new_data.push_back(data_as_instr[i]);
      }
      for (int i = 0; i < array_size+1 ; ++i)
      {
        data_as_instr[i] = new_data[i];
      } 
      return Size + sizeof(uint32_t);
    }
    case 3:
    {
      std::vector<uint32_t> new_data;
      //Delete one of the instructions
      for (int i = 0; i < array_size ; ++i)
      {
        if (ind == i) 
          continue;
        new_data.push_back(data_as_instr[i]);
      }
      for (int i = 0; i < new_data.size() ; ++i)
      {
        data_as_instr[i] = new_data[i];
      } 
      return Size - sizeof(uint32_t);
    }
    default:
      return Size;
  }
}
    
