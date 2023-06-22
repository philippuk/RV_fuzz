#include <string>
#include <cstdint>
#include <iostream>
#include <stdlib.h>
#include <fstream>
#include <sys/wait.h>

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
