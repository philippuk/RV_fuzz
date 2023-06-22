#include <string>
#include <cstdint>
#include <iostream>
#include <stdlib.h>
#include <fstream>
#include <vector>

#include <riscv/sim.h>
#include <fesvr/config.h>
#include <riscv/disasm.h>
#include <riscv/extension.h>
#include <vector>

const char* isa = "RV64IMAFDC";
isa_parser_t isa_parser(isa, "MSU");
disassembler_t* disassembler = new disassembler_t(&isa_parser);
std::vector<uint32_t> bytes;

int main(int argc, char *argv[])
{
  std::vector<std::string> software {"spike", "forvis", "rvemu", "sail"};
  std::string asm_seq;

  FILE *f = fopen(argv[2], "r");
  assert(f);
  fseek(f, 0, SEEK_END);
  size_t len = ftell(f);
  fseek(f, 0, SEEK_SET);
  unsigned char *buf = (unsigned char*)malloc(len);
  size_t n_read = fread(buf, 1, len, f);
  fclose(f);
  assert(n_read == len);

  const size_t array_size = len / sizeof(uint32_t);
    
  const uint32_t* data_as_instr = reinterpret_cast<const uint32_t *>(buf);

  std::cout<<"Asm: "<<std::endl;

  int label_count = 0;

  for (size_t i = 0; i < array_size; ++i)
  {
    std::string dis = disassembler->disassemble((uint64_t)data_as_instr[i]);

    //Dealing pc relative instructions
    if ((dis.find("pc +") != std::string::npos) || (dis.find("pc -") != std::string::npos))
    {
      size_t pc_num_pos = dis.find("pc");
      std::string pc_label = "pc" + std::to_string(label_count) + dis.substr(pc_num_pos + 2);
      dis.replace(dis.begin()+pc_num_pos, dis.end(), pc_label);
      std::string label = "\npc" + std::to_string(label_count) + ":";
      asm_seq += label; 
      label_count++;
    }

    std::cout << dis << std::endl;
    bytes.push_back(data_as_instr[i]);
    asm_seq += "\n\t"+dis; 
  }

  free(buf);
  //Debug purpose
  // std::cout<<std::endl<<"Hex: "<<std::endl;

  // for (auto byte : bytes)
  // {
  //   std::cout << std::hex <<  std::setw(8) << std::setfill('0') << byte << std::endl;
  // }

  //Exit early if not for fuzzing by proxy
  if (strcmp(argv[1], "-o") != 0)
  {
    return 0;
  }

  for (std::string app: software)
  {
    int nop_pos;
    std::string assembly;
    std::string template_name = "/Users/ppuk/Downloads/FYP_fuzzing/asm_templates/" + app + "_template.s";
    std::ifstream asm_template(template_name);
    std::string line;
    while (!asm_template.eof()) 
    { 
      getline(asm_template, line);
      assembly += line + "\n";
    }
    
    nop_pos = assembly.find("#APP") + 4;
    assembly.insert(nop_pos, asm_seq); 
    asm_template.close();

    std::string input_name = app + ".s";
    std::ofstream outFile(input_name);
    outFile << assembly << std::endl; 
    outFile.close(); 
  }  

  return 0;
}
