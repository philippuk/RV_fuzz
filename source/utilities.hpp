#include <string>
#include <fstream>
#include <stdlib.h>

#include <riscv/sim.h>
#include <fesvr/config.h>
#include <riscv/disasm.h>
#include <riscv/extension.h>

//from riscv example code
static std::vector<std::pair<reg_t, mem_t*>> make_mems(const std::vector<mem_cfg_t> &layout)
{
  std::vector<std::pair<reg_t, mem_t*>> mems;
  mems.reserve(layout.size());
  for (const auto &cfg : layout) {
    mems.push_back(std::make_pair(cfg.get_base(), new mem_t(cfg.get_size())));
  }
  return mems;
}

//Disassembler configuration
const char* isa = "RV64IMAFDC";
const char* dtb = "/Users/ppuk/Downloads/FYP_fuzzing/dtb.txt";
isa_parser_t isa_parser(isa, "MSU");
disassembler_t* disassembler = new disassembler_t(&isa_parser);

std::string init_asm()
{
  //Fill the template assembly if empty
  std::ifstream inFile("/Users/ppuk/Downloads/FYP_fuzzing/asm_templates/template.s");
  std::string line;
  std::string temp_asm;
  while (!inFile.eof()) 
  { 
    getline(inFile, line);
    temp_asm += line + "\n";
  }
  inFile.close();
  return temp_asm;
}

void add_pc_label(std::string &dis, std::string &temp_asm, size_t &pos, int &label_count)
{
    if ( (dis.find("pc +") != std::string::npos) || (dis.find("pc -") != std::string::npos))
    {
        size_t pc_num_pos = dis.find("pc");
        std::string pc_label = "pc" + std::to_string(label_count) + dis.substr(pc_num_pos + 2);
        dis.replace(dis.begin()+pc_num_pos, dis.end(), pc_label);
        std::string label = "\npc" + std::to_string(label_count) + ":";
        temp_asm.insert(pos, label); 
        pos += label.length();
        label_count++;
    }
}

int compile_data(const uint8_t *Data, size_t Size, std::string temp_asm, size_t pos)
{
  const size_t array_size = Size / sizeof(uint32_t);
    
  const uint32_t* data_as_instr = reinterpret_cast<const uint32_t *>(Data);

  int label_count = 0;

  for (size_t i = 0; i < array_size; ++i)
  {
    std::string dis = disassembler->disassemble((uint64_t)data_as_instr[i]);

    if ((dis.find("c.") != std::string::npos) && (dis.find("sc.d") == std::string::npos))
      return 256;
  
    add_pc_label(dis, temp_asm, pos, label_count);

    temp_asm.insert(pos, "\n\t"+dis); 
    pos += (dis.length() + 2);
  }

  std::ofstream outFile("fuzzed_template.s");
  outFile << temp_asm << std::endl; 
  outFile.close(); 

  //Compile the binary
  int sys_ret = system("/usr/local/opt/riscv-gnu-toolchain/bin/riscv64-unknown-elf-g++ -march=rv64g fuzzed_template.s -o template");

  return sys_ret;
}

void run_spike(std::string path)
{
  std::vector<mem_cfg_t> mem_cfg { mem_cfg_t(0x80000000, 0x10000000) };
  std::vector<int> hartids = {0};
  cfg_t cfg(std::make_pair(0, 0),
            nullptr,
            "rv64imafdc",
            "MSU",
            "vlen:128,elen:64",
            false,
            endianness_little,
            16,
            mem_cfg,
            hartids,
            false,
            4);
  std::vector<std::pair<reg_t, abstract_device_t*>> plugin_devices;
    debug_module_config_t dm_config = {
    .progbufsize = 2,
    .max_sba_data_width = 0,
    .require_authentication = false,
    .abstract_rti = 0,
    .support_hasel = true,
    .support_abstract_csr_access = true,
    .support_abstract_fpr_access = true,
    .support_haltgroups = true,
    .support_impebreak = true
  };
  std::vector<std::pair<reg_t, mem_t*>> mems = make_mems(cfg.mem_layout());

  //Provide the binary name argument here
  std::vector<std::string> htif_args {"pk", path};

  sim_t sim(&cfg, false,
            mems,
            plugin_devices,
            htif_args,
            dm_config,
            nullptr,
            true,
            dtb,
            false,
            nullptr);

  //Run the simulation
  sim.run();
}

