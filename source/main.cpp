#include <string>
#include <cstdint>
#include <iostream>
#include <stdlib.h>
#include <fstream>

#include <riscv/sim.h>
#include <fesvr/config.h>
#include <riscv/disasm.h>
#include <riscv/extension.h>

//clang++ -g --std=c++17 -ISpike/include/ -LSpike/lib main.cpp -lriscv -o main

static std::vector<std::pair<reg_t, mem_t*>> make_mems(const std::vector<mem_cfg_t> &layout)
{
  std::vector<std::pair<reg_t, mem_t*>> mems;
  mems.reserve(layout.size());
  for (const auto &cfg : layout) {
    mems.push_back(std::make_pair(cfg.get_base(), new mem_t(cfg.get_size())));
  }
  return mems;
}

const char* isa = "RV64IMAFDC";
const char* dtb = "dtb.txt";
isa_parser_t isa_parser(isa, "MSU");
disassembler_t* disassembler = new disassembler_t(&isa_parser);
std::string temp_assembly;
size_t nop_pos;
std::ifstream inFile("/Users/ppuk/Downloads/FYP_fuzzing/asm_templates/template.s");

// The fuzz target.
int main()
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
  std::vector<std::string> htif_args {"pk", "/Users/ppuk/Downloads/FYP_fuzzing/template"};
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
  sim_t sim(&cfg, false,
            mems,
            plugin_devices,
            htif_args,
            dm_config,
            nullptr,
            true,
            //dtb,
            nullptr,
            false,
            nullptr);
  // sim.run();
  return 0;
}
