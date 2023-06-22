#include <cstdlib>
#include <random>
#include <vector>
#include <bitset>

enum opcode_type { R, I, S, B, U, J, unknown};
 
template <typename T>
std::vector<T> operator+(std::vector<T> const &x, std::vector<T> const &y)
{
    std::vector<T> vec;
    vec.reserve(x.size() + y.size());
    vec.insert(vec.end(), x.begin(), x.end());
    vec.insert(vec.end(), y.begin(), y.end());
    return vec;
}

std::vector<uint8_t> U_opcode {0b0110111, 0b0010111};
std::vector<uint8_t> B_opcode {0b1100011};
std::vector<uint8_t> I_opcode {0b0010011, 0b0000011, 0b1100111, 0b0011011, 0b0000111, 0b1110011, 0b0001111};
std::vector<uint8_t> J_opcode {0b1101111};
std::vector<uint8_t> R_opcode {0b0110011, 0b0111011, 0b0101111, 0b1000011, 0b1000111, 
                                0b1001011, 0b1001111, 0b1010011};
std::vector<uint8_t> S_opcode {0b0100011, 0b0100111};
std::vector<uint8_t> all_opcode = U_opcode + B_opcode + I_opcode + J_opcode + R_opcode + S_opcode;

bool opcode_exists(std::vector<uint8_t> vec, uint8_t opcode)
{
    for (size_t i = 0; i < vec.size(); i++) 
    {
        if (vec[i] == opcode) 
        {
            return true;
        }
    }
    return false;
}

int opcode_ind(std::vector<uint8_t> vec, uint8_t opcode)
{
    for (int i = 0; i < vec.size(); i++) 
    {
        if (vec[i] == opcode) 
        {
            return i;
        }
    }
    return -1;
}

int rangeSelector(int min, int max)
{
    return min + (std::rand() % ( max - min + 1 ));
}

int arrSelector(const std::vector<int>& arr)
{
    int ind = rangeSelector(0, arr.size()-1);
    return arr[ind];
}

int arrSelector_prob(const std::vector<int>& arr)
{
    int sum = 0;
    for (int i : arr)
    {
        sum += i;
    }
    int num = rangeSelector(0, sum-1);

    int cumsum = 0;

    for (int i = 0; i < arr.size(); ++i)
    {
        cumsum += arr[i];
        if (num < cumsum)
        {
            return i;
        }
    } 
    std::cerr<< "Prob Selector error"<<std::endl;
    return 0;
}

opcode_type decode(uint32_t instr)
{
    int opcode = instr & 0x0000007F; 
    if(opcode_exists(U_opcode, opcode)) 
    {   
        return U;
    }
    else if(opcode_exists(I_opcode, opcode))
    {  
        return I;
    }
    else if(opcode_exists(B_opcode, opcode))
    {  
        return B;
    }
    else if(opcode_exists(R_opcode, opcode))
    {  
        return R;
    }
    else if(opcode_exists(J_opcode, opcode))
    {  
        return J;
    }
    else if(opcode_exists(S_opcode, opcode))
    {  
        return S;
    }
    else
    {
        return unknown;
    }
}

//replace opcode across all opcodes
uint8_t mutate_opcode_v2(uint8_t opcode)
{
    uint8_t sel_opcode_ind;

    do 
    {
        sel_opcode_ind = rangeSelector(0,all_opcode.size()-1);
    }
    while (all_opcode[sel_opcode_ind] == opcode);

    return all_opcode[sel_opcode_ind];
}

//replace opcode across the same type of instructions for U, I, R type instructions
uint8_t mutate_opcode_v3(uint8_t opcode, opcode_type instr_type)
{
    uint8_t sel_opcode_ind;
    std::vector<uint8_t> sel_opcode;

    if(instr_type == U)
    {
        sel_opcode = U_opcode;
    }
    else if (instr_type == I)
    {   
        sel_opcode = I_opcode;
    }
    else if (instr_type == R)
    {
        sel_opcode = R_opcode;
    }
    else if (instr_type == S)
    {
        sel_opcode = S_opcode;
    }
    else
    {
        //temporary measure against unrecognized instruction
        return mutate_opcode_v2(opcode);
    }

    do 
    {
        sel_opcode_ind = rangeSelector(0,sel_opcode.size()-1);
    }
    while (sel_opcode[sel_opcode_ind] == opcode);
    return sel_opcode[sel_opcode_ind];
}

int genReg()
{
    return rangeSelector(0,31);
}

int genReg64()
{
    return rangeSelector(0,63);
}

uint32_t genUInstr(uint8_t opcode)
{
    uint32_t imm = rangeSelector(0, 0xFFFFF);
    uint8_t rd = genReg();
    uint32_t res = (imm<<11) | ((uint32_t)rd<<7) | opcode ;
    return res;
}

uint32_t genUInstr()
{
    int index = rangeSelector(0, U_opcode.size()-1);
    uint8_t opcode = U_opcode[index];
    return genUInstr(opcode);
}

uint32_t genJInstr()
{
    int index = rangeSelector(0,1);
    uint32_t imm = rangeSelector(1, 5) * 4;
    uint8_t opcode = J_opcode[0];
    uint8_t rd = genReg();
    uint32_t res = (imm<<21) | ((uint32_t)rd<<7) | opcode ;
    return res;
}

uint32_t genIInstr(uint8_t opcode)
{
    int index = opcode_ind(I_opcode, opcode);
    uint8_t rd = genReg();
    uint8_t rs1 = genReg();
    uint32_t res;
    if (index == 0)
    {
        int funct3 = rangeSelector(0,7);
        if (funct3 == 1)
        {
            //SLLI
            uint8_t shamt = genReg64();
            res = ((uint32_t)shamt<<20) | ((uint32_t)rs1<<15) | ((uint32_t)funct3<<12) | ((uint32_t)rd<<7) | opcode;
        }
        else if (funct3 == 5)
        {
            //SRLI, SRAI
            uint8_t shamt = genReg64();
            int sel = rangeSelector(0,1);
            res = ((uint32_t)sel<<30)| ((uint32_t)shamt<<20) | ((uint32_t)rs1<<15) 
                | ((uint32_t)funct3<<12) | ((uint32_t)rd<<7) | opcode;
        }
        else
        {
            //ADDI, SLTI, SLTIU, XORI, ORI, ANDI
            uint16_t imm = rangeSelector(0,0xFFF);
            res = (imm<<20) | ((uint32_t)rs1<<15) | ((uint32_t)funct3<<12) | ((uint32_t)rd<<7) | opcode;
        }
    }
    else if (index == 1)
    {
        //LB, LH, LW, LBU, LHU, LD, LWU
        int funct3 = rangeSelector(0,6);
        uint16_t imm = rangeSelector(0,0xFFF);

        res = (imm<<20) | ((uint32_t)rs1<<15) | ((uint32_t)funct3<<12) | ((uint32_t)rd<<7) | opcode;
    }
    else if (index == 2)
    {
        //JALR
        uint16_t imm = rangeSelector(0,0xFFF);
        res = (imm<<20) | ((uint32_t)rs1<<15) | ((uint32_t)rd<<7) | opcode;
    }
    else if (index == 3)
    {
        //Choose between 0,1,5
        std::vector<int> funct3_arr {0,1,5};
        int funct3 = arrSelector(funct3_arr);
        if (funct3 == 1)
        {
            //SLLIW
            uint8_t funct3 = 1;
            uint8_t shamt = genReg();
            res = ((uint32_t)shamt<<20) | ((uint32_t)rs1<<15) | ((uint32_t)funct3<<12) | ((uint32_t)rd<<7) | opcode;
        }
        else if (funct3 == 5)
        {
            //SRLIW, SRAIW
            uint8_t funct3 = 5;
            uint8_t shamt = genReg();
            int sel = rangeSelector(0,1);
            res = ((uint32_t)sel<<30)| ((uint32_t)shamt<<20) | ((uint32_t)rs1<<15) 
                | ((uint32_t)funct3<<12) | ((uint32_t)rd<<7) | opcode;
        }
        else
        {
            //ADDIW
            uint16_t imm = rangeSelector(0,0xFFF);
            res = (imm<<20) | ((uint32_t)rs1<<15) | ((uint32_t)rd<<7) | opcode;
        }
    }
    else if (index == 4)
    {
        //FLW, FLD
        std::vector<int> funct3_arr {2,3};
        int funct3 = arrSelector(funct3_arr);
        uint16_t imm = rangeSelector(0,0xFFF);
        res = (imm<<20) | ((uint32_t)rs1<<15) | ((uint32_t)funct3<<12) | ((uint32_t)rd<<7) | opcode;
    }
    else if (index == 5)
    {
        //ECALL, EBREAK, CSR instructions
        std::vector<int> funct3_arr {0,1,2,3,5,6,7};
        int funct3 = arrSelector(funct3_arr);
        if (funct3 == 0)
        {
            uint16_t imm = rangeSelector(0,1);
            res = (imm<<20) | opcode;
        }
        else
        {
            uint16_t csr = rangeSelector(0,0xFFF);
            res = (csr<<20) | ((uint32_t)rs1<<15) | ((uint32_t)funct3<<12) | ((uint32_t)rd<<7) | opcode;
        }
    }
    else if (index == 6)
    {
        //FENCE, FENCE.I
        int funct3 = rangeSelector(0,1);
        uint16_t imm;
        if (funct3 == 0)
        {
            imm = 0xFF;
        }
        else
        {
            imm = 0;
        }
        res = (imm<<20) | ((uint32_t)funct3<<12) | opcode;
    }

    return res;
}

uint32_t genIInstr()
{
    static const std::vector<int> I_dist {9, 7, 1, 4, 2, 8, 2};
    int index = arrSelector_prob(I_dist);
    uint8_t opcode = I_opcode[index];
    return genIInstr(opcode);
}

uint32_t genRInstr(uint8_t opcode) 
{
    int index = opcode_ind(R_opcode, opcode);
    int funct7;
    int funct3;
    if (index < 2)
    {
        std::vector<int> funct7_arr {0,(1<<5),1};
        std::vector<int> funct3_arr {0,5};
        funct7 = arrSelector(funct7_arr);
        if ((index == 0) && (funct7 != (1<<5)))
        {
            std::vector<int> funct3_arr_app {1,2,3,4,6,7};
            funct3_arr = funct3_arr + funct3_arr_app;
        }
        else if ((index == 1) && (funct7 == 0))
        {
            std::vector<int> funct3_arr_app {1};
            funct3_arr = funct3_arr + funct3_arr_app;
        } 
        else if ((index == 1) && (funct7 == 1))
        {
            std::vector<int> funct3_arr_app {4, 6, 7};
            funct3_arr = funct3_arr + funct3_arr_app;
        }
        funct3 = arrSelector(funct3_arr);
    }
    else if (index == 2)
    {
        //RV32,64A
        std::vector<int> funct3_arr {0b010,0b011};
        funct3 = arrSelector(funct3_arr);
        std::vector<int> funct5_arr {0b00000, 0b00001, 0b00010, 0b00011,
                                    0b00100, 0b01000, 0b01100, 0b10000,
                                    0b10100, 0b11000, 0b11100};
        int funct5 = arrSelector(funct5_arr);
        int ar_rl = rangeSelector(0,3);
        funct7 = (funct5 << 2) | ar_rl;
    }
    else if ( (index > 2) && (index < 7))
    {
        //FMADD.S/D, FMSUB, FNMSUB, FNMADD
        int rs3 = genReg();
        funct3 = rangeSelector(0, 7);
        int funct2 = rangeSelector(0, 1);
        funct7 = (rs3 << 2) | funct2;
    }
    else if (index == 7)
    {
        std::vector<int> funct7_arr {0b0000000, 0b0000100, 0b0001000, 0b0001100,
                                    0b0101100, 0b0010000, 0b0010100, 0b1100000,
                                    0b1110000, 0b1010000, 0b1101000, 0b1111000,
                                    0b0100000};
        //switch between extension D and F
        int d_f = rangeSelector(0,1);
        int funct7_base = arrSelector(funct7_arr);
        funct7 = funct7_base | d_f;
        if ((funct7_base == 0b0010000) || (funct7_base == 0b1010000))
        {
            funct3 = rangeSelector(0,2);
        }
        else if ((funct7_base == 0b0010100) || (funct7_base == 0b1110000))
        {
            funct3 = rangeSelector(0,1);
        }
        else if (funct7_base == 0b1111000)
        {
            funct3 = 0;
        }
        else
        {
            funct3 = rangeSelector(0,7);
        }
    }
    
    uint8_t rd = genReg();
    uint8_t rs1 = genReg();
    uint8_t rs2 = genReg();
    if ((index == 2) && ((funct7>>2) == 2))
    {
        //LR.W, LR.D
        rs2 = 0;
    }
    else if (index == 7)
    {
        if ((funct7 == 0b0101100) || (funct7 == 0b1110000) || (funct7 == 0b1111000)
            || (funct7 == 0b0100001) || (funct7 == 0b0101101) || (funct7 == 0b1110001)
            || (funct7 == 0b1111001))
        {
            rs2 = 0;
        }
        else if ((funct7 == 0b1100000) || (funct7 == 0b1101000) || 
                (funct7 == 0b1100001) || (funct7 == 0b1101001))
        {
            rs2 = rangeSelector(0,3);
        }
        else if (funct7 == 0b0100000)
        {
            rs2 = 1;
        }
    }
    uint32_t res =  ((uint32_t)funct7<<25) | ((uint32_t)rs2<<20) 
                    | ((uint32_t)rs1<<15) | ((uint32_t)funct3<<12) | ((uint32_t)rd<<7) | opcode;
    return res;
}

uint32_t genRInstr()
{
    static const std::vector<int> R_dist {21, 10, 22, 2, 2, 2, 2, 50};
    int index = arrSelector_prob(R_dist);
    uint8_t opcode = R_opcode[index];
    return genRInstr(opcode);
}

uint32_t genSInstr(uint8_t opcode)
{
    int index = opcode_ind(S_opcode, opcode);
    uint8_t rs1 = genReg();
    uint8_t rs2 = genReg();
    uint8_t funct3 = rangeSelector(0,3);
    if (index == 1)
    {
        //FSW, FSD
        std::vector<int> funct3_arr {2,3};
        funct3 = arrSelector(funct3_arr);
    }
    uint8_t imm1 = rangeSelector(0,0x1F);
    uint8_t imm2 = rangeSelector(0,0x7F);
    uint32_t res =  ((uint32_t)imm2<<25) | ((uint32_t)rs2<<20) 
                    | ((uint32_t)rs1<<15) | ((uint32_t)funct3<<12) | ((uint32_t)imm1<<7) | opcode;
    return res;
}

uint32_t genSInstr()
{
    int index = rangeSelector(0, S_opcode.size()-1);
    uint8_t opcode = S_opcode[index];
    return genSInstr(opcode);
}

uint32_t genBInstr()
{
    uint8_t rs1 = genReg();
    uint8_t rs2 = genReg();
    std::vector<int> funct3_arr {0, 1, 4, 5, 6, 7};
    int funct3 = arrSelector(funct3_arr);
    uint8_t imm1 = rangeSelector(1,5) * 4;
    uint8_t opcode = B_opcode[0];

    uint32_t res =  ((uint32_t)rs2<<20) | ((uint32_t)rs1<<15) | ((uint32_t)funct3<<12) | ((uint32_t)imm1<<8) | opcode;
    return res;
}

uint32_t genInstr()
{
    int num = rangeSelector(0, 158);
    if (num == 0)
    {
        return genJInstr();
    }
    else if ((num > 0) && (num <= 6))
    {
        return genBInstr();
    }
    else if ((num > 6) && (num <= 12))
    {
        return genSInstr();
    }
    else if ((num > 12) && (num <= 45))
    {
        return genIInstr();
    }
    else if ((num > 45) && (num <= 47))
    {
        return genUInstr();
    }
    else
    {
        return genRInstr();
    }
}

uint32_t mutate_imm(uint32_t instr, opcode_type instr_type)
{
    uint8_t opcode = static_cast<uint8_t> (instr & 0x0000007F); 
    if (instr_type == R)
    {
        return genRInstr(opcode);
    }
    else if (instr_type == I)
    {
        return genIInstr(opcode);
    }
    else if (instr_type == S)
    {
        return genSInstr(opcode);
    }
    else if (instr_type == B)
    {
        return genBInstr();
    }
    else if (instr_type == U)
    {
        return genUInstr(opcode);
    }
    else if (instr_type == J)
    {
        return genJInstr();
    }
    else
    {
        std::cerr << "Unrecognized instr type: " << instr_type << std::endl;
        exit(1);
    }
}


