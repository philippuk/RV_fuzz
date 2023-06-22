#include <string>
#include <cstdint>
#include <iostream>
#include <stdlib.h>
#include <fstream>
#include <vector>
#include <iomanip>
#include <cmath>

using namespace std;

bool check_empty(ifstream& pFile, string prog)
{
    bool empty = (pFile.peek() == ifstream::traits_type::eof());
    if (empty)
    {
        cout << prog << ": Empty log file" << endl; 
    }
    return empty;
}

bool parse_sail(vector<uint64_t> &reg, vector<uint64_t> &freg)
{
    ifstream inFile("sail_reg_output.txt");
    string line;
    int line_count = 1;
    if (check_empty(inFile, "SAIL"))
        return false;
    while (!inFile.eof()) 
    { 
        if (line_count > 63)
            break;
        getline(inFile, line);
        if (line_count < 32)
        {
            line = line.substr(line.find("0x"));
            reg.push_back(stoull(line, nullptr, 16));
        }
        else
        { 
            if (line.empty())
            {
                freg.push_back(0);
            }
            else
            {
                line = line.substr(line.find("0x"));
                freg.push_back(stoull(line, nullptr, 16));
            }
        }
        line_count++;
    }
    inFile.close();
    return true;
}

bool parse_spike(vector<uint64_t> &reg, vector<float> &freg)
{
    ifstream inFile("spike_reg_output.txt");
    string line;
    int line_count = 1;
    if(check_empty(inFile, "SPIKE"))
        return false;
    while (!inFile.eof()) 
    { 
        if (line_count > 63)
            break;
        getline(inFile, line);
        if (line_count < 32)
        {
            reg.push_back(stoull(line, nullptr, 16));
        }
        else
        {
            //handling spike error case where freg output is unknown
            if (line.empty())
            {
                for (int i = 0; i < 32; ++i)
                {
                    freg.push_back(0);
                }
            }
            else
            {
                freg.push_back(stof(line));
            }
            
        }  
        line_count++;
    }
    inFile.close();
    return true;
}

bool parse_rvemu(vector<uint64_t> &reg, vector<float> &freg)
{
    ifstream inFile("rvemu_reg_output.txt");
    string line;
    int line_count = 1;
    if(check_empty(inFile, "RVEMU"))
        return false;
    while (!inFile.eof()) 
    { 
        if (line_count > 64)
            break;
        getline(inFile, line);
        if (line_count < 33 && line_count != 1)
        {
            reg.push_back(stoull(line, nullptr, 16));
        }
        else if (line_count >= 33)
        {
            freg.push_back(stof(line));
        }
        line_count++;
    }
    inFile.close();
    return true;
}

bool parse_forvis(vector<uint64_t> &reg, vector<uint64_t> &freg)
{
    ifstream inFile("forvis_reg_output.txt");
    string line;
    int line_count = 1;
    if(check_empty(inFile, "FORVIS"))
        return false;
    while (!inFile.eof()) 
    { 
        if (line_count > 64)
            break;
        getline(inFile, line);
        line.erase(remove(line.begin(), line.end(), '_'), line.end());
        line.erase(remove(line.begin(), line.end(), '.'), line.end());
        if (line_count < 33 && line_count != 1)
        {
            reg.push_back(stoull(line, nullptr, 16));
        }
        else if (line_count >= 33)
        {
            freg.push_back(stoull(line, nullptr, 16));
        }
        line_count++;
    }
    inFile.close();
    return true;
}

template<typename T> void printElement(T t, const int& width)
{
    cout << left << setw(width) << setfill(' ') << t;
}

template<typename T> void printhexElement(T t, const int& width)
{
    cout << left << setw(width) << setfill(' ') << hex << t;
}

int main()
{
    vector<uint64_t> spike_reg, rvemu_reg, forvis_reg, sail_reg, sail_freg, forvis_freg;
    vector<float> spike_freg, rvemu_freg;
    vector<string> reg_names;
    reg_names = { "x1/ra", "x2/sp", "x3/gp", "x4/tp", "x5/t0", "x6/t1", "x7/t2", "x8/s0/fp", "x9/s1", "x10/a0",
      "x11/a1", "x12/a2", "x13/a3", "x14/a4", "x15/a5", "x16/a6", "x17/a7", "x18/s2", "x19/s3", "x20/s4",
      "x21/s5", "x22/s6", "x23/s7", "x24/s8", "x25/s9", "x26/s10", "x27/s11", "x28/t3", "x29/t4", "x30/t5",
      "x31/t6"
    };

    vector<string> freg_names;
    freg_names = { "f0/ft0", "f1/ft1", "f2/ft2", "f3/ft3", "f4/ft4", "f5/ft5", "f6/ft6", "f7/ft7", "f8/fs0", "f9/fs1", "f10/fa0",
      "f11/fa1", "f12/fa2", "f13/fa3", "f14/fa4", "f15/fa5", "f16/fa6", "f17/fa7", "f18/fs2", "f19/fs3", "f20/fs4",
      "f21/fs5", "f22/fs6", "f23/fs7", "f24/fs8", "f25/fs9", "f26/fs10", "f27/fs11", "f28/ft8", "f29/ft9", "f30/ft10",
      "f31/ft11"  
    };

    //parse the register values
    if (! ( parse_spike(spike_reg, spike_freg) &&
            parse_rvemu(rvemu_reg, rvemu_freg) &&
            parse_forvis(forvis_reg, forvis_freg) &&
            parse_sail(sail_reg, sail_freg)))
    {
        cout << "Parse failure: No Comparision is made" << endl;
        return 0;
    }

    cout << "Difference of register values:" << endl;

    const int nameWidth     = 10;
    const int numWidth      = 18;
    int diff_count = 0;

    printElement("Reg_name", nameWidth);
    printElement("Spike", numWidth);
    printElement("RVEMU", numWidth);
    printElement("FORVIS", numWidth);
    printElement("SAIL", numWidth);
    cout<< endl;

    //compare the general register value
    for (int i = 0; i < 31; ++i)
    {
        uint64_t spike = spike_reg[i];
        uint64_t rvemu = rvemu_reg[i];
        uint64_t forvis = forvis_reg[i];
        uint64_t sail = sail_reg[i];

        if (!(spike == rvemu && spike == forvis && spike == sail))
        {
            printElement(reg_names[i], nameWidth);
            printhexElement(spike, numWidth);
            printhexElement(rvemu, numWidth);
            printhexElement(forvis, numWidth);
            printhexElement(sail, numWidth);
            cout<< endl;
            diff_count++;
        }
    }

    cout << "----------------------------------------" << endl;

    //compare the floating point register value

    cout << "Difference of floating point register values:" << endl;

    printElement("Reg_name", nameWidth);
    printElement("Spike", numWidth);
    printElement("RVEMU", numWidth);
    printElement("FORVIS", numWidth);
    printElement("SAIL", numWidth);
    cout<< endl;

    //compare the general register value
    for (int i = 0; i < 31; ++i)
    {
        float spike = spike_freg[i];
        float rvemu = rvemu_freg[i];
        uint64_t forvis = forvis_freg[i];
        uint64_t sail = sail_freg[i];

        if (((spike != rvemu) || (forvis != sail))
                && !(isnan(spike) && isnan(rvemu)))
        {
            printElement(freg_names[i], nameWidth);
            printElement(spike, numWidth);
            printElement(rvemu, numWidth);
            printhexElement(forvis, numWidth);
            printhexElement(sail, numWidth);
            cout<< endl;
            diff_count++;
        }
    }

    cout << "----------------------------------------" << endl;

    if (diff_count > 0)
    {
        cout << "Difference found : " << diff_count << endl;
    }

}