import sys

class fileCoverageStats:
    def __init__(self, filename) -> None:
        self.filename = filename
        self.branch_hit = set()
        self.line_hit = set()

f1 = open(sys.argv[1],"r")
f2 = open(sys.argv[2],"r")
f3 = open(sys.argv[3],"r")

def parse_lcov(file):
    fileList = []
    currFile = fileCoverageStats("")
    for line in file:
        line = line.strip()
        if line[:2] == "SF":
            if line.find(".hpp") != -1 or line.find(".cpp") != -1:
                currFile = fileCoverageStats("")
            else:
                currFile = fileCoverageStats(line[3:])
        elif line[:2] == "DA":
            hit_count = int(line.split(',', 1)[1])
            line_num = int(line[line.find(':')+1:line.find(',')])
            if hit_count > 0: 
                currFile.line_hit.add(line_num)
        elif line[:4] == "BRDA":
            line_num = int(line[line.find(':')+1:line.find(',')])
            split_line = line.split(',',3)
            branch_num = split_line[2]
            hit_count = split_line[3]
            if hit_count == "-":
                continue
            elif int(hit_count) > 0:
                currFile.branch_hit.add((line_num,branch_num))
        elif line == "end_of_record" and currFile.filename != "":
            fileList.append(currFile)
    return fileList

f1_list = parse_lcov(f1)
f2_list = parse_lcov(f2)
f3_list = parse_lcov(f3)

f1.close()
f2.close()
f3.close()

print("filename," 
      "v1_branch_cov," 
      "v2_branch_cov,"
      "v3_branch_cov,"  
      "b_v1," 
      "b_v2,"
      "b_v3,"
      "b_v1_v2,"
      "b_v2_v3,"
      "b_v1_v3,"
      "b_v1_v2_v3,"
      "v1_line_cov," 
      "v2_line_cov,"
      "v3_line_cov,"  
      "l_v1," 
      "l_v2,"
      "l_v3,"
      "l_v1_v2,"
      "l_v2_v3,"
      "l_v1_v3,"
      "l_v1_v2_v3")

if (len(f1_list) != len(f2_list) != len(f3_list)):
    print("Unequal length of files")

for i in range(len(f1_list)):

    file1 = f1_list[i]
    file2 = f2_list[i]
    file3 = f3_list[i]
 
    if (file1.filename != file2.filename != file3.filename):
        print("Error: Filename does not match")
        continue

    v1_b = file1.branch_hit
    v2_b = file2.branch_hit
    v3_b = file3.branch_hit
    v1_l = file1.line_hit
    v2_l = file2.line_hit
    v3_l = file3.line_hit

    v1_branch_cov = len(v1_b)
    v2_branch_cov = len(v2_b)
    v3_branch_cov = len(v3_b)
    b_v1 = len(v1_b.difference(v2_b).difference(v3_b))
    b_v2 = len(v2_b.difference(v1_b).difference(v3_b))
    b_v3 = len(v3_b.difference(v2_b).difference(v1_b))
    b_v1_v2_v3 = len(v1_b.intersection(v2_b).intersection(v3_b))
    b_v1_v2 =  len(v1_b.intersection(v2_b)) - b_v1_v2_v3
    b_v2_v3 =  len(v2_b.intersection(v3_b)) - b_v1_v2_v3
    b_v1_v3 =  len(v1_b.intersection(v3_b)) - b_v1_v2_v3


    v1_line_cov = len(v1_l)
    v2_line_cov = len(v2_l)
    v3_line_cov = len(v3_l)
    l_v1 = len(v1_l.difference(v2_l).difference(v3_l))
    l_v2 = len(v2_l.difference(v1_l).difference(v3_l))
    l_v3 = len(v3_l.difference(v2_l).difference(v1_l))
    l_v1_v2_v3 = len(v1_l.intersection(v2_l).intersection(v3_l))
    l_v1_v2 =  len(v1_l.intersection(v2_l)) - l_v1_v2_v3
    l_v2_v3 =  len(v2_l.intersection(v3_l)) - l_v1_v2_v3
    l_v1_v3 =  len(v1_l.intersection(v3_l)) - l_v1_v2_v3

    print(file1.filename,
          v1_branch_cov,
          v2_branch_cov,
          v3_branch_cov,
          b_v1,
          b_v2,
          b_v3,
          b_v1_v2,
          b_v2_v3,
          b_v1_v3,
          b_v1_v2_v3,
          v1_line_cov,
          v2_line_cov,
          v3_line_cov,
          l_v1,
          l_v2,
          l_v3,
          l_v1_v2,
          l_v2_v3,
          l_v1_v3,
          l_v1_v2_v3,
          sep=",")

