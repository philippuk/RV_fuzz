import sys

class fileCoverageStats:
    def __init__(self, filename) -> None:
        self.filename = filename
        self.branch_hit = set()
        self.line_hit = set()

f1 = open(sys.argv[1],"r")
f2 = open(sys.argv[2],"r")

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

f1.close()
f2.close()

print("filename, isa_branch_cov, fuzz_branch_cov, diff_branch_cov, uniq_isa_branch_cov, unique_fuzz_branch_cov, branch_intersection, isa_line_cov, fuzz_line_cov, diff_line_cov, uniq_isa_line_cov, unique_fuzz_line_cov, line_intersection")

for file1, file2 in zip(f1_list,f2_list):
 
    if (file1.filename != file2.filename):
        print("Error: Filename does not match")
        continue

    isa_branch_set = file1.branch_hit
    fuzz_branch_set = file2.branch_hit
    isa_line_set = file1.line_hit
    fuzz_line_set = file2.line_hit

    isa_branch_cov = len(isa_branch_set)
    fuzz_branch_cov = len(fuzz_branch_set)
    diff_branch_cov = len(fuzz_branch_set) - len(isa_branch_set)
    uniq_isa_branch_cov = len(isa_branch_set.difference(fuzz_branch_set))
    uniq_fuzz_branch_cov = len(fuzz_branch_set.difference(isa_branch_set))
    branch_intersection = len(isa_branch_set.intersection(fuzz_branch_set))

    isa_line_cov = len(isa_line_set)
    fuzz_line_cov = len(fuzz_line_set)
    diff_line_cov = len(fuzz_line_set) - len(isa_line_set)
    uniq_isa_line_cov = len(isa_line_set.difference(fuzz_line_set))
    uniq_fuzz_line_cov = len(fuzz_line_set.difference(isa_line_set))
    line_intersection = len(isa_line_set.intersection(fuzz_line_set))

    print(file1.filename,
          isa_branch_cov,
          fuzz_branch_cov,
          diff_branch_cov,
          uniq_isa_branch_cov,
          uniq_fuzz_branch_cov,
          branch_intersection,
          isa_line_cov,
          fuzz_line_cov,
          diff_line_cov,
          uniq_isa_line_cov,
          uniq_fuzz_line_cov,
          line_intersection,
          sep=",")

