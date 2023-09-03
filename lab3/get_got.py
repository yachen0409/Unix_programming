from pwn import *
elf = ELF('./chals')
#print("main =", hex(elf.symbols['main']))
#print("{:<12s} {:<8s} {:<8s}".format("Func", "GOT", "Address"))
temp_got_base_list = []
got_base_list = []
for g in elf.got:
   if "code_" in g:
        temppair = ((int)(g.split('_')[1]), (hex)(elf.got[g]))
        print(temppair)
        temp_got_base_list.append(temppair)
        #print(g.split('_')[1], elf.got[g])
with open('got_index.txt', 'a') as the_file:
        for item in sorted(temp_got_base_list):
                the_file.write("{} {}\n".format(item[0], item[1]))