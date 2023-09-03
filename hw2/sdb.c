#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <elf.h>
#include <capstone/capstone.h>

#define errquit(m)	{ perror(m); _exit(-1); }
#define BUF_WRITABLE_SIZE 0X1000
#define BUF_HEAP_SIZE 0x21000
#define BUF_STACK_SIZE 0x21000

long stack_buf[BUF_STACK_SIZE];
long heap_buf[BUF_HEAP_SIZE];
long writable_buf[BUF_WRITABLE_SIZE];
long stack_min = 0, stack_max = 0;
long heap_min = 0, heap_max = 0;
long writable_min = 0, writable_max = 0;

void get_stack_heap_base(long pid) {
	int fd, sz;
	char buf[16384], *s = buf, *line, *saveptr;
    char filename[64];
    sprintf(filename, "/proc/%ld/maps", pid);
    // printf("filename: %s\n", filename);
	if((fd = open(filename, O_RDONLY)) < 0) errquit("get_stack_heap_base/open");
	if((sz = read(fd, buf, sizeof(buf)-1)) < 0) errquit("get_stack_heap_base/read");
	buf[sz] = 0;
	close(fd);
	while((line = strtok_r(s, "\n\r", &saveptr)) != NULL) { s = NULL;
		// if(strstr(line, " rw") == NULL) continue;
		if(strstr(line, "[stack]") != NULL) {
			if(sscanf(line, "%lx-%lx ", &stack_min, &stack_max) != 2) errquit("get_stack_heap_base/stack");
            // printf("%s\n", line);
		} 
        else if(strstr(line, "[heap]") != NULL) {
			if(sscanf(line, "%lx-%lx ", &heap_min, &heap_max) != 2) errquit("get_stack_heap_base/heap");
            // printf("%s\n", line);
		} 
	}
    if(stack_min!=0 && stack_max!=0) return;
	_exit(-fprintf(stderr, "** get_stack_heap_base failed.\n"));
}

void get_writable_base(long pid, char prog_name[]) {
	int fd, sz;
	char buf[16384], *s = buf, *line, *saveptr;
    char filename[64];
    char *real_prog_name;
    sprintf(filename, "/proc/%ld/maps", pid);
    real_prog_name = realpath(prog_name, NULL);
	if((fd = open(filename, O_RDONLY)) < 0) errquit("get_writable_base/open");
	if((sz = read(fd, buf, sizeof(buf)-1)) < 0) errquit("get_writable_base/read");
	buf[sz] = 0;
	close(fd);
	while((line = strtok_r(s, "\n\r", &saveptr)) != NULL) { s = NULL;
		if(strstr(line, " rw") != NULL && strstr(line, real_prog_name) != NULL) {
			if(sscanf(line, "%lx-%lx ", &writable_min, &writable_max) != 2) errquit("get_writable_base/writable");
            // printf("%s\n", line);
		} 
	}
    if(writable_min!=0 && writable_max!=0) return;
    // else{
    //     printf("(NOTICE) No writable mem for %s!\n", real_prog_name);
    // }
}

struct text_buf{
    long addr;
    long buf;
};

int main(int argc, char* argv[]) {
    pid_t child;
    long orig_rax;
    int status;
    struct user_regs_struct regs, anchor_regs;
    child = fork();
    if(child == 0){
        ptrace(PTRACE_TRACEME, 0, 0);
        execvp(argv[1], argv+1);
        errquit("execvp");
    }
    else{

        waitpid(child, &status, 0);
        long text_base = 0, text_end = 0;
        int text_size = 0;
        char *text_data;
        csh handle;
        cs_insn *insn;
        size_t count;
        struct text_buf tmp_buf[20];
        int tmp_buf_index = 0;

        FILE *file = fopen(argv[1], "rb");
        if(file){
            Elf64_Ehdr *elfhdr;
            elfhdr = malloc(sizeof(Elf64_Ehdr));
            fseek(file, 0, SEEK_SET);
            fread(elfhdr, 1, sizeof(Elf64_Ehdr), file);
            // fprintf(stderr, "program header offset:%08lx, section header offset:%08lx\n", elfhdr->e_phoff, elfhdr->e_shoff);
            Elf64_Shdr *sechdr;
            sechdr = malloc(elfhdr->e_shentsize*elfhdr->e_shnum);
            fseek(file, elfhdr->e_shoff, SEEK_SET);
            fread(sechdr, 1, elfhdr->e_shentsize*elfhdr->e_shnum, file);
            char sec_table[(int)((sechdr+elfhdr->e_shstrndx)->sh_size)];
            fseek(file, (sechdr+elfhdr->e_shstrndx)->sh_offset, SEEK_SET);
            fread(sec_table, 1, (sechdr+elfhdr->e_shstrndx)->sh_size, file);
            char *sec_start = sec_table;
            for(int i = 0; i < elfhdr->e_shnum; ++i){
                if(!strcmp(".text", (sec_start+(sechdr+i)->sh_name))){
                    printf("** program '%s' loaded. entry point 0x%lx\n", argv[1], (sechdr+i)->sh_addr);
                    // fprintf(stderr, "Found .text!\n");
                    // fprintf(stderr, "addr=0x%08lx\n", (sechdr+i)->sh_addr);
                    // fprintf(stderr, "offset=0x%08lx\n", (sechdr+i)->sh_offset);
                    // fprintf(stderr, "size=0x%08lx\n", (sechdr+i)->sh_size);
                    text_base = (sechdr+i)->sh_addr;
                    text_size = (sechdr+i)->sh_size;
                    text_end = text_base + text_size;
                    text_data = malloc((sechdr+i)->sh_size);
                    fseek(file, (sechdr+i)->sh_offset, SEEK_SET);
                    int j = fread(text_data, 1, (sechdr+i)->sh_size, file);
                    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
                        return -1;
                }
            }
        }

        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
        // int hit_index = -1;
        bool display_disassembly = true, no_breakpoint_msg = false;
        while(WIFSTOPPED(status)){
            int hit_index = -1;
            ptrace(PTRACE_GETREGS, child, 0, &regs);
            for (int j = 0; j < tmp_buf_index; ++j){
                // printf("tmp_buf index %d, %08lx, %p\n", j, tmp_buf[j].addr, tmp_buf[j].buf);
                if(tmp_buf[j].addr == regs.rip){
                    if(WIFSTOPPED(status) && !no_breakpoint_msg)
                        printf("** hit a breakpoint at 0x%lx\n", tmp_buf[j].addr);
                    hit_index = j;
                }
            }
            no_breakpoint_msg = false;
            if(display_disassembly){
                count = cs_disasm(handle, text_data+(regs.rip - text_base), text_size, regs.rip, 5, &insn);
                if (count > 0) {
                    for (int j = 0; j < 5; j++) {
                        if(insn[j].address >= text_end){
                            printf("** the address is out of the range of the text section.\n");
                            break;
                        }
                        printf("0x%"PRIx64": ", insn[j].address);
                        for(int k = 0; k < insn[j].size; ++k){
                            printf("%02x ", insn[j].bytes[k]);
                        }
                        if (insn[j].size < 5){
                            for (int k = 0; k < 5-insn[j].size; ++k)
                            printf("   ");
                        }
                        printf("\t");
                        printf("%s    %s\n", insn[j].mnemonic, insn[j].op_str);
                    }
                } else
                    printf("ERROR: Failed to disassemble given code!\n");
                
                cs_free(insn, count);
                // display_disassembly = false;
            }
            display_disassembly = false;
            char cmd[30];
            printf("(sdb) ");
            scanf("%s", cmd);
            // printf("Get command: %s\n", cmd);
            if(!strcmp(cmd, "si")){
                // printf("Single Step!\n");
                if(hit_index > -1){
                    // printf("hit_index = %d, %08lx\n", hit_index, tmp_buf[hit_index].addr);
                    // long tmp = ptrace(PTRACE_PEEKTEXT, child, (void *)tmp_buf[hit_index].addr, 0);
                    // printf("data = %lx\n", tmp);
                    long ori = ptrace(PTRACE_PEEKTEXT, child, regs.rip, 0);
                    uint8_t orig_byte =  text_data[(regs.rip - text_base)];
                    ptrace(PTRACE_POKETEXT, child, regs.rip, ((ori & 0xffffffffffffff00) | orig_byte));
                    if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0)
                        errquit("ptrace@parent");
                    if(waitpid(child, &status, 0) < 0)
                        errquit("quit");
                    // long ori_buf = ptrace(PTRACE_PEEKTEXT, child, tmp_buf[hit_index].addr, 0);
                    ptrace(PTRACE_POKETEXT, child, tmp_buf[hit_index].addr, ori);
                }
                else{
                    if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0)
                        errquit("ptrace@parent");
                    if(waitpid(child, &status, 0) < 0)
                        errquit("quit");
                }
                // ptrace(PTRACE_GETREGS, child, 0, &regs);
                // printf("after si, rip=%08lx\n", regs.rip);
                
                display_disassembly = true;
            }
            else if(!strcmp(cmd, "anchor")){
                printf("** dropped an anchor\n");
                get_writable_base(child, argv[1]);
                get_stack_heap_base(child);
                for(int j = 0; j < BUF_STACK_SIZE/8; ++j){
                    stack_buf[j] = ptrace(PTRACE_PEEKTEXT, child, (stack_min + j*8), 0);
                }
                if(heap_min != 0){
                    for(int j = 0; j < BUF_HEAP_SIZE/8; ++j){
                        heap_buf[j] = ptrace(PTRACE_PEEKTEXT, child, (heap_min + j*8), 0);
                    }
                }
                if (writable_min != 0){
                    for(int j = 0; j < BUF_WRITABLE_SIZE/8; ++j){
                        writable_buf[j] = ptrace(PTRACE_PEEKTEXT, child, (writable_min + j*8), 0);
                    }
                }
                ptrace(PTRACE_GETREGS, child, 0, &anchor_regs);
                no_breakpoint_msg = true;
            }
            else if(!strcmp(cmd, "timetravel")){
                printf("** go back to the anchor point\n");
                for(int j = 0; j < BUF_STACK_SIZE/8; ++j){
                    ptrace(PTRACE_POKETEXT, child, (stack_min + j*8), stack_buf[j]);
                }
                if (heap_min != 0){
                    for(int j = 0; j < BUF_HEAP_SIZE/8; ++j){
                        ptrace(PTRACE_POKETEXT, child, (heap_min + j*8), heap_buf[j]);
                    }
                }
                if (writable_min != 0){
                    for(int j = 0; j < BUF_WRITABLE_SIZE/8; ++j){
                        ptrace(PTRACE_POKETEXT, child, (writable_min + j*8), writable_buf[j]);
                    }
                }
                ptrace(PTRACE_SETREGS, child, 0, &anchor_regs);
                ptrace(PTRACE_GETREGS, child, 0, &regs);
                no_breakpoint_msg = true;
                display_disassembly = true;
            }
            else if(!strcmp(cmd, "break")){
                char addr_str[16];
                scanf("%s", addr_str);
                long addr = strtol(addr_str, NULL, 0);
                tmp_buf[tmp_buf_index].addr = addr;
                long ori_buf = ptrace(PTRACE_PEEKTEXT, child, (void *)addr, 0);
                tmp_buf[tmp_buf_index].buf = ori_buf;
                tmp_buf_index += 1;
                if (tmp_buf_index >= 20){
                    printf("tmp_buf is full!!!\n");
                    exit(-1);
                }
                ptrace(PTRACE_POKETEXT, child, (void *)addr, ((ori_buf & 0xffffffffffffff00) | 0xcc) );
                printf("** set a breakpoint at %s\n", addr_str);
                if(regs.rip == addr){
                    hit_index = tmp_buf_index-1;
                }
                no_breakpoint_msg = true;
            }
            //! continue
            else if(!strcmp(cmd, "cont")){
                // printf("Continue!\n");
                if(hit_index > -1){
                    // printf("hit_index = %d, %08lx\n", hit_index, tmp_buf[hit_index].addr);
                    // long tmp2 = ptrace(PTRACE_PEEKTEXT, child, (void *)tmp_buf[hit_index].addr, 0);
                    // printf("data = %lx\n", tmp2);
                    long ori = ptrace(PTRACE_PEEKTEXT, child, regs.rip, 0);
                    // printf("%x\n", text_data[(regs.rip - text_base)]);
                    uint8_t orig_byte =  text_data[(regs.rip - text_base)];
                    ptrace(PTRACE_POKETEXT, child, regs.rip, ((ori & 0xffffffffffffff00) | orig_byte));
                    if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) 
                        errquit("ptrace@parent");
                    if(waitpid(child, &status, 0) < 0)
                        errquit("quit");
                    // long ori_buf = ptrace(PTRACE_PEEKTEXT, child, tmp_buf[hit_index].addr, 0);
                    ptrace(PTRACE_POKETEXT, child, regs.rip, ori);
                    ptrace(PTRACE_CONT, child, 0, 0);
                    if(waitpid(child, &status, 0) < 0)
                        errquit("quit");
                }
                else{
                    if(ptrace(PTRACE_CONT, child, 0, 0) < 0) 
                        errquit("ptrace@parent");
                    if(waitpid(child, &status, 0) < 0)
                        errquit("quit");
                }
                ptrace(PTRACE_GETREGS, child, 0, &regs);
                regs.rip -= 1;
                ptrace(PTRACE_SETREGS, child, 0, &regs);
                // ptrace(PTRACE_GETREGS, child, 0, &regs);
                // printf("after cont, rip=%08lx\n", regs.rip);
               
                display_disassembly = true;
            }  
        }
        printf("** the target program terminated.\n");
        cs_close(&handle);
        
    }
    
    return 0;
}