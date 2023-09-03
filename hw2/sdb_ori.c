#include<sys/wait.h>/*引入wait函数的头文件*/
#include<sys/reg.h>/* 对寄存器的常量值进行定义，如Eax，EBX....... */
#include<sys/user.h>/*gdb调试专用文件，里面有定义好的各种数据类型*/
#include<sys/ptrace.h>/*引入prtace头文件*/
#include<unistd.h>/*引入fork函数的头文件*/
#include<sys/syscall.h> /* SYS_write */
#include <string.h>
#include<stdio.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <elf.h>
#include <capstone/capstone.h>

#define errquit(m)	{ perror(m); _exit(-1); }
static long main_min = 0, main_max = 0;
static long poem_min = 0, poem_max = 0;
static void get_base() {
	int fd, sz;
	char buf[16384], *s = buf, *line, *saveptr;
	if(poem_max != 0) return;
	if((fd = open("/proc/self/maps", O_RDONLY)) < 0) errquit("get_base/open");
	if((sz = read(fd, buf, sizeof(buf)-1)) < 0) errquit("get_base/read");
	buf[sz] = 0;
	close(fd);
	while((line = strtok_r(s, "\n\r", &saveptr)) != NULL) { s = NULL;
		if(strstr(line, " r-xp ") == NULL) continue;
		if(strstr(line, "/libpoem.so") != NULL) {
			if(sscanf(line, "%lx-%lx ", &poem_min, &poem_max) != 2) errquit("get_base/poem");
		} 
		printf("%s\n", line);
		if(main_min!=0 && main_max!=0 && poem_min!=0 && poem_max!=0) return;
	}
	_exit(-fprintf(stderr, "** get_base failed.\n"));
}

struct text_buf{
    long addr;
    char *buf;
};

int main(int argc, char* argv[]) {
    pid_t child;/*定义子进程变量*/
    long orig_rax;//定义rax寄存器的值的变量
    int status;/*定义进程状态变量*/
    int iscalling = 0;/*判断是否正在被调用*/
    // int loop_count = 0;
    bool first_three = true;
    bool first_four = true;
    // csh handle;
	// cs_insn *insn;
	// size_t dis_count;
    struct user_regs_struct regs, three_regs, four_regs;/*定义寄存器结构体数据类型*/
    int number = 0;
    unsigned char cc[] = {0xcc};
    child = fork();/*利用fork函数创建子进程*/
    if(child == 0){
        ptrace(PTRACE_TRACEME, 0, 0);//发送信号给父进程表示已做好准备被跟踪（调试）
        printf("%s\n", argv[1]);
        execvp(argv[1], argv+1);
        errquit("execvp");
    }
    else{
        // for(int i = 0; i < 5; ++i){
            // long long counter = 0;
            waitpid(child, &status, 0);//等待子进程发来信号或者子进程退出
            
            char program_name[1024] = {0};
            
            long text_base = 0, text_end = 0;
            int text_size = 0;
            char *text_data;
            csh handle;
            cs_insn *insn;
            size_t count;
            struct text_buf tmp_buf[20];
            int tmp_buf_index = 0;

            long previous_pos = 0;
            // n = readlink("/proc/self/exe", program_name, sizeof(program_name));
            FILE *file = fopen(argv[1], "rb");
            if(file){
                Elf64_Ehdr *elfhdr;
                elfhdr = malloc(sizeof(Elf64_Ehdr));

                // Elf64_Phdr programhdr;
                fseek(file, 0, SEEK_SET);
                fread(elfhdr, 1, sizeof(Elf64_Ehdr), file);
                // fprintf(stderr, "program header offset:%08lx, section header offset:%08lx\n", elfhdr->e_phoff, elfhdr->e_shoff);
                Elf64_Shdr *sechdr;
                sechdr = malloc(elfhdr->e_shentsize*elfhdr->e_shnum);
                fseek(file, elfhdr->e_shoff, SEEK_SET);
                fread(sechdr, 1, elfhdr->e_shentsize*elfhdr->e_shnum, file);
                // fprintf(stderr, "%d, %d\n", elfhdr->e_shstrndx, (sechdr+elfhdr->e_shstrndx)->sh_size);

                char sec_table[(int)((sechdr+elfhdr->e_shstrndx)->sh_size)];
                fseek(file, (sechdr+elfhdr->e_shstrndx)->sh_offset, SEEK_SET);
                fread(sec_table, 1, (sechdr+elfhdr->e_shstrndx)->sh_size, file);
                char *sec_start = sec_table;
                for(int i = 0; i < elfhdr->e_shnum; ++i){
                    if(!strcmp(".text", (sec_start+(sechdr+i)->sh_name))){
                        fprintf(stderr, "** program '%s' loaded. entry point 0x%lx\n", argv[1], (sechdr+i)->sh_addr);
                        // fprintf(stderr, "Found .text!\n");
                        // fprintf(stderr, "addr=0x%08lx\n", (sechdr+i)->sh_addr);
                        // fprintf(stderr, "offset=0x%08lx\n", (sechdr+i)->sh_offset);
                        text_base = (sechdr+i)->sh_addr;
                        // fprintf(stderr, "size=0x%08lx\n", (sechdr+i)->sh_size);
                        text_size = (sechdr+i)->sh_size;
                        text_end = text_base + text_size;
                        printf("text_end = 0x%x\n", text_end);
                        text_data = malloc((sechdr+i)->sh_size);
                        fseek(file, (sechdr+i)->sh_offset, SEEK_SET);
                        int j = fread(text_data, 1, (sechdr+i)->sh_size, file);
                        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
                            return -1;
                        // break;
                    }
                }
            }

            ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
            int hit_index = -1;
            while(WIFSTOPPED(status)){
                ptrace(PTRACE_GETREGS, child, 0, &regs);
                //!rip已經變成下個指令的位子
                
                // printf("rax, rdi, rsi, rdx, rip is: %016llx, %016llx, %lld, %lld, %08llx\n",regs.rax, regs.orig_rax, regs.rsi, regs.rdx, regs.rip);
                // printf("%d, %d\n", first_three, first_four);
                printf("%08lx, %08lx\n", regs.rip, previous_pos);
                if(regs.rip != previous_pos){
                    count = cs_disasm(handle, text_data+(regs.rip - text_base), text_size, regs.rip, 0, &insn);
                    // printf("count = %ld\n", count);
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
                }
                // printf("hit_index = %d\n", hit_index);
                // while(true){
                char cmd[30];
                printf("(sdb) ");
                scanf("%s", cmd);
                // printf("Get command: %s\n", cmd);
                previous_pos = regs.rip;
                //! single step
                if(!strcmp(cmd, "si")){
                    // printf("Single Step!\n");
                    //!有問題 不知道是哪裡錯(maybe存buf data時錯，maybe這裡寫回去的時候錯，maybe判斷hit有錯)
                    // printf("hit_index = %d, %08lx, %p\n", hit_index, tmp_buf[hit_index].addr, tmp_buf[hit_index].buf);
                    // char *tmp = malloc(8);
                    // tmp = ptrace(PTRACE_PEEKTEXT, child, (void *)tmp_buf[hit_index].addr, 0);
                    // printf("origin buf = %lx\n", tmp);
                    // if(hit_index > -1){
                    //     if(ptrace(PTRACE_POKETEXT, child, tmp_buf[hit_index].addr, tmp_buf[hit_index].buf) < 0)
                    //         errquit("drop cc");
                    //     if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0)
                    //         errquit("ptrace@parent");
                    //     // ptrace(PTRACE_SINGLESTEP, child, 0, 0);
                    //     if(waitpid(child, &status, 0) < 0)
                    //         errquit("quit");
                    //     if(ptrace(PTRACE_POKETEXT, child, tmp_buf[hit_index].addr, *((long*)cc)) < 0)
                    //         errquit("resume cc");
                    // //         // printf("** hit a breakpoint at 0x%lx\n", tmp_buf[j].addr);
                    // }
                    // else{
                        if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0)
                            errquit("ptrace@parent");
                        // ptrace(PTRACE_SINGLESTEP, child, 0, 0);
                        if(waitpid(child, &status, 0) < 0)
                            errquit("quit");
                    // }
                    // if(hit_index > -1){
                    //     if(ptrace(PTRACE_POKETEXT, child, tmp_buf[hit_index].addr, 0xcc) < 0)
                    //             errquit("resume cc");
                    // }
                    ptrace(PTRACE_GETREGS, child, 0, &regs);
                    printf("after si, rip=%08lx\n", regs.rip);
                    hit_index = -1;
                    for (int j = 0; j < tmp_buf_index; ++j){
                        if(tmp_buf[j].addr == regs.rip){
                            // ptrace(PTRACE_POKETEXT, child, regs.rip, tmp_buf[j].buf);
                            printf("** hit a breakpoint at 0x%lx\n", tmp_buf[j].addr);
                            hit_index = j;
                        }
                    }
                    // ptrace(PTRACE_GETREGS, child, 0, &regs);
                    // printf("after si, rip=%08lx\n", regs.rip);
                    // break;0
                }
                else if(!strcmp(cmd, "anchor")){
                    printf("anchor SET!\n");
                }
                else if(!strcmp(cmd, "timetravel")){
                    printf("Timetravel!\n");
                }
                else if(!strcmp(cmd, "break")){
                    char addr_str[16];
                    scanf("%s", addr_str);
                    long addr = strtol(addr_str, NULL, 0);
                    tmp_buf[tmp_buf_index].addr = addr;
                    tmp_buf[tmp_buf_index].buf = malloc(8);
                    tmp_buf[tmp_buf_index].buf = ptrace(PTRACE_PEEKTEXT, child, (void *)addr, 0);
                    tmp_buf_index += 1;
                    if (tmp_buf_index >= 20){
                        printf("tmp_buf is full!!!\n");
                        exit(-1);
                    }
                    ptrace(PTRACE_POKETEXT, child, (void *)addr, *((long*)cc));
                    printf("** set a breakpoint at %s\n", addr_str);
                }
                //! continue
                else if(!strcmp(cmd, "cont")){
                    // printf("Continue!\n");
                    // printf("hit_index = %d, %08lx, %p\n", hit_index, tmp_buf[hit_index].addr, tmp_buf[hit_index].buf);
                    // char *tmp2 = malloc(8);
                    // tmp2 = ptrace(PTRACE_PEEKTEXT, child, (void *)tmp_buf[hit_index].addr, 0);
                    // printf("origin buf = %lx\n", tmp2);
                    // if(hit_index > -1){
                        // ptrace(PTRACE_POKETEXT, child, tmp_buf[hit_index].addr, tmp_buf[hit_index].buf);
                        // if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) 
                        //     errquit("ptrace@parent");
                        // if(waitpid(child, &status, 0) < 0)
                        //     errquit("quit");
                        // ptrace(PTRACE_CONT, child, 0, 0);
                        // if(waitpid(child, &status, 0) < 0)
                        //     errquit("quit");
                        // ptrace(PTRACE_POKETEXT, child, tmp_buf[hit_index].addr, *((long*)cc));
                        
                            // printf("** hit a breakpoint at 0x%lx\n", tmp_buf[j].addr);
                    // }
                    // else{
                    if(ptrace(PTRACE_CONT, child, 0, 0) < 0) 
                        errquit("ptrace@parent");
                    if(waitpid(child, &status, 0) < 0)
                        errquit("quit");
                    // }
                    ptrace(PTRACE_GETREGS, child, 0, &regs);
                    regs.rip -= 1;
                    ptrace(PTRACE_SETREGS, child, 0, &regs);
                    // ptrace(PTRACE_POKETEXT, child, tmp_buf[regs.rip].addr, tmp_buf[regs.rip].buf);
                    // printf("after cont, rip=%08lx\n", regs.rip);
                    hit_index = -1;
                    for (int j = 0; j < tmp_buf_index; ++j){
                        if(tmp_buf[j].addr == regs.rip){
                            ptrace(PTRACE_POKETEXT, child, regs.rip, tmp_buf[j].buf);
                            printf("** hit a breakpoint at 0x%lx\n", tmp_buf[j].addr);
                            hit_index = j;
                        }
                    }
                }
                
                // }
                
                
            }
            printf("** the target program terminated.\n");
            cs_close(&handle);
            
    }
    
    return 0;
}