#include<sys/wait.h>/*引入wait函数的头文件*/
#include<sys/reg.h>/* 对寄存器的常量值进行定义，如Eax，EBX....... */
#include<sys/user.h>/*gdb调试专用文件，里面有定义好的各种数据类型*/
#include<sys/ptrace.h>/*引入prtace头文件*/
#include<unistd.h>/*引入fork函数的头文件*/
#include<sys/syscall.h> /* SYS_write */
#include <string.h>
#include<stdio.h>
#include <stdbool.h>
#define errquit(m)	{ perror(m); _exit(-1); }
int singlestep(int pid)
{
    int retval, status;
    retval = ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
    if( retval ) {
        return retval;
    }
    waitpid(pid, &status, 0);
    return status;
}

int main(int argc, char* argv[]) {
    pid_t child;/*定义子进程变量*/
    long orig_rax;//定义rax寄存器的值的变量
    int status;/*定义进程状态变量*/
    int iscalling = 0;/*判断是否正在被调用*/
    int loop_count = 0;
    bool first_three = true;
    bool first_four = true;
    struct user_regs_struct regs, three_regs, four_regs;/*定义寄存器结构体数据类型*/
    int number = 0;
    unsigned char number_array[] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30};
    child = fork();/*利用fork函数创建子进程*/
    if(child == 0){
        ptrace(PTRACE_TRACEME, 0, 0);//发送信号给父进程表示已做好准备被跟踪（调试）
        printf("%s\n", argv[1]);
        execvp(argv[1], argv+1);
        errquit("execvp");
    }
    else{
        // for(int i = 0; i < 5; ++i){
            long long counter = 0;
            waitpid(child, &status, 0);//等待子进程发来信号或者子进程退出
            ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
            while(WIFSTOPPED(status)){
                loop_count++;
                counter++;
                // if(loop_count >= 36){
                //     break;
                // }
                ptrace(PTRACE_GETREGS, child, 0, &regs);
                // printf("rax, rdi, rsi, rdx is: %016llx, %016llx, %lld, %lld\n",regs.rax, regs.orig_rax, regs.rsi, regs.rdx);
                // printf("%d, %d\n", first_three, first_four);
                if ((counter%6) == 3){
                    three_regs = regs;
                    three_regs.rip -= 1;
                    first_three = false;
                    // printf("%s\n", number_array);
                    ptrace(PTRACE_POKETEXT, child, three_regs.rax, *((long*)number_array));
                    ptrace(PTRACE_POKETEXT, child, three_regs.rax+8, *((long*)(number_array+8)));
                    if (!first_four){
                        ptrace(PTRACE_SETREGS, child, NULL, &four_regs);
                    }
                    // memset(regs.rax, '1', 10);
                }
                if ((counter%6) == 4 && first_four){
                    four_regs = regs;
                    four_regs.rip -= 1;
                    first_four = false;
                }
                if ((counter%6) == 0){
                    if (regs.rax == 0xffffffff){
                        ptrace(PTRACE_SETREGS, child, NULL, &three_regs);
                        number++;
                        int count_number = number;
                        for (int j = 0; j < 11; ++j){
                            number_array[j] = (count_number%2) + 0x30;
                            count_number /= 2;
                        }
                        counter = 2;

                        // int temp1 = number / 2;
                        // int temp2 = number % 2;
                        // number_array[temp1] = 0x30 + temp2;
                        // printf("%s\n", number_array);   
                    }

                }
                // if (counter == 7){
                    
                    
                // }
                if(ptrace(PTRACE_CONT, child, 0, 0) < 0) 
                    errquit("ptrace@parent");
                if(waitpid(child, &status, 0) < 0)
                    errquit("quit");
            }
            fprintf(stderr, "## %lld instructions executed!\n", counter);
            // if(WIFEXITED(status))//WIFEXITED函数(宏)用来检查子进程是被ptrace暂停的还是准备退出
            // {
            //     ptrace(PTRACE_GETREGS, child, 0, &regs);
            //     printf("here!\n");
            //     // break;
            // }
            // orig_rax = ptrace(PTRACE_PEEKUSER, child, 8 * ORIG_RAX, 0);//获取rax值从而判断将要执行的系统调用号
            // if(orig_rax == SYS_write)//如果系统调用是write
            // {    
            // ptrace(PTRACE_GETREGS, child, 0, &regs);
            // if(!iscalling)
            // {
            //     iscalling = 1;
            //     printf("rax, rdi, rsi, rdx is: %lld, %lld, %lld, %lld\n",regs.rax, regs.rdi, regs.rsi, regs.rdx);//打印出系统调用write的各个参数内容
            // }
            // else
            // {
            //     printf("SYS_write call return %lld\n", regs.rax);//打印出系统调用write函数结果的返回值
            //     iscalling = 0;
            // }
            // }
            // status = singlestep(child);
            // printf("%d\n", status);
            // ptrace(PTRACE_SYSCALL, child, 0, 0);//PTRACE_SYSCALL,其作用是使内核在子进程进入和退出系统调用时都将其暂停
            //得到处于本次调用之后下次调用之前的状态
        // }
    }
    return 0;
}