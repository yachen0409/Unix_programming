#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <dlfcn.h>
#include <elf.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <string.h>
#include <netdb.h>
#include <netdb.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define errquit(m)	{ perror(m); _exit(-1); }
#define MAX_LINES 100
#define MAX_LINE_LENGTH 1024
int (*oldptr)(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (*stack_end));
int (*my_openptr)(const char *pathname, int flags, ...);
ssize_t (*my_readptr)(int fd, void *buf, size_t count);
ssize_t (*my_writeptr)(int fd, const void *buf, size_t count);
int (*my_conptr)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int (*my_addrptr)(const char *restrict node, const char *restrict service, const struct addrinfo *restrict hints, struct addrinfo **restrict res);
int (*my_sysptr)(const char *command);
int (*real_openptr)(const char *pathname, int flags, ...);
ssize_t (*real_writeptr)(int fd, const void *buf, size_t count);
ssize_t (*real_readptr)(int fd, void *buf, size_t count);
int (*real_conptr)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int (*real_addrptr)(const char *restrict node, const char *restrict service, const struct addrinfo *restrict hints, struct addrinfo **restrict res);
int (*real_sysptr)(const char *command);
char open_blacklist[MAX_LINES][MAX_LINE_LENGTH];
int log_fd;
static long main_min = 0, main_max = 0;
static void get_base(char *prog_name) {
	int fd, sz;
	char buf[16384], *s = buf, *line, *saveptr;
	// if(poem_max != 0) return;
	if((fd = open("/proc/self/maps", O_RDONLY)) < 0) errquit("get_base/open");
	if((sz = read(fd, buf, sizeof(buf)-1)) < 0) errquit("get_base/read");
	buf[sz] = 0;
	close(fd);
	while((line = strtok_r(s, "\n\r", &saveptr)) != NULL) { s = NULL;
		if(strstr(line, " r--p ") == NULL) continue;
		// if(strstr(line, "/libpoem.so") != NULL) {
		// 	if(sscanf(line, "%lx-%lx ", &poem_min, &poem_max) != 2) errquit("get_base/poem");
		// } else
        // printf("%s\n", prog_name);
        if(strstr(line, prog_name) != NULL) {
			if(sscanf(line, "%lx-%lx ", &main_min, &main_max) != 2) errquit("get_base/main");
		}
		// printf("%s\n", line);
		if(main_min!=0 && main_max!=0) return;
	}
	_exit(-fprintf(stderr, "** get_base failed.\n"));
}
int my_open(const char *pathname, int flags, ...){
    // dprintf(log_fd, "Function called: %s\n", "my_open");
    mode_t mode = 0;
    va_list args;
    if((flags == O_CREAT) || (flags == O_TMPFILE)){
        va_start(args, flags);
        mode = va_arg(args, mode_t);
    }
    char *config_path = getenv("SANDBOX_CONFIG");
    FILE *blacklist_file;
    char line[MAX_LINE_LENGTH];
    char blacklist[MAX_LINE_LENGTH];
    blacklist_file = fopen(config_path, "r");
    if (blacklist_file == NULL) {
        printf("Failed to open the file.\n");
        return 1; // Exit with an error code
    }

    // Read and print each line in the file
    int in = 0;
    while (fgets(line, sizeof(line), blacklist_file) != NULL) {
        if(strstr(line, "BEGIN open-blacklist") != NULL) {
            in = 1; // Set flag to indicate that we are inside the blacklist
            continue;
        }
        else if(strstr(line, "END open-blacklist") != NULL) {
            in = 0; // Clear flag to indicate that we are outside the blacklist
            continue;
        }
        if(in == 1){
            sscanf(line, "%s\n ", blacklist);

            line[strlen(line)-1] = '\0';
            //printf("%s, %s, %s\n", line, blacklist, pathname);
            char actualpath1[MAX_LINE_LENGTH];
            char *ptr1;
            char actualpath2[MAX_LINE_LENGTH];
            char *ptr2;
            ptr1 = realpath(blacklist, actualpath1);
            // printf("actual path 1: %s\n", ptr1);
            ptr2 = realpath(pathname, actualpath2);
            // printf("actual path 2: %s\n", ptr2);
            // printf("compare result: %d\n", re);
            if(ptr1!=NULL && !strcmp(ptr1, ptr2)){
                // printf("match, %s, %s\n", line, pathname);
                dprintf(log_fd, "[logger] open(\"%s\", %d, %d) = %d\n", pathname, flags, mode, -1);
                errno = EACCES;
                return -1;
            }
        }
        // printf("%s\n", line);
    }
    fclose(blacklist_file);

    int return_value = real_openptr(pathname, flags, 0);
    dprintf(log_fd, "[logger] open(\"%s\", %d, %d) = %d\n", pathname, flags, (int)mode, return_value);
    return return_value;
}
//!問題比較大
ssize_t my_read(int fd, void *buf, size_t count){
    // dprintf(log_fd, "Function called: %s\n", "my_read");
    pid_t pid = getpid();
    //!大小問題？
    char temp_buf[65536];
    memset(temp_buf, 0x00, sizeof(temp_buf));
    ssize_t return_value = read(fd, temp_buf, count);
    // printf("temp_buf: %s\n", temp_buf);
    char fd_path[MAX_LINE_LENGTH], fd_file[MAX_LINE_LENGTH], filterfile[2*MAX_LINE_LENGTH];
    sprintf(fd_path, "/proc/self/fd/%d", fd);
    readlink(fd_path, fd_file, MAX_LINE_LENGTH-1);
    // printf("strlen(fd_file): %ld\n", strlen(fd_file));
    for(int i = 0; i < strlen(fd_file); ++i){
        // printf("%c ", fd_file[i]);
        if(fd_file[i] == '/'){
            fd_file[i] = '_';
        }
    }
    sprintf(filterfile, "filter%s.txt", fd_file);
    FILE *filter_fileptr = fopen(filterfile, "a");
    if(filter_fileptr == NULL){
        printf("fileter file open failed!\n");
        exit(1);
    }
    fwrite(temp_buf, sizeof(char), return_value, filter_fileptr);
    fclose(filter_fileptr);

    char filename[MAX_LINE_LENGTH];
    sprintf(filename, "%d-%d-read.log", pid, fd);
    FILE* log_fileptr = fopen(filename, "a");
    char *config_path = getenv("SANDBOX_CONFIG");
    FILE *blacklist_file;
    char line[MAX_LINE_LENGTH];
    char blacklist[MAX_LINE_LENGTH];
    blacklist_file = fopen(config_path, "r");
    if (blacklist_file == NULL) {
        printf("Failed to open the file.\n");
        return 1; // Exit with an error code
    }
    // Read and print each line in the file
    int in = 0;
    while (fgets(line, sizeof(line), blacklist_file) != NULL) {
        if(strstr(line, "BEGIN read-blacklist") != NULL) {
            in = 1; // Set flag to indicate that we are inside the blacklist
            continue;
        }
        else if(strstr(line, "END read-blacklist") != NULL) {
            in = 0; // Clear flag to indicate that we are outside the blacklist
            continue;
        }
        if(in == 1){
            sscanf(line, "%s\n ", blacklist);
            //printf("here!\nblacklist: %s\nbuf: %s", line, temp_buf);
            line[strlen(line)-1] = '\0';
            if(strstr(temp_buf, line)!=NULL){
                //printf("match!!!!\n");
                dprintf(log_fd, "[logger] read(%d, %p, %ld) = %d\n", fd, buf, count, -1);
                errno = EIO;
                close(fd);
                remove(filterfile);
                return -1;
            }
        }
        // printf("%s\n", line);
    }
    fclose(blacklist_file);
    //printf("jlsfiajeilsfjailefjsilaj %s\n", temp_buf);
    memcpy(buf, temp_buf, return_value);
    fwrite(buf, sizeof(char), return_value, log_fileptr);
    dprintf(log_fd, "[logger] read(%d, %p, %ld) = %ld\n", fd, buf, count, return_value);
    fclose(log_fileptr);
    return return_value;
}
ssize_t my_write(int fd, const void *buf, size_t count){
    //dprintf(log_fd, "Function called: %s\n", "my_write");
    pid_t pid = getpid();
    char filename[MAX_LINE_LENGTH];
    sprintf(filename, "%d-%d-write.log", pid, fd);
    FILE* log_fileptr = fopen(filename, "a");

    ssize_t return_value = real_writeptr(fd, buf, count);
    fwrite(buf, sizeof(char), return_value, log_fileptr);
    dprintf(log_fd, "[logger] write(%d, %p, %ld) = %ld\n", fd, buf, count, return_value);
    return return_value;
}
int my_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    // dprintf(log_fd, "Function called: %s\n", "my_connect");

    const struct sockaddr_in *addr_origin = (const struct sockaddr_in *)addr;
    // char host[NI_MAXHOST];
    // char *ip_connect = inet_ntoa(addr_origin->sin_addr);
    // printf("ip_connect0000000000: %s\n",inet_ntoa(addr_origin->sin_addr));
    // getnameinfo(addr, sizeof(struct sockaddr), host, sizeof(host), NULL, 0, NI_NOFQDN);
    // printf("host name: %s\n", host);
    int return_value = real_conptr(sockfd, addr, addrlen);
    char *config_path = getenv("SANDBOX_CONFIG");
    FILE *blacklist_file;
    char line[MAX_LINE_LENGTH];
    char blacklist[MAX_LINE_LENGTH];
    int port;
    blacklist_file = fopen(config_path, "r");
    if (blacklist_file == NULL) {
        printf("Failed to open the file.\n");
        return 1; // Exit with an error code
    }

    // Read and print each line in the file
    int in = 0;
    while (fgets(line, sizeof(line), blacklist_file) != NULL) {
        if(strstr(line, "BEGIN connect-blacklist") != NULL) {
            in = 1; // Set flag to indicate that we are inside the blacklist
            continue;
        }
        else if(strstr(line, "END connect-blacklist") != NULL) {
            in = 0; // Clear flag to indicate that we are outside the blacklist
            continue;
        }
        if(in == 1){
            // printf("%s\n", line);
            sscanf(line, "%255[^:]:%d\n ", blacklist, &port);
            // printf("---- %s ----\n", blacklist);
            //! getaddrinfo
            // struct addrinfo hints, *result, *rp;
            // int status;
            // char ip[INET6_ADDRSTRLEN]; // Buffer to hold the IP address

            // // Set up hints for the type of address we want to resolve
            // memset(&hints, 0, sizeof(hints));
            // hints.ai_family = AF_UNSPEC; // Allow both IPv4 and IPv6
            // hints.ai_socktype = SOCK_STREAM; // We're interested in a TCP socket

            // // Call getaddrinfo() to get the address information for the hostname
            // status = getaddrinfo(blacklist, NULL, &hints, &result);
            // printf("blacklist getaddrinfo status: %d\n", status);
            // for (rp = result; rp != NULL; rp = rp->ai_next) {
            //     void *addr;
            //     char *ipver;

            //     // Get the pointer to the address depending on the address family
            //     if (rp->ai_family == AF_INET) {
            //         struct sockaddr_in *ipv4 = (struct sockaddr_in *)rp->ai_addr;
            //         addr = &(ipv4->sin_addr);
            //         ipver = "IPv4";
            //     } else {
            //         struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)rp->ai_addr;
            //         addr = &(ipv6->sin6_addr);
            //         ipver = "IPv6";
            //     }

            //     // Convert the binary IP address to a human-readable string
            //     inet_ntop(rp->ai_family, addr, ip, sizeof(ip));
            //     printf("%s: %s\n", ipver, ip);
            // }
            //!end getaddrinfo
            //! gethostbyname
            // printf("ip_connect111: %s\n",ip_connect);
            struct hostent *host = gethostbyname(blacklist);
            struct in_addr **addr_list;
            addr_list = (struct in_addr **)host->h_addr_list;
            for (int i = 0; addr_list[i] != NULL; i++) {
                char ip_blacklist[MAX_LINE_LENGTH], ip_connect[MAX_LINE_LENGTH];
                inet_ntop(AF_INET, addr_list[i], ip_blacklist, sizeof(ip_blacklist));
                inet_ntop(AF_INET, &addr_origin->sin_addr, ip_connect, sizeof(ip_blacklist));
                // printf("ip before strcmp: blacklist=%s, connect=%s\n",ip_blacklist,ip_connect);
                if(!strcmp(ip_blacklist, ip_connect)){
                    printf("domain match\n");
                    // printf("ip after strcmp: blacklist=%s, connect=%s\n",ip_blacklist,ip_connect);
                    if(port == ntohs(addr_origin->sin_port)){
                        // printf("port match\n");
                        errno = ECONNREFUSED;
                        dprintf(log_fd, "[logger] connect(%d, \"%s\", %d) = %d\n", sockfd, inet_ntoa(addr_origin->sin_addr), addrlen, -1);
                        return -1;
                    }
                }
                // printf("send to %s\n", ip);
            }

            // printf("%s, %s\n", inet_ntoa(*(struct in_addr *) lh->h_addr_list), ip);
            // if(!strcmp(inet_ntoa(*(struct in_addr *) lh->h_addr_list), ip)){
            //     printf("domain match\n");
            //     printf("%d, %d\n", port, ntohs(addr_in->sin_port));
            //     if(port == ntohs(addr_in->sin_port)){
            //         printf("port match\n");
            //     }
            // }
            // printf("%s, %d\n", blacklist, port);
            // line[strlen(line)] = '\0';
            // printf("%s, %s, %s\n", line, blacklist, pathname);
            // if(strstr(line, pathname)!=NULL){
            //     printf("match, %s, %s\n", line, pathname);
            //     dprintf(log_fd, "[logger] open(\"%s\", %d, %d) = %d\n", pathname, flags, mode, -1);
            //     errno = EACCES;
            //     return -1;
            // }
        }
        // printf("%s\n", line);
    }
    // printf("lidsjflisjdfjdsafjl   %s lsidofidsjlfis\n", inet_ntoa(addr_in->sin_addr));
    fclose(blacklist_file);
    dprintf(log_fd, "[logger] connect(%d, \"%s\", %d) = %d\n", sockfd, inet_ntoa(addr_origin->sin_addr), addrlen, return_value);
    return return_value;
}
int my_getaddrinfo(const char *restrict node, const char *restrict service, const struct addrinfo *restrict hints, struct addrinfo **restrict res){
    // dprintf(log_fd, "Function called: %s\n", "my_getaddrinfo");
    // printf("%s\n", node);
    char *config_path = getenv("SANDBOX_CONFIG");
    FILE *blacklist_file;
    char line[MAX_LINE_LENGTH];
    char blacklist[MAX_LINE_LENGTH];
    int port;
    blacklist_file = fopen(config_path, "r");
    if (blacklist_file == NULL) {
        printf("Failed to open the file.\n");
        return 1; // Exit with an error code
    }
    // Read and print each line in the file
    int in = 0;
    while (fgets(line, sizeof(line), blacklist_file) != NULL) {
        if(strstr(line, "BEGIN getaddrinfo-blacklist") != NULL) {
            in = 1; // Set flag to indicate that we are inside the blacklist
            continue;
        }
        else if(strstr(line, "END getaddrinfo-blacklist") != NULL) {
            in = 0; // Clear flag to indicate that we are outside the blacklist
            continue;
        }
        if(in == 1){
            sscanf(line, "%s\n ", blacklist);
            //printf("%s, %s\n", node, blacklist);
            if(!strcmp(node, blacklist)){
                errno = EAI_NONAME;
                dprintf(log_fd, "[logger] getaddrinfo(\"%s\", \"%s\", %p, %p) = %d\n", node, service, hints, res, EAI_NONAME);
                return EAI_NONAME;
            }
        }
        // printf("%s\n", line);
    }
    int return_value = real_addrptr(node, service, hints, res);
    dprintf(log_fd, "[logger] getaddrinfo(\"%s\", \"%s\", %p, %p) = %d\n", node, service, hints, res, return_value);
    return return_value;
}
int my_system(const char *command){
    // dprintf(log_fd, "Function called: %s\n", "my_system");
    dprintf(log_fd, "[logger] system(\"%s\")\n", command);
    // system(command);
    int return_value = real_sysptr(command);
    return return_value;
}
int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (*stack_end)){
    void *handle;
    // int  *oldptr;
    log_fd = atoi(getenv("LOGGER_FD"));
    handle = dlopen("libc.so.6",  RTLD_LAZY);
    // fprintf(stderr, "sidjfoidsjfosjd\n");
    if(handle != NULL){
        oldptr = dlsym(handle, "__libc_start_main");
        real_openptr = dlsym(handle, "open");
        real_readptr = dlsym(handle, "read");
        real_writeptr = dlsym(handle, "write");
        real_conptr = dlsym(handle, "connect");
        real_addrptr = dlsym(handle, "getaddrinfo");
        real_sysptr = dlsym(handle, "system");
    }

    int n;
    char program_name[1024] = {0};
    n = readlink("/proc/self/exe", program_name, sizeof(program_name));
    // if(n > 0 && n < sizeof(program_name)){
    //     fprintf(stderr, "%s\n", program_name);
    // }
    FILE *file = fopen(program_name, "rb");
    if(file){
        // fprintf(stderr, "can open!\n");
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

        Elf64_Rela *relahdr;
        Elf64_Sym *symhdr;
        char *strhdr;
        int relasize;
        char *sec_start = sec_table;
        long got_base = 0;
        int got_size;
        for(int i = 0; i < elfhdr->e_shnum; ++i){
            if(!strcmp(".got", (sec_start+(sechdr+i)->sh_name))){
                // fprintf(stderr, "Found .got!\n");
                // fprintf(stderr, "addr=0x%08lx\n", (sechdr+i)->sh_addr);
                // fprintf(stderr, "offset=0x%08lx\n", (sechdr+i)->sh_offset);
                got_base = (sechdr+i)->sh_addr;
                // fprintf(stderr, "size=0x%08lx\n", (sechdr+i)->sh_size);
                got_size = (sechdr+i)->sh_size;
                char *mydata = malloc((sechdr+i)->sh_size);
                fseek(file, (sechdr+i)->sh_offset, SEEK_SET);
                int j = fread(mydata, 1, (sechdr+i)->sh_size, file);
                // for (int k = 0; k < (sechdr+i)->sh_size; k += 8) {
                //     Elf64_Addr *addr = (Elf64_Addr *)(mydata + k);
                //     fprintf(stderr, "Address: 0x%016lx\n", *addr);
                // }
                // break;
            }
            else if(!strcmp(".dynsym", (sec_start+(sechdr+i)->sh_name))){
                // fprintf(stderr, "Found .dynsym!\n");
                // fprintf(stderr, "addr=0x%08lx\n", (sechdr+i)->sh_addr);
                // fprintf(stderr, "offset=0x%08lx\n", (sechdr+i)->sh_offset);
                // fprintf(stderr, "size=0x%08lx\n", (sechdr+i)->sh_size);

                symhdr = malloc((sechdr+i)->sh_size);
                fseek(file, (sechdr+i)->sh_offset, SEEK_SET);
                fread(symhdr, 1, (sechdr+i)->sh_size, file);
                // fprintf(stderr, "%d\n", j/sizeof(Elf64_Sym));
                char *sym_start = symhdr;
                // for(int k = 0; k < (sechdr+i)->sh_size/sizeof(Elf64_Sym); k++){
                //     fprintf(stderr, "%s\n", ((symhdr+k)->st_info) );
                // }
            }
            else if(!strcmp(".dynstr", (sec_start+(sechdr+i)->sh_name))){
                // fprintf(stderr, "Found .dynstr!\n");
                // fprintf(stderr, "addr=0x%08lx\n", (sechdr+i)->sh_addr);
                // fprintf(stderr, "offset=0x%08lx\n", (sechdr+i)->sh_offset);
                // fprintf(stderr, "size=0x%08lx\n", (sechdr+i)->sh_size);
                // Elf64_Sym *symhdr;
                strhdr = malloc((sechdr+i)->sh_size);
                fseek(file, (sechdr+i)->sh_offset, SEEK_SET);
                fread(strhdr, 1, (sechdr+i)->sh_size, file);
            }
            else if(!strcmp(".rela.plt", (sec_start+(sechdr+i)->sh_name))){
                // fprintf(stderr, "Found .rela.plt!\n");
                // fprintf(stderr, "addr=0x%08lx\n", (sechdr+i)->sh_addr);
                // fprintf(stderr, "offset=0x%08lx\n", (sechdr+i)->sh_offset);
                // fprintf(stderr, "size=0x%08lx\n", (sechdr+i)->sh_size);
                relahdr = malloc((sechdr+i)->sh_size);
                fseek(file, (sechdr+i)->sh_offset, SEEK_SET);
                fread(relahdr, 1, (sechdr+i)->sh_size, file);
                relasize = (sechdr+i)->sh_size;
            }
        }

        get_base(program_name);
        void *so_handle = dlopen("~/hw1/sandbox.so",  RTLD_LAZY);
        got_base += main_min;
        long page_size = sysconf(_SC_PAGESIZE);
        long got_page_start = got_base & ~(page_size-1);
        // printf("out: %016lx\n", (long *)got_page_start);
        int got_page_num = (got_size/page_size) + 1;
        // printf("%016lx, %d, %d\n", got_page_start, page_size, got_page_num);
        if (mprotect((void *)got_page_start, page_size*got_page_num , PROT_READ | PROT_WRITE) == -1) {
            perror("mprotect");
            exit(0);
            return 1;
        }
        // printf("symbol offset   | Symbol name\n");
        // printf("%ld, %d, %d\n", sizeof(relahdr), relasize, sizeof(Elf64_Rela));

        for(int j = 0; j < relasize/sizeof(Elf64_Rela); ++j){
            Elf64_Rela *temp_rela = &relahdr[j];
            Elf64_Sym *temp_sym = &symhdr[ELF64_R_SYM(temp_rela->r_info)];
            // fprintf(stderr, "%d\n", j);

            if(!strcmp("open", strhdr+temp_sym->st_name)){
                // printf("find open with offset %016lx\n", temp_rela->r_offset);
                my_openptr = dlsym(so_handle, "my_open");
                // fseek(file, temp_rela->r_offset, SEEK_SET);
                // fread(tempptr, 1, 8, file);
                // printf("%016lx, %016lx, %016lx, %016lx, %d\n", main_min, main_min+temp_rela->r_offset, &my_open, &my_openptr, sizeof(long));
                long tempptr = main_min + temp_rela->r_offset;
                memcpy((long *)tempptr, &my_openptr, sizeof(long));
                // file = my_openptr;
            }
            else if(!strcmp("write", strhdr+temp_sym->st_name)){
                // printf("find write with offset %016lx\n", temp_rela->r_offset);
                my_writeptr = dlsym(so_handle, "my_write");
                long tempptr = main_min + temp_rela->r_offset;
                memcpy((long *)tempptr, &my_writeptr, sizeof(long));
            }
            else if(!strcmp("read", strhdr+temp_sym->st_name)){
                // printf("find read with offset %016lx\n", temp_rela->r_offset);
                my_readptr = dlsym(so_handle, "my_read");
                long tempptr = main_min + temp_rela->r_offset;
                memcpy((long *)tempptr, &my_readptr, sizeof(long));
            }
            else if(!strcmp("connect", strhdr+temp_sym->st_name)){
                // printf("find connect with offset %016lx\n", temp_rela->r_offset);
                my_conptr = dlsym(so_handle, "my_connect");
                long tempptr = main_min + temp_rela->r_offset;
                memcpy((long *)tempptr, &my_conptr, sizeof(long));
            }
            else if(!strcmp("getaddrinfo", strhdr+temp_sym->st_name)){
                // printf("find getaddrinfo with offset %016lx\n", temp_rela->r_offset);
                my_addrptr = dlsym(so_handle, "my_getaddrinfo");
                long tempptr = main_min + temp_rela->r_offset;
                memcpy((long *)tempptr, &my_addrptr, sizeof(long));
            }
            else if(!strcmp("system", strhdr+temp_sym->st_name)){
                // printf("find system with offset %016lx\n", temp_rela->r_offset);
                my_sysptr = dlsym(so_handle, "my_system");
                long tempptr = main_min + temp_rela->r_offset;
                memcpy((long *)tempptr, &my_sysptr, sizeof(long));
            }
            // printf("%d\n", j);
            // fprintf(stderr, "%016lx  | %s\n", temp_rela->r_offset, strhdr+temp_sym->st_name);
        }

    }

    int status = oldptr(main, argc, ubp_av, init, fini, rtld_fini, stack_end);

    return 0;
}