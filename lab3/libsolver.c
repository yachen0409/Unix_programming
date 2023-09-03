/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <libunwind.h>
#include <sys/mman.h>
#include "libpoem.h"
#include "shuffle.h"
#include "libgotlist.h"

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
		if(strstr(line, " r--p ") == NULL) continue;
		if(strstr(line, "/libpoem.so") != NULL) {
			if(sscanf(line, "%lx-%lx ", &poem_min, &poem_max) != 2) errquit("get_base/poem");
		} else if(strstr(line, "/chal") != NULL) {
			if(sscanf(line, "%lx-%lx ", &main_min, &main_max) != 2) errquit("get_base/main");
		}
		// printf("%s\n", line);
		if(main_min!=0 && main_max!=0 && poem_min!=0 && poem_max!=0) return;
	}
	_exit(-fprintf(stderr, "** get_base failed.\n"));
}

int ndat_size = sizeof(ndat)/sizeof(int);
int (*old_list[sizeof(ndat)/sizeof(int)])(void);
int init()   {
    setbuf(stdout, NULL);
	void *handle = dlopen("libpoem.so", RTLD_LAZY);
	if(handle != NULL){
		for(int index = 0; index < ndat_size; ++index){
			char funcname[16] = "code_";
			char num[8];
			sprintf(num, "%d", index);
			strcat(funcname, num);
			old_list[index] = dlsym(handle, funcname);
			//printf("real mem address for code_%s = %p\n", num, old_list[index]);	
		}
	}
	get_base();
	long got_offset_max = LONG_MIN;
	long got_offset_min = LONG_MAX;
	long page_size = sysconf(_SC_PAGESIZE);
	// printf("%d\n", sizeof(got_list)/sizeof(long));
	for(int index = 0; index < ndat_size; ++index){
		if(got_list[index] != 0){
			if(got_offset_max < got_list[index]){
				got_offset_max = got_list[index];
			}
			if(got_offset_min > got_list[index]){
				got_offset_min = got_list[index];			
			}
		}
	}
	long chals_base = main_min - 0xb000;
	long got_base = chals_base + got_offset_min;
	long got_page_start = got_base & ~(page_size-1);
	int got_page_num = ((got_offset_max - got_offset_min)/page_size) + 1;
	void *got_page_ptr = (void*) got_page_start;
	// printf("%p, %p ,%p\n", chals_base, got_offset_min, (long*)got_page_ptr);
	// printf("\n%lx, %lx\n", got_offset_max, got_offset_min);
	if (mprotect(got_page_ptr, page_size * got_page_num, PROT_READ | PROT_WRITE) == -1) {
		perror("mprotect");
		exit(0);
		return 1;
	}
	for(int index = 0; index < ndat_size; ++index){
		if(got_list[index] != 0){
			// printf("%d ", index);
			long realaddr = (chals_base + got_list[index]);
			long* realptr = (long*) realaddr;
			int old_index;
			for(old_index = 0; old_index < ndat_size; old_index++){
				// printf("im here!");
				if (ndat[old_index] == index){
					break;
				} 
			}
			*realptr = old_list[old_index];
		}
	}
	return 0; 
}
