/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <libunwind.h>
#include <sys/mman.h>
#include "libpoem.h"
#include "functaddr.h"
#include "shuffle.h"


#define errquit(m){ perror(m); _exit(-1); }

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
		} else if(strstr(line, "/chal") != NULL) {
			if(sscanf(line, "%lx-%lx ", &main_min, &main_max) != 2) errquit("get_base/main");
		}
		if(main_min!=0 && main_max!=0 && poem_min!=0 && poem_max!=0) return;
	}
	_exit(-fprintf(stderr, "** get_base failed.\n"));
}

int init(){ 
	get_base();
    int len = 689;

    int (*old_funct)(void);
	
    void* handle = dlopen("./libpoem.so", RTLD_LAZY);
	
	char* gap_str = "b000";
	long gap;
	sscanf(gap_str, "%lx", &gap);

	long prog_start = main_min - gap;
	long got_start = prog_start + 0x17a30;
	
	fprintf(stderr, "Program start position: %lx\n", prog_start);
	fprintf(stderr, "GOT start position: %lx\n", got_start);

	long page_size = sysconf(_SC_PAGE_SIZE);

	long got_end = prog_start + 0x18fc8;

	long got_range = got_end - got_start;
	//fprintf(stderr, "GOT range is %ld\n", got_range);

	long length = got_range / page_size + 1;
	//fprintf(stderr, "len: %ld\n", length);

	long pg_start = got_start & ~(page_size-1);
	long* pg_start_ptr = pg_start;
	
	//fprintf(stderr, "Page start at %p\n", pg_start_ptr);

	int dis_prot_ok = mprotect(pg_start_ptr, length * page_size, PROT_WRITE);
	if(dis_prot_ok < 0)
		fprintf(stderr, "There is error during mprotect\n");

    //fprintf(stderr, "Main Min: %lx\n", main_min);
	//fprintf(stderr, "Main Max: %lx\n", main_max);

    if(handle != NULL){
        for(int i = 0; i < len; i++){
            char funct[20];
            
            strcpy(funct, addr[i][0]);

			int modify_num;
			sscanf(&funct[5], "%d", &modify_num);
			//printf("current function is code %d\n", num);


			int num = 0;
			for(; num < 1477; num++){
				if(ndat[num] == modify_num)
					break;
			}
			//printf("the position of code %d is modified to code %d\n", modify_num, num);

			char rel_addr[10];
			strcpy(rel_addr, addr[i][1]);

			long rel_offset;
			sscanf(rel_addr, "%lx", &rel_offset);
			//fprintf(stderr, "relative offset is %lx\n", rel_offset);
			
			long got_pos = prog_start + rel_offset;
			//fprintf(stderr, "Got position is %lx\n", got_pos);
			long* got_ptr = got_pos;
			
			char new_funct[20];
			char new_funct_num[20];
			sprintf(new_funct_num, "%d", num);

			strcpy(new_funct, "code_");
			strcat(new_funct, new_funct_num);

            old_funct = dlsym(handle, new_funct);
			//fprintf(stderr, "Memory Position: %p\n", old_funct);

			*got_ptr = (long)old_funct;
			//fprintf(stderr, "passed\n");
        }

        
    }
    

	return 0; 
}

