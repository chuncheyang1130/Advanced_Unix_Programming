#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <elf.h>
#include <dlfcn.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>

#define errquit(m){ perror(m); _exit(-1); }
#define MAP_SIZE 0x1000000
#define BUF_SIZE 1024
#define MAX_BUF_SIZE 131072
#define OPEN 0
#define READ 1
#define CONN 2
#define ADDR 3

//static long main_min = 0, main_max = 0;
static long exe_min = 0, exe_max = 0;

void get_base(char* executable);
int fetch_got();
int check_open(const char* content, const char* config_txt);
int check_read(const char* pathname, const char* config_tx);
int check_write(const char* filtername, const char* config_txt);
int check_getaddrinfo(const char* hostname, const char* config_txt);
int check_connect(const char* host_ip, unsigned short host_port, const char* config_txt);
int check_system(const char* cmd, const char* config_txt);

static int (*old_libc_start_main)(int *(main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end)) = NULL;
int __libc_start_main(int *(main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end));

int my_open(const char* pathname, ...);
static int (*my_open_ptr)(const char*, ...) = NULL;

ssize_t my_read(int fd, void* buf, size_t count);
static ssize_t (*my_read_ptr)(int fd, void* buf, size_t count) = NULL;

ssize_t my_write(int fd, void* buf, size_t count);
static ssize_t (*my_write_ptr)(int fd, void* buf, size_t count) = NULL;

int my_getaddrinfo(const char* hostname, const char *service, const struct addrinfo* hints, const struct addrinfo** result);
static int (*my_getaddrinfo_ptr)(const char* hostname, const char *service, const struct addrinfo* hints, const struct addrinfo** result) = NULL;

int my_connect(int fd, const struct sockaddr* addr, socklen_t addrlen);
static int (*my_connect_ptr)(int fd, const struct sockaddr* addr, socklen_t addrlen) = NULL;

int my_system(const char* cmd);
static int (*my_system_ptr)(const char* cmd) = NULL;

int __libc_start_main(int *(main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end)){
    //get_base();
    //fprintf(stderr, "libc min = %lx, libc max = %lx\n", libc_min, libc_max);

    fetch_got();

    if(old_libc_start_main == NULL){
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        //fprintf(stderr, "Old libc start main is at %p\n", handle);

        if(handle != NULL)
            old_libc_start_main = dlsym(handle, "__libc_start_main");
    }

    //fprintf(stderr, "Injected __libc_start_main!\n");

    int ret = old_libc_start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
    _exit(ret);
}

void get_base(char* executable) {
	int fd, sz;
	char buf[16384], *s = buf, *line, *saveptr;

    exe_max = 0;
    exe_min = 0;

	if(exe_max != 0) return;
	if((fd = open("/proc/self/maps", O_RDONLY)) < 0) errquit("get_base/open");
	if((sz = read(fd, buf, sizeof(buf)-1)) < 0) errquit("get_base/read");
	buf[sz] = 0;
	close(fd);

    // fprintf(stderr, "%s\n", buf);

	while((line = strtok_r(s, "\n\r", &saveptr)) != NULL) { 
        s = NULL;
		if(strstr(line, " r--p ") == NULL) continue;
		if(strstr(line, executable) != NULL) {
			if(sscanf(line, "%lx-%lx ", &exe_min, &exe_max) != 2) errquit("get_base/exe");
		} /* else if(strstr(line, "") != NULL) {
			if(sscanf(line, "%lx-%lx ", &main_min, &main_max) != 2) errquit("get_base/main");
		} */
        if(exe_min != 0 && exe_max != 0) return;
		//if(main_min!=0 && main_max!=0 && libc_min!=0 && libc_max!=0) return;
	}
	_exit(-fprintf(stderr, "get_base failed.\n"));
}

int fetch_got(){

    int fd;
    FILE* fp;
    ssize_t rl_sz;
    //size_t rd_sz;
    //int cur_pos;
    char buf[BUF_SIZE];

    /* Readlink exe */
    rl_sz = readlink("/proc/self/exe", buf, BUF_SIZE);
    buf[rl_sz] = 0;

    // fprintf(stderr, "The symbolic link is %s\n", buf);


    if((fd = open(buf, O_RDONLY)) < 0)
        perror("open exe");

    get_base(buf);

    // fprintf(stderr, "base address is 0x%lx\n", exe_min);
    void* map_start = mmap(NULL, 0x1000000, PROT_READ, MAP_PRIVATE, fd, 0);
    if(map_start == NULL)
        fprintf(stderr, "Error during mmap\n");

    /* Get ELF Header, Program Header, Section Header */
    Elf64_Ehdr* elf_header = (Elf64_Ehdr*)map_start;

    int section_offset = elf_header->e_shoff;
    int section_num = elf_header->e_shnum;

    Elf64_Shdr* section_header = (Elf64_Shdr*)((uintptr_t)map_start + section_offset);


    /* Get the offset of GOT Table and GOT Size */
    Elf64_Addr got_addr = 0;
    Elf64_Xword got_size = 0;
    uint64_t got_entry_size = 0;

    char *sh_str_table = (char*)((uintptr_t)map_start + section_header[elf_header->e_shstrndx].sh_offset);

    for(int i = 0; i < section_num; i++) {
        if(section_header[i].sh_type == SHT_PROGBITS && strcmp(".got", sh_str_table + section_header[i].sh_name) == 0) {
            got_addr = section_header[i].sh_addr;
            got_size = section_header[i].sh_size;
            got_entry_size = section_header[i].sh_entsize;
            break;
        }
    }

    if(got_addr == 0 || got_size == 0) {
        fprintf(stderr, "GOT address and size not found\n");
    }/* else{
        fprintf(stderr, "GOT address found at 0x%lx, and size of GOT is 0x%lx\n", got_addr, got_size);
    } */

    /* Get the offset of Symbol Table and Symbol Table Size */
    Elf64_Addr symtab_addr = 0;
    Elf64_Xword symtab_size = 0;

    for(int i = 0; i < section_num; i++) {
        if(section_header[i].sh_type == SHT_DYNSYM && strcmp(".dynsym", sh_str_table + section_header[i].sh_name) == 0) {
            symtab_addr = section_header[i].sh_addr;
            symtab_size = section_header[i].sh_size;
            break;
        }
    }
    
    if(symtab_addr == 0 || symtab_size == 0) {
        fprintf(stderr, "Symbol Table address and size not found\n");
    }/* else{
        fprintf(stderr, "Symbol Table address found at 0x%lx, and size of Symbol Table is 0x%lx\n", symtab_addr, symtab_size);
    } */

    /* Get the offset of Symbol String Table and Symbol String Table Size */
    Elf64_Addr sym_str_addr = 0;
    Elf64_Xword sym_str_size = 0;

    for(int i = 0; i < elf_header->e_shnum; i++) {
        if(section_header[i].sh_type == SHT_STRTAB && strcmp(".dynstr", sh_str_table + section_header[i].sh_name) == 0) {
            sym_str_addr = section_header[i].sh_addr;
            sym_str_size = section_header[i].sh_size;
            break;
        }
    }

    if(sym_str_addr == 0 || sym_str_size == 0) {
        fprintf(stderr, "Symbol String Table address and size not found\n");
    }/* else{
        fprintf(stderr, "Symbol String Table address found at 0x%lx, and size of Symbol String Table is 0x%lx\n", sym_str_addr, sym_str_size);
    } */

    /* Get Symbol table and Symbol string table */
    Elf64_Sym* symbol_table = (Elf64_Sym*)((uintptr_t)map_start + symtab_addr);
    char* sym_str_table = (char*)((uintptr_t)map_start + sym_str_addr);


    /* Get Relocation Table offset and Relocation Table size */
    Elf64_Addr rela_addr = 0;
    Elf64_Xword rela_size = 0;
    uint64_t rela_entry_size = 0;

    for(int i = 0; i < section_num; i++) {
        if(section_header[i].sh_type == SHT_RELA && strcmp(".rela.plt", sh_str_table + section_header[i].sh_name) == 0) {
            rela_addr = section_header[i].sh_addr;
            rela_size = section_header[i].sh_size;
            rela_entry_size = section_header[i].sh_entsize;
            break;
        }
    }
    
    if(rela_addr == 0 || rela_size == 0) {
        fprintf(stderr, "Relocation Table address and size not found\n");
    }/* else{
        fprintf(stderr, "Relocation Table address found at 0x%lx, and size of Relocation Table is 0x%lx\n", rela_addr, rela_size);
    } */

    /* Get relocation table */
    Elf64_Rela* rela_table = (Elf64_Rela*)((uintptr_t)map_start + rela_addr);

    long open_offset = -1;
    long read_offset = -1;
    long write_offset = -1;
    long connect_offset = -1;
    long getaddrinfo_offset = -1;
    long system_offset = -1;

    // fprintf(stderr, "entry size of rela entry: %d\n", got_entry_size);
    // fprintf(stderr, "number of got entries: %d\n", rela_size/rela_entry_size);
    
    for(int i = 0; i < rela_size / rela_entry_size; i++){
        int symtab_idx = ELF64_R_SYM(rela_table[i].r_info);
        Elf64_Sym* sym = &symbol_table[symtab_idx];

        // fprintf(stderr, "Current symbol: %s\n", sym_str_table + symbol_table[i].st_name);
        // fprintf(stderr, "Symbol of %s at %lx\n", sym_str_table + symbol_table[i].st_name, symbol_table[i].st_value);

        if(strcmp("open", sym_str_table + sym->st_name) == 0) {
            // fprintf(stderr, "GOT offset of open at %d\n", i);
            open_offset = rela_table[i].r_offset;
        }else if(strcmp("read", sym_str_table + sym->st_name) == 0) {
            // fprintf(stderr, "GOT offset of read at %d\n", i);
            read_offset = rela_table[i].r_offset;
        }else if(strcmp("write", sym_str_table + sym->st_name) == 0) {
            // fprintf(stderr, "GOT offset of write at %d\n", i);
            write_offset = rela_table[i].r_offset;
        }else if(strcmp("connect", sym_str_table + sym->st_name) == 0) {
            // fprintf(stderr, "GOT offset of connect at %d\n", i);
            connect_offset = rela_table[i].r_offset;
        }else if(strcmp("getaddrinfo", sym_str_table + sym->st_name) == 0) {
            // fprintf(stderr, "GOT offset of getaddrinto at %d\n", i);
            getaddrinfo_offset = rela_table[i].r_offset;
        }else if(strcmp("system", sym_str_table + sym->st_name) == 0) {
            // fprintf(stderr, "symbol name: %s\n", sym_str_table + sym->st_name);
            // fprintf(stderr, "GOT offset of system at %d\n", i);
            system_offset = rela_table[i].r_offset;
        }

        // fprintf(stderr, "current index: %d\n", i);
        // if(open_offset > 0 && read_offset > 0 && write_offset > 0 && connect_offset > 0 && getaddrinfo_offset > 0 && system_offset > 0){
        //     fprintf(stderr, "All Found\n");
        //     break;
        // }
            
    }

    munmap(map_start, 0x1000000);

    /* mprotect */
    long page_size = sysconf(_SC_PAGE_SIZE);
    // fprintf(stderr, "Page size is 0x%lx\n", page_size);
    long got_start = exe_min + got_addr;
    // fprintf(stderr, "Got address is 0x%lx\n", got_start);

    long got_end = got_start + got_size;

    long pg_start = got_start & ~(page_size-1);
    // fprintf(stderr, "Page start at 0x%lx\n", pg_start);
    long* pg_start_ptr = pg_start;

    long length = (got_end - pg_start) / page_size + 1;
    // fprintf(stderr, "Page start is at 0x%lx\n", pg_start);
    // fprintf(stderr, "The page start pointer is at %p\n", pg_start_ptr);

    int dis_prot_ok = mprotect(pg_start_ptr, length * page_size, PROT_READ | PROT_WRITE);
	if(dis_prot_ok < 0)
		fprintf(stderr, "There is error during mprotect\n");

    /* dlopen */
    void* handle = dlopen("/home/angus/hw1/sandbox.so", RTLD_LAZY);

    if(handle == NULL)
        fprintf(stderr, "cannot dlsym to sandbox.so\n");
        
    long* got_ptr;

    if(open_offset != -1){
        my_open_ptr = dlsym(handle, "my_open");
        got_ptr = exe_min + open_offset;
        *got_ptr = my_open_ptr;
        // fprintf(stderr, "got_ptr is at %p\n", got_ptr);
        //memcpy(got_ptr, &my_open_ptr, sizeof(long));
        //fprintf(stderr, "Hijack open!!!\n");
    }

    if(read_offset != -1){
        my_read_ptr = dlsym(handle, "my_read");
        got_ptr = exe_min + read_offset;
        // fprintf(stderr, "got_ptr is at %p\n", got_ptr);
        // fprintf(stderr, "got_ptr is at %p\n", my_read_ptr);
        *got_ptr = my_read_ptr;
        
        //memcpy(got_ptr, &my_read_ptr, sizeof(long));
    }

    if(write_offset != -1){
        my_write_ptr = dlsym(handle, "my_write");
        got_ptr = exe_min + write_offset;
        *got_ptr = my_write_ptr;
        //memcpy(got_ptr, &my_write_ptr, sizeof(long));
    }

    if(getaddrinfo_offset != -1){
        my_getaddrinfo_ptr = dlsym(handle, "my_getaddrinfo");
        got_ptr = exe_min + getaddrinfo_offset;
        *got_ptr = my_getaddrinfo_ptr;
        //memcpy(got_ptr, &my_getaddrinfo_ptr, sizeof(long));
    }

    if(connect_offset != -1){
        my_connect_ptr = dlsym(handle, "my_connect");
        got_ptr = exe_min + connect_offset;
        *got_ptr = my_connect_ptr;
        //memcpy(got_ptr, &my_connect_ptr, sizeof(long));
    }

    if(system_offset != -1){
        my_system_ptr = dlsym(handle, "my_system");
        got_ptr = exe_min + system_offset;
        *got_ptr = my_system_ptr;

        // fprintf(stderr, "got_ptr is at %p\n", got_ptr);
        //memcpy(got_ptr, &my_connect_ptr, sizeof(long));
    }

    close(fd);

    return 0;
}

int check_open(const char* pathname, const char* config_txt){

    FILE* fp;
    char* line = NULL;
    size_t len = 0;
    ssize_t sz = 0;

    if((fp = fopen(config_txt, "r")) == NULL)
        perror("fopen()");

    int state = 0;
    while((sz = getline(&line, &len, fp)) != -1){
        // fprintf(stderr, "line: %s", line);
        if(strncmp("BEGIN open-blacklist", line, strlen("BEGIN open-blacklist")) == 0)
            state = 1;
        else if(strncmp("END open-blacklist", line, strlen("END open-blacklist")) == 0)
            state = 2;
        
        if(state == 1){
            line[strlen(line)-1] = 0;
            if(strcmp(pathname, line) == 0){
                fclose(fp);
                return 0; /* Not able to open*/
            }
        }else if(state == 2){
            fclose(fp);
            return 1; /*Able to open*/
        }
    }

    return 1;
}

int my_open(const char* pathname, ...){

    int logger_fd = atoi(getenv("LOGGER_FD"));
    //fprintf(stderr, "logger_fd is %d\n", logger_fd);
    if(dup2(fileno(stderr), logger_fd) == -1){
        perror("dup2()");
    }

    char* config_path = getenv("SANDBOX_CONFIG");

    va_list args;
    va_start(args, pathname);

    // fprintf(stderr, "Injected my open: %s\n", pathname);

    int fd = 0;
    unsigned int flags = va_arg(args, unsigned int);

    mode_t mode = 0;

    if(flags & O_CREAT > 0 || flags & O_TMPFILE > 0)
        mode = va_arg(args, mode_t);

    va_end(args);

    struct stat st;
    int status = lstat(pathname, &st);
    ssize_t rl_sz;
    
    char* real_path = calloc(BUF_SIZE, sizeof(char));
    // fprintf(stderr, "pathname is %s\n", pathname);

    if(S_ISLNK(st.st_mode)){
        rl_sz = readlink(pathname, real_path, BUF_SIZE);
        real_path[rl_sz] = 0;
    }else{
        strcpy(real_path, pathname);
    }

    // fprintf(stderr, "real path is %s\n", real_path);
    
    if(mode == 0){
        if(!check_open(pathname, config_path)){
            fprintf(stderr, "[LOGGER] open(\"%s\", %u, 0) = -1\n", pathname, flags);
            errno = EACCES;
            return -1;
        }else{
            fd = open(real_path, flags);
            //FILE* fp = fopen(pathname, "r");
            fprintf(stderr, "[LOGGER] open(\"%s\", %u, 0) = %d\n", pathname, flags, fd);
            return fd;
            //return fileno(fp);
        }
        
    }else{
        if(!check_open(pathname, config_path)){
            fprintf(stderr, "[LOGGER] open(\"%s\", %u, %o) = -1\n", pathname, flags, mode);
            errno = EACCES;
            return -1;
        }else{
            fd = open(real_path, flags, mode);
            //FILE* fp = fopen(pathname, "r");
            fprintf(stderr, "[LOGGER] open(\"%s\", %u, %o) = %d\n", pathname, flags, mode, fd);
            return fd;
            //return fileno(fp);
        }
    }

    // close(logger_fd);
}

int check_read(const char* filtername, const char* config_txt){

    FILE* fp;
    char* line = NULL;
    size_t len = 0;
    ssize_t sz = 0, rd_sz = 0;

    if((fp = fopen(config_txt, "r")) == NULL)
        perror("fopen()");

    int filter_fd;
    
    // fprintf(stderr, "filtername: %s\n", filtername);
    if((filter_fd = open(filtername, O_RDONLY)) < 0)
        perror("open filter in check");

    char buf[MAX_BUF_SIZE];
    if((rd_sz = read(filter_fd, buf, MAX_BUF_SIZE)) < 0)
        perror("read filter in check");

    int state = 0;
    while((sz = getline(&line, &len, fp)) != -1){
        // fprintf(stderr, "line: %s", line);
        if(strncmp("BEGIN read-blacklist", line, strlen("BEGIN read-blacklist")) == 0)
            state = 1;
        else if(strncmp("END read-blacklist", line, strlen("END read-blacklist")) == 0)
            state = 2;
        
        if(state == 1){
            line[strlen(line)-1] = 0;
            // fprintf(stderr, "read blacklist: %s\n", line);
            if(strstr(buf, line) != NULL){
                fclose(fp);
                close(filter_fd);
                if(remove(filtername) != 0)
                    perror("remove"); 
                return 0; /* Not able to open*/
            }
        }else if(state == 2){
            fclose(fp);
            close(filter_fd);
            return 1; /*Able to open*/
        }
    }

    return 1;
}

ssize_t my_read(int fd, void* buf, size_t count){

    int logger_fd = atoi(getenv("LOGGER_FD"));
    // fprintf(stderr, "logger_fd is %d\n", logger_fd);
    if(dup2(fileno(stderr), logger_fd) == -1){
        perror("dup2()");
    }

    char* config_path = getenv("SANDBOX_CONFIG");

    // fprintf(stderr, "Injected my read fd: %d\n", fd);

    char filename[BUF_SIZE], fd_link[BUF_SIZE], filtername[BUF_SIZE+15], logfile_name[BUF_SIZE];
    ssize_t rl_sz, wr_sz;

    /* Get the link to real path of the file that is opened on the fd */
    sprintf(fd_link, "/proc/self/fd/%d", fd);

    if((rl_sz = readlink(fd_link, filename, BUF_SIZE)) < 0)
        perror("readlink");

    filename[rl_sz] = 0;

    /* Create a filter file */
    sprintf(filtername, "./filter/filter%s", filename);


    for(int i = 0; i < strlen(filtername); i++){
        if(i <= 8)
            continue;
            
        if(filtername[i] == '/' | filtername[i] == '.'){
            filtername[i] = '-';
        }
    }
    
    // fprintf(stderr, "filtername: %s\n", filtername);

    int filter_fd;
    if((filter_fd = open(filtername, O_CREAT | O_RDWR | O_APPEND, 0777)) < 0){
        // fprintf(stderr, "cannot create filtername: %s\n", filtername);
        if(errno == EEXIST){
            if( (filter_fd = open(filtername, O_APPEND, 0777)) < 0)
                perror("filter open");
        }/* else{
            fprintf(stderr, "filter open: %s\n", strerror(errno));
        } */
    }

    // fprintf(stderr, "filtername: %s\n", filtername);

    /* Create a log file if not exist, open it if already exist */
    sprintf(logfile_name, "./logs/%d-%d-read.log", getpid(), fd);
    
    int logfile_fd;
    if((logfile_fd = open(logfile_name, O_CREAT | O_RDWR | O_APPEND, 0777)) < 0){
        if(errno == EEXIST){
            if((logfile_fd = open(logfile_name, O_APPEND, 0777)) < 0)
                perror("logfile open");
        }
    }

    /* Read from fd */
    char tmp_buf[MAX_BUF_SIZE];
    ssize_t rd_sz;
    if((rd_sz = read(fd, tmp_buf, count)) < 0)
        perror("fd read");

    /* Filter content */
    // fprintf(stderr, "filter fd: %d\n", filter_fd);
    if( (wr_sz = write(filter_fd, tmp_buf, rd_sz)) < 0)
        perror("filter write");
    
    // fprintf(stderr, "filtername: %s\n", filtername);

    close(filter_fd);
    if(!check_read(filtername, config_path)){
        close(fd);
        fprintf(stderr, "[LOGGER] read(%d, %p, %ld) = -1\n", fd, buf, count);
        errno = EIO;
        return -1;
    }else{
        fprintf(stderr, "[LOGGER] read(%d, %p, %ld) = %ld\n", fd, buf, count, rd_sz);
    }

    if( (wr_sz = write(logfile_fd, tmp_buf, rd_sz)) < 0)
        perror("logfile write");

    strncpy(buf, tmp_buf, rd_sz);
    // fprintf(stderr, "sizeof buf: %d\n", buf);

    // fprintf(stderr, "read size: %d\n", rd_sz);
    
    return rd_sz;
    // close(logger_fd);
}

int check_write(const char* filtername, const char* config_txt){

    FILE* fp;
    char* line = NULL;
    size_t len = 0;
    ssize_t sz = 0, rd_sz = 0;

    if((fp = fopen(config_txt, "r")) == NULL)
        perror("fopen()");

    int filter_fd;
    
    // fprintf(stderr, "filtername: %s\n", filtername);
    if((filter_fd = open(filtername, O_RDONLY)) < 0)
        perror("open filter in check");

    char buf[2*BUF_SIZE];
    if((rd_sz = read(filter_fd, buf, BUF_SIZE)) < 0)
        perror("read filter in check");

    int state = 0;
    while((sz = getline(&line, &len, fp)) != -1){
        // fprintf(stderr, "line: %s", line);
        if(strncmp("BEGIN write-blacklist", line, strlen("BEGIN write-blacklist")) == 0)
            state = 1;
        else if(strncmp("END write-blacklist", line, strlen("END write-blacklist")) == 0)
            state = 2;
        
        if(state == 1){
            line[strlen(line)-1] = 0;
            // fprintf(stderr, "read blacklist: %s\n", line);
            if(strstr(buf, line) != NULL){
                fclose(fp);
                close(filter_fd);
                if(remove(filtername) != 0)
                    perror("remove");

                return 0; /* Not able to open*/
            }
        }else if(state == 2){
            fclose(fp);
            close(filter_fd);
            return 1; /*Able to open*/
        }
    }

    return 1;
}

ssize_t my_write(int fd, void* buf, size_t count){

    int logger_fd = atoi(getenv("LOGGER_FD"));
    //fprintf(stderr, "logger_fd is %d\n", logger_fd);
    if(dup2(fileno(stderr), logger_fd) == -1){
        perror("dup2()");
    }

    char* config_path = getenv("SANDBOX_CONFIG");

    // fprintf(stderr, "Injected my read fd: %d\n", fd);

    char filename[BUF_SIZE], fd_link[BUF_SIZE], filtername[BUF_SIZE+16], logfile_name[BUF_SIZE];
    ssize_t rl_sz, wr_sz;

    /* Get the link to real path of the file that is opened on the fd */
    sprintf(fd_link, "/proc/self/fd/%d", fd);

    if((rl_sz = readlink(fd_link, filename, BUF_SIZE)) < 0)
        perror("readlink");

    filename[rl_sz] = 0;

    /* Create a filter file */
    sprintf(filtername, "./filter/filter-%s", filename);


    for(int i = 0; i < strlen(filtername); i++){
        if(i <= 8)
            continue;

        if(filtername[i] == '/' | filtername[i] == '.'){
            filtername[i] = '-';
        }
    }

    
    
    // fprintf(stderr, "filtername: %s\n", filtername);

    int filter_fd;
    if((filter_fd = open(filtername, O_CREAT | O_RDWR | O_APPEND, 0777)) < 0){
        // fprintf(stderr, "cannot create filtername: %s\n", filtername);
        if(errno == EEXIST){
            if( (filter_fd = open(filtername, O_APPEND, 0777)) < 0)
                perror("filter open");
        }/* else{
            fprintf(stderr, "filter open: %s\n", strerror(errno));
        } */
    }

    /* Create a log file if not exist, open it if already exist */
    sprintf(logfile_name, "./logs/%d-%d-write.log", getpid(), fd);
    
    int logfile_fd;
    if((logfile_fd = open(logfile_name, O_CREAT | O_RDWR | O_APPEND, 0777)) < 0){
        if(errno == EEXIST){
            if((logfile_fd = open(logfile_name, O_APPEND, 0777)) < 0)
                perror("logfile open");
        }
    }

    // fprintf(stderr, "filtername: %s\n", filtername);

    /* Read from buf */
    // char tmp_buf[MAX_BUF_SIZE];
    // ssize_t rd_sz;
    // if((rd_sz = read(fd, tmp_buf, count)) < 0)
    //     perror("fd read");

    /* Filter content */
    // fprintf(stderr, "filter fd: %d\n", filter_fd);
    if( (wr_sz = write(filter_fd, buf, strlen(buf))) < 0)
        perror("filter write");
    
    // fprintf(stderr, "filtername: %s\n", filtername);

    close(filter_fd);
    if(!check_write(filtername, config_path)){
        close(fd);
        fprintf(stderr, "[LOGGER] write(%d, %p, %ld) = -1\n", fd, buf, count);
        errno = EIO;
        return -1;
    }else{
        /* Write to fd */
        if((wr_sz = write(fd, buf, count)) < 0)
            perror("fd write");
        fprintf(stderr, "[LOGGER] write(%d, %p, %ld) = %ld\n", fd, buf, count, strlen(buf));
    }

    if( (wr_sz = write(logfile_fd, buf, strlen(buf))) < 0)
        perror("logfile write");

    // strcpy(buf, tmp_buf);
    
    return strlen(buf);
    // close(logger_fd);
}

int check_getaddrinfo(const char* hostname, const char* config_txt){
    FILE* fp;
    char* line = NULL;
    size_t len = 0;
    ssize_t sz = 0, rd_sz = 0;

    if((fp = fopen(config_txt, "r")) == NULL)
        perror("fopen()");

    int state = 0;

    while((sz = getline(&line, &len, fp)) != -1){
        // fprintf(stderr, "line: %s", line);
        if(strncmp("BEGIN getaddrinfo-blacklist", line, strlen("BEGIN getaddrinfo-blacklist")) == 0)
            state = 1;
        else if(strncmp("END getaddrinfo-blacklist", line, strlen("END getaddrinfo-blacklist")) == 0)
            state = 2;
        
        if(state == 1){
            line[strlen(line)-1] = 0;
            // fprintf(stderr, "read blacklist: %s\n", line);
            if(strcmp(hostname, line) == 0){
                fclose(fp);
                return 0; /* Not able to open*/
            }
        }else if(state == 2){
            fclose(fp);
            return 1; /*Able to open*/
        }
    }
    
    return 1;
}

int my_getaddrinfo(const char* hostname, const char *service, const struct addrinfo* hints, const struct addrinfo** result){

    int logger_fd = atoi(getenv("LOGGER_FD"));
    //fprintf(stderr, "logger_fd is %d\n", logger_fd);
    if(dup2(fileno(stderr), logger_fd) == -1){
        perror("dup2()");
    }

    char* config_path = getenv("SANDBOX_CONFIG");

    if(!check_getaddrinfo(hostname, config_path)){
        fprintf(stderr, "[LOGGER] getaddrinfo(\"%s\", %p, %p, %p) = %d\n", hostname, service, hints, result, EAI_NONAME);
        return EAI_NONAME;
    }else{
        if(getaddrinfo(hostname, service, hints, result) != 0){
            fprintf(stderr, "[LOGGER] getaddrinfo(\"%s\", %p, %p, %p) = %d\n", hostname, service, hints, result, EAI_NONAME);
            return EAI_NONAME;
        }else{
            fprintf(stderr, "[LOGGER] getaddrinfo(\"%s\", %p, %p, %p) = 0\n", hostname, service, hints, result);
            return 0;
        }
    }

}

int check_connect(const char* host_ip, unsigned short host_port, const char* config_txt){

    FILE* fp;
    char* line = NULL;
    size_t len = 0;
    ssize_t sz = 0, rd_sz = 0;

    if((fp = fopen(config_txt, "r")) == NULL)
        perror("fopen()");

    int state = 0;
    while((sz = getline(&line, &len, fp)) != -1){
        // fprintf(stderr, "line: %s", line);
        if(strncmp("BEGIN connect-blacklist", line, strlen("BEGIN connect-blacklist")) == 0)
            state = 1;
        else if(strncmp("END connect-blacklist", line, strlen("END connect-blacklist")) == 0)
            state = 2;
        
        if(state == 1){
            line[strlen(line)-1] = 0;
            // fprintf(stderr, "read blacklist: %s\n", line);

            char hostname[50], str_port[50];

            char* token = strtok(line, ":");
            strcpy(hostname, token);
            // hostname[strlen(hostname)-1] = 0;

            token = strtok(NULL, ":");
            if(token == NULL)
                continue;

            strcpy(str_port, token);
            //str_port[strlen(str_port)-1] = 0;
            
            unsigned short port = atoi(str_port);

            
            // fprintf(stderr, "port: %s\n", str_port);
            // fprintf(stderr, "host_port: %u, port: %u\n", host_port, port);

            if(port != host_port)
                continue;

            // fprintf(stderr, "hostname: %s\n", hostname);
            struct hostent* ret = gethostbyname(hostname);
            struct in_addr** ip_list = (struct in_addr**)ret->h_addr_list;

            if(ret->h_addrtype == AF_INET){
                for(struct in_addr** ip_ptr = ip_list; *ip_ptr != NULL; ip_ptr++){
                    char* ip = calloc(50, sizeof(char));
                    // fprintf(stderr, "ip: %s, host_ip: %s\n", inet_ntop(AF_INET, **ip, tmp_ip, 50), host_ip);
                    ip = inet_ntop(AF_INET, *ip_ptr, ip, 50);

                    if(strcmp(ip, host_ip) == 0){
                        fclose(fp);
                        return 0;
                    }
                }
            }
        
        }else if(state == 2){
            fclose(fp);
            return 1; /*Able to open*/
        }
    }

    return 1;
}

int my_connect(int fd, const struct sockaddr* addr, socklen_t addrlen){
    int logger_fd = atoi(getenv("LOGGER_FD"));
    //fprintf(stderr, "logger_fd is %d\n", logger_fd);
    if(dup2(fileno(stderr), logger_fd) == -1){
        perror("dup2()");
    }

    char* config_path = getenv("SANDBOX_CONFIG");

    struct sockaddr_in* host_addr = (struct sockaddr_in*)addr;
    unsigned short port = ntohs(host_addr->sin_port);
    struct in_addr sin_addr = host_addr->sin_addr;

    char* ip = calloc(50, sizeof(char));
    ip = inet_ntop(AF_INET, &sin_addr, ip, 50);

    // fprintf(stderr, "ip addr: %s\n", ip);
    // fprintf(stderr, "port: %u\n", port);

    if(!check_connect(ip, port, config_path)){
        fprintf(stderr, "[LOGGER] connect(%d, \"%s\", %u) = -1\n", fd, ip, addrlen);
        errno = ECONNREFUSED;
        return -1;
    }else{
        if(connect(fd, addr, addrlen) < 0){
            fprintf(stderr, "[LOGGER] connect(%d, \"%s\", %u) = -1\n", fd, ip, addrlen);
            errno = ECONNREFUSED;
            return -1;
        }else{
            fprintf(stderr, "[LOGGER] connect(%d, \"%s\", %u) = 0\n", fd, ip, addrlen);
            return 0;
        }
    }
   
}

int check_system(const char* cmd, const char* config_txt){
    FILE* fp;
    char* line = NULL;
    size_t len = 0;
    ssize_t sz = 0, rd_sz = 0;

    if((fp = fopen(config_txt, "r")) == NULL)
        perror("fopen()");

    int state = 0;
    while((sz = getline(&line, &len, fp)) != -1){
        // fprintf(stderr, "line: %s", line);
        if(strncmp("BEGIN system-blacklist", line, strlen("BEGIN system-blacklist")) == 0)
            state = 1;
        else if(strncmp("END system-blacklist", line, strlen("END system-blacklist")) == 0)
            state = 2;
        
        if(state == 1){
            line[strlen(line)-1] = 0;
            // fprintf(stderr, "read blacklist: %s\n", line);
            if(strcmp(cmd, line) == 0){
                fclose(fp);
                return 0; /* Not able to open*/
            }
        }else if(state == 2){
            fclose(fp);
            return 1; /*Able to open*/
        }
    }
    
    return 1;
}

int my_system(const char* cmd){

    int logger_fd = atoi(getenv("LOGGER_FD"));
    //fprintf(stderr, "logger_fd is %d\n", logger_fd);
    if(dup2(fileno(stderr), logger_fd) == -1){
        perror("dup2()");
    }

    char* config_path = getenv("SANDBOX_CONFIG");

    if(!check_system(cmd, config_path)){
        fprintf(stderr, "[LOGGER] system(\"%s\")\n", cmd);
        return 127;
    }else{
        fprintf(stderr, "[LOGGER] system(\"%s\")\n", cmd);
        char new_cmd[50];
        strncpy(new_cmd, cmd, strlen(cmd));
        int status = system(new_cmd);
        // fprintf(stderr, "status: %d\n", status);

        if(WIFSIGNALED(status)){
            fprintf(stderr, "%d\n", WTERMSIG(status));
        }

        // if(WCOREDUMP(status)){
        //     fprintf(stderr, "core dump\n");
        // }

        return status;
    }
}