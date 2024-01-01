#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/user.h>
#include <string.h>
#include <elf.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <capstone/capstone.h>
#include <fcntl.h>

#define CODE_SIZE  0x10000
#define MEM_SIZE   0x1000
#define BUF_SIZE   0x1000
#define STACK_SIZE 0x21000
#define HEAP_SIZE  0x21000
#define CMD_LEN    50
#define MAP_LEN    50
#define ull unsigned long long 

pid_t child;
int status;
void* prog_ptr;
Elf64_Addr entry_point;

off_t text_offset = 0;      
size_t text_size = 0;
ull base_addr = 0;

int anchor_is_bp = 0;
int exit_sign = 0;
csh cshandle = 0;

char cmd[CMD_LEN];
unsigned char code_buffer[CODE_SIZE];

ull write_min = 0;
ull write_max = 0;
ull stack_min = 0;
ull stack_max = 0;
ull heap_min = 0;
ull heap_max = 0;

ull snapshot_buffer[MEM_SIZE] = { 0 };
ull stack_buffer[STACK_SIZE] = { 0 };
ull heap_buffer[HEAP_SIZE] = { 0 };
struct user_regs_struct snapshot_regs;

int cur_new_bp = 0;

ull GetCurRip();
void Disasm();
int Step();
int Cont();
void Breakpoint(char* bp);
int HitBp();
void Anchor(char* maps_path, char* executable);
void TimeTravel();

int main(int argc, char* argv[]){

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    if( (child = fork()) < 0){
        perror("fork()");
    }

    if(child == 0){
        // printf("child\n");

        if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
            perror("ptrace");
        
        execvp(argv[1], argv+1);
        perror("execvp");

    }else if(child > 0){
        
        ssize_t numb;


        if(waitpid(child, &status, 0) < 0)
            perror("wait");

        // assert(WIFSTOPPED(status));

        if(ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL) < 0)
            perror("ptrace setopt");

        /* mmap elf file */
        int fd;
        if( (fd = open(argv[1], O_RDONLY)) < 0)
            perror("open elf");

        prog_ptr = mmap(NULL, CODE_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
        if(prog_ptr == NULL)
            fprintf(stderr, "Error during mmap\n");

        // fprintf(stderr, "Program Pointer at %p\n", prog_ptr);
        
        /* Get entry point */
        Elf64_Ehdr* elf_hdr = (Elf64_Ehdr*)prog_ptr;
        entry_point = elf_hdr->e_entry;

        // Get text section
        Elf64_Shdr* shdr = (Elf64_Shdr*)((uintptr_t)prog_ptr + elf_hdr->e_shoff);
        char *sh_str_table = (char*)((uintptr_t)prog_ptr + shdr[elf_hdr->e_shstrndx].sh_offset);

        for(int i = 0; i < elf_hdr->e_shnum; i++) {
            if(shdr[i].sh_type == SHT_PROGBITS && strcmp(".text", sh_str_table + shdr[i].sh_name) == 0) {
                text_offset = shdr[i].sh_offset;
                text_size = shdr[i].sh_size;
                base_addr = shdr[i].sh_addr;
                break;
            }
        }

        if(text_offset == 0 || text_size == 0 || base_addr == 0) 
            fprintf(stderr, "text offset and size not found\n");
    
             
        /* Print entry point info */ 
        fprintf(stdout, "** program \'%s\' loaded. entry point 0x%lx\n", argv[1], entry_point);

        // memset(code_buffer, 0, CODE_SIZE);

        memcpy(code_buffer, prog_ptr+text_offset, text_size);

        // for(int i = 0; i < (text_size / 16 + 1); i++){
        //     for(int j = 0; j < 16; j++)
        //         fprintf(stderr, "%x\t", code_buffer[i*16+j]);
        //     fprintf(stderr, "\n");
        // }

        /* Child mapping */
        char maps_path[MAP_LEN];
        sprintf(maps_path, "/proc/%d/maps", child);


        /* Disassemble */ 
        if(cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK)
            perror("cs_open");


        cs_insn* insn;
        // fprintf(stderr, "Base addr: %llx\n", base_addr);

        int instr_count = cs_disasm(cshandle, &code_buffer[entry_point-base_addr], text_size, entry_point, 0, &insn);

        cs_free(insn, instr_count);

        /* Start program */
        Disasm(entry_point);

        int hit_bp = 0;
        ull cur_rip;
        
        while(!exit_sign){

            fprintf(stdout, "(sdb) ");
            // fflush(stdout);

            memset(cmd, 0, CMD_LEN);

            if(read(0, cmd, CMD_LEN) < 0)
                perror("read cmd from user");

            cmd[strlen(cmd)-1] = 0;
            // fprintf(stderr, "cmd: %s\n", cmd);

            if(strcmp(cmd, "exit") == 0){
                exit_sign = 1;
            }else if(strcmp(cmd, "si") == 0){
                
                if(cur_new_bp){
                    hit_bp = HitBp();
                    cur_new_bp = 0;
                }else if(hit_bp){
                    hit_bp = HitBp();
                }else{
                    hit_bp = Step();
                }

                if(exit_sign){
                    continue;
                }else{
                    Disasm();
                }

            }else if(strcmp(cmd, "cont") == 0){

                if(cur_new_bp){
                    hit_bp = HitBp();
                    cur_new_bp = 0;

                    if(!hit_bp)
                        hit_bp = Cont();

                }else if(hit_bp){
                    hit_bp = HitBp();

                    if(!hit_bp)
                        hit_bp = Cont();
                        
                }else{
                    hit_bp = Cont();
                }
            
                if(exit_sign){
                    continue;
                }else{
                    Disasm();
                }

            }else if(strncmp(cmd, "break", 5) == 0){
                char* tmp_cmd = strdup(cmd);
                char* bp = strtok(tmp_cmd, " ");
                bp = strtok(NULL, " ");
                 
                // fprintf(stderr, "bp: %s\n", bp);

                Breakpoint(bp);
            }else if(strcmp(cmd, "anchor") == 0){
                Anchor(maps_path, argv[1]+2);
            }else if(strcmp(cmd, "timetravel") == 0){
                TimeTravel();
                hit_bp = anchor_is_bp;
                Disasm();
            }

        }
        
        cs_close(&cshandle);
        
        if(munmap(prog_ptr, CODE_SIZE) < 0)
            perror("munmap");

        if(close(fd) < 0)
            perror("close");

    }
}

ull GetCurRip(){
    struct user_regs_struct tmp_regs;
    ull cur_rip;

    if(ptrace(PTRACE_GETREGS, child, 0, &tmp_regs) == 0)
        cur_rip = tmp_regs.rip;

    return cur_rip;
}

void Disasm(){

    ull cur_rip = GetCurRip();

    cs_insn* insn;

    int instr_count = cs_disasm(cshandle, &code_buffer[entry_point-base_addr], text_size, entry_point, 0, &insn);
    // fprintf(stderr, "instr_count: %d\n", instr_count);

    int idx = 0;
    while((ull)insn[idx].address < cur_rip)
        idx++;

    // fprintf(stderr, "idx: %d\n", idx);

    for(int i = idx; i < (idx+5 > instr_count ? instr_count : idx+5); i++){
        fprintf(stdout, "\t0x%"PRIx64": ", insn[i].address);

        for(int j = 0; j < insn[i].size; j++)
            fprintf(stdout, "%02x ", insn[i].bytes[j]);
        
        for (int j = insn[i].size; j < 9; j++) 
            fprintf(stdout, "   ");
        
        fprintf(stdout, "\t%s\t%s\n", insn[i].mnemonic, insn[i].op_str);
    }

    cs_free(insn, instr_count);

    if(idx+5 > instr_count)
        fprintf(stdout, "** the address is out of the range of the text section.\n");
}

int Step(){

    if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0)
        perror("ptrace single step");
    
    if(waitpid(child, &status, 0) < 0)
        perror("wait");

    if((WIFEXITED(status))){
        fprintf(stdout, "** the target program terminated.\n");
        exit_sign = 1;
        return 0;
    }

    ull cur_rip = GetCurRip();

    /* Check if there is 0xcc */
    ull code = ptrace(PTRACE_PEEKTEXT, child, cur_rip, 0);
    // fprintf(stderr, "orig_code: %lx\n", orig_code);

    // fprintf(stderr, "%lx\n", code);
    // fprintf(stderr, "%x\n", (0xcc & 0xcd));

    if(code - (code & 0xffffffffffffff00) != 0xcc)
        return 0;

    // fprintf(stderr, "%lx\n", (code & 0x00000000000000cc));

    if(!cur_new_bp)
        fprintf(stdout, "** hit a breakpoint at 0x%llx.\n", cur_rip);
    
    return 1;
    // HitBp(cur_rip);

    // fprintf(stderr, "** step\n");
}

int Cont(){

    if(ptrace(PTRACE_CONT, child, 0, 0) < 0)
        perror("ptrace cont");

    if(waitpid(child, &status, 0) < 0)
        perror("wait");

    if((WIFEXITED(status))){
        fprintf(stdout, "** the target program terminated.\n");
        exit_sign = 1;
        return 0;
    }
    
    struct user_regs_struct tmp_regs;

    if(ptrace(PTRACE_GETREGS, child, 0, &tmp_regs) < 0)
        perror("ptrace GETREGS");

    tmp_regs.rip = tmp_regs.rip-1;

    if(ptrace(PTRACE_SETREGS, child, 0, &tmp_regs) < 0)
        perror("ptrace SETREGS");

    ull cur_rip = GetCurRip();

    if(!cur_new_bp)
        fprintf(stdout, "** hit a breakpoint at 0x%llx.\n", cur_rip);

    return 1;
    // HitBp(cur_rip);
}

void Breakpoint(char* bp){
    unsigned long bp_value = (unsigned long)strtol(bp, NULL, 16);
    // fprintf(stderr, "bp: %lx\n", bp_value);
    
    /* original text */
    ull orig_code = ptrace(PTRACE_PEEKTEXT, child, bp_value, 0);
    // fprintf(stderr, "orig_code: %lx\n", orig_code);

    if(ptrace(PTRACE_POKETEXT, child, bp_value, (orig_code & 0xffffffffffffff00) | 0xcc) < 0)
        perror("ptrace POKETEXT");

    ull cur_rip = GetCurRip();

    if(cur_rip == bp_value)
        cur_new_bp = 1;

    // fprintf(stderr, "cur_rip: %llx, bp_value: %llx, cur_new_bp: %x\n", cur_rip, bp_value, cur_new_bp);

    fprintf(stdout, "** set a breakpoint at 0x%lx.\n", bp_value);
}

int HitBp(){
    ull cur_rip = GetCurRip();

    ull offset = cur_rip - base_addr;

    struct user_regs_struct tmp_regs;
    uint8_t orig_byte = code_buffer[offset];
    // fprintf(stderr, "orig_byte: %u\n", orig_byte);

    ull orig_code = ptrace(PTRACE_PEEKTEXT, child, cur_rip, 0);


    ull new_code = orig_code;
    new_code = ((new_code & 0xffffffffffffff00) | orig_byte);

    if(ptrace(PTRACE_POKETEXT, child, cur_rip, new_code) < 0)
        perror("ptrace POKETEXT");

    if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0)
        perror("ptrace single step");
    
    if(waitpid(child, &status, 0) < 0)
        perror("wait");

    if(ptrace(PTRACE_POKETEXT, child, cur_rip, orig_code) < 0)
        perror("ptrace POKETEXT");

    if((WIFEXITED(status))){
        fprintf(stdout, "** the target program terminated.\n");
        exit_sign = 1;
        return 0;
    }

    cur_rip = GetCurRip();

    /* Check if there is 0xcc */
    ull code = ptrace(PTRACE_PEEKTEXT, child, cur_rip, 0);
    // fprintf(stderr, "orig_code: %lx\n", orig_code);

    if((code & 0x00000000000000cc) != 0xcc)
        return 0;

    if(!cur_new_bp)
        fprintf(stdout, "** hit a breakpoint at 0x%llx.\n", cur_rip);
    
    return 1;
        
}

void Anchor(char* maps_path, char* executable){
    int fd, sz;
    char buf[BUF_SIZE], *s, *line, *saveptr;

    if((fd = open(maps_path, O_RDONLY)) < 0)
        perror("open child maps");
    
    if((sz = read(fd, buf, sizeof(buf)-1)) < 0)
        perror("read child maps");

    buf[sz] = 0;
    close(fd);


    /* Writable executable -> Stack -> Heap */
    s = strdup(buf);
    // fprintf(stderr, "%s\n", s);

    while((line = strtok_r(s, "\n\r", &saveptr)) != NULL) { 
        s = NULL;

		if(strstr(line, " rw") == NULL) 
            continue;

		if(strstr(line, executable) != NULL) {
			if(sscanf(line, "%llx-%llx ", &write_min, &write_max) != 2) 
                perror("sscanf");
		}else if(strstr(line, "stack") != NULL){
            if(sscanf(line, "%llx-%llx ", &stack_min, &stack_max) != 2) 
                perror("sscanf");
        }else if(strstr(line, "heap") != NULL){
            if(sscanf(line, "%llx-%llx ", &heap_min, &heap_max) != 2) 
                perror("sscanf");
        }

        if(write_min != 0 && write_max != 0 && stack_min != 0 && stack_max != 0 && heap_min != 0 && heap_max != 0) 
            break;
	}
    

    for(int idx = 0; write_min + idx * 8 < write_max; idx++){
        ull code = ptrace(PTRACE_PEEKTEXT, child, write_min+idx*8, 0);
        snapshot_buffer[idx] = code;
    }

    for(int idx = 0; stack_min + idx * 8 < stack_max; idx++){
        ull code = ptrace(PTRACE_PEEKTEXT, child, stack_min+idx*8, 0);
        stack_buffer[idx] = code;

        // if(code != 0)
        //     fprintf(stderr, "NOT ZERO!\n");
    }

    for(int idx = 0; heap_min + idx * 8 < heap_max; idx++){
        ull code = ptrace(PTRACE_PEEKTEXT, child, heap_min+idx*8, 0);
        heap_buffer[idx] = code;

        // if(code != 0)
        //     fprintf(stderr, "NOT ZERO!\n");
    }

    if(ptrace(PTRACE_GETREGS, child, 0, &snapshot_regs) < 0)
        perror("ptrace GETREGS");

    ull cur_rip = GetCurRip();

    ull start_code = ptrace(PTRACE_PEEKTEXT, child, cur_rip, 0);

    if(start_code - (start_code & 0xffffffffffffff00) == 0xcc)
        anchor_is_bp = 1;
    else anchor_is_bp = 0;

    fprintf(stdout, "** dropped an anchor\n");

}

void TimeTravel(){
    for(int idx = 0; write_min + idx * 8 < write_max; idx++){
        ull addr = write_min + idx * 8; 
        if(ptrace(PTRACE_POKETEXT, child, addr, snapshot_buffer[idx]) < 0)
            perror("ptrace POKETEXT");
    }

    for(int idx = 0; stack_min + idx * 8 < stack_max; idx++){
        ull addr = stack_min + idx * 8; 
        if(ptrace(PTRACE_POKETEXT, child, addr, stack_buffer[idx]) < 0)
            perror("ptrace POKETEXT");
    }

    for(int idx = 0; heap_min + idx * 8 < heap_max; idx++){
        ull addr = heap_min + idx * 8; 
        if(ptrace(PTRACE_POKETEXT, child, addr, heap_buffer[idx]) < 0)
            perror("ptrace POKETEXT");
    }

    if(ptrace(PTRACE_SETREGS, child, 0, &snapshot_regs) < 0)
        perror("ptrace SETREGS");

    

    fprintf(stdout, "** go back to the anchor point\n");
}