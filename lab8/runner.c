#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <sys/user.h>
#include <string.h>

int main(int argc, char* argv[]){
    pid_t child;
    struct user_regs_struct regs, tmp_regs, ret_regs;
    int bingo = -1;

    unsigned char code[11] = { 0 };
    memset(code, '0', sizeof(code)-1);

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
        int status;
        // printf("child pid: %d\n", child);
        // ptrace(PTRACE_ATTACH, child, 0, 0);

        if(waitpid(child, &status, 0) < 0)
            perror("wait");

        assert(WIFSTOPPED(status));
        if(ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL) < 0)
            perror("ptrace setopt");

        // printf("status: %d\n", status);
        if(ptrace(PTRACE_CONT, child, 0, 0) < 0)
            perror("ptrace cont");


        // setvbuf
        waitpid(child, &status, 0);
        assert(WIFSTOPPED(status));
        // printf("first break point\n");

        if(ptrace(PTRACE_CONT, child, 0, 0) < 0)
            perror("ptrace cont");
        
        // memset
        waitpid(child, &status, 0);
        assert(WIFSTOPPED(status));
        // printf("Second break point\n");

        long magic_pos; 

        if(ptrace(PTRACE_GETREGS, child, 0, &regs) == 0){
            magic_pos = regs.rax;
            // printf("magic position: 0x%lx\n", magic_pos);
        }

        int val[11] = {0};
        int num = 1;

        for(int i = 8; i >= 0; i--){
            val[i] = num;
            num *= 2;
        }

        int cnt = 0;

        while(bingo < 0 && cnt < 512){
            
            if(cnt > 0){
                if(ptrace(PTRACE_SETREGS, child, 0, &ret_regs) < 0){
                    perror("set reg");
                }
            }

            for(int i = 0; i <= 8; i++){
                if(cnt & val[i]){
                    code[i] = '1';
                }else{
                    code[i] = '0';
                }
            }

            unsigned long* lcode = (unsigned long*)code;

            long orig_code;
            orig_code = ptrace(PTRACE_PEEKTEXT, child, magic_pos+8, 0);

            if(ptrace(PTRACE_POKETEXT, child, magic_pos, *lcode) != 0)
                perror("ptrace poke text1");

            if(code[8] == '1'){
                if(ptrace(PTRACE_POKETEXT, child, magic_pos+8, (orig_code & 0xffffffffffffff00) | 0x31) != 0)
                    perror("ptrace poke text2");
            }else{
                if(ptrace(PTRACE_POKETEXT, child, magic_pos+8, (orig_code & 0xffffffffffffff00) | 0x30) != 0)
                    perror("ptrace poke text2");
            }
            

            if(ptrace(PTRACE_CONT, child, 0, 0) < 0)
                perror("ptrace cont");

            if(cnt == 0){
                // oracle connect
                waitpid(child, &status, 0);
                assert(WIFSTOPPED(status));
                // printf("Third break point\n");

                if(ptrace(PTRACE_GETREGS, child, 0, &ret_regs) < 0)
                    perror("ptrace get regs\n");
                

                if(ptrace(PTRACE_CONT, child, 0, 0) < 0)
                    perror("ptrace cont");
            }

            // oracle reset
            waitpid(child, &status, 0);
            assert(WIFSTOPPED(status));
            // printf("Fourth break point\n");

            if(ptrace(PTRACE_CONT, child, 0, 0) < 0)
                perror("ptrace cont");

            // evaluation 
            waitpid(child, &status, 0);
            assert(WIFSTOPPED(status));
            // printf("Fifth break point\n");

            if(ptrace(PTRACE_GETREGS, child, 0, &tmp_regs) == 0){
                bingo = tmp_regs.rax;
                // printf("bingo: %d\n", bingo);
            }

            cnt++;
        }
        
        if(ptrace(PTRACE_CONT, child, 0, 0) < 0)
            perror("ptrace cont");

        // done
        waitpid(child, &status, 0);
        assert(WIFSTOPPED(status));
        // printf("Sixth break point\n");

        if(ptrace(PTRACE_CONT, child, 0, 0) < 0)
            perror("ptrace cont");
        
        perror("done()");
    }
}