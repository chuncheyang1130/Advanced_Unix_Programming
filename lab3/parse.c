#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>


int main(){

    int fd = open("store.txt", O_RDWR);

    char line[100];
    size_t sz = 0;

    while((sz = read(fd, line, 22)) > 0){
        //printf("str is %s", line);
        char* tok;
        printf("{\"");
        
        tok = strtok(line, " ");
        printf("%s", tok);
        printf("\", \"");

        tok = strtok(NULL, " ");
        printf("%s", tok);
        printf("\"},\n");
    }

}