#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define BUFSIZE 1024

int get_info(char* path, char* magic){

    char buf[BUFSIZE], full_path[BUFSIZE];
    int fd, close_ok;
    ssize_t size;

    DIR* dir = opendir(path);
    struct dirent* dir_ptr = readdir(dir);

    while(dir_ptr != NULL){

        memset(buf, 0, BUFSIZE);

        memset(full_path, 0, BUFSIZE);
        strcpy(full_path, path);
        strcat(full_path, "/");
        strcat(full_path, dir_ptr->d_name);

    
        if(strcmp(dir_ptr->d_name, ".") == 0 || strcmp(dir_ptr->d_name, "..") == 0){
            dir_ptr = readdir(dir);
            continue;
        }

        fprintf(stderr, "Current position is %s\n", full_path);

        if(dir_ptr->d_type == DT_DIR){
            fprintf(stderr, "Current d type is directory\n");
            fprintf(stderr, "Going into dir %s\n", full_path);

            int finish = get_info(full_path, magic);
            if(finish){
                return 1;
            }else{
                dir_ptr = readdir(dir);
                continue;
            }
        }

        if((fd = open(full_path, O_RDONLY)) < 0)
            fprintf(stderr, "File open error\n");
        
        if((size = read(fd, buf, BUFSIZE)) < 0)
            fprintf(stderr, "Reading error\n");
        else 
            fprintf(stderr, "Buffer Content in %s is %s\n", full_path, buf);
        
        close(fd);

        if(strncmp(buf, magic, strlen(magic)) == 0){
            printf("%s\n", full_path);

            if((close_ok = closedir(dir)) < 0)
                fprintf(stderr, "Something Wrong while closing dir");
                
            return 1;
        }

        dir_ptr = readdir(dir);
    }

    if((close_ok = closedir(dir)) < 0)
        fprintf(stderr, "Something Wrong while closing dir");

    return 0;
}

int main(int argc, char* argv[]){
    char path[BUFSIZE], magic[BUFSIZE];

    memset(path, 0, BUFSIZE);
    memset(magic, 0, BUFSIZE);

    strcpy(path, argv[1]);
    strcpy(magic, argv[2]);
    
    int finish = get_info(path, magic);

}