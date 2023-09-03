#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
using namespace std;

void find(char *dir, char* magicnum){
    DIR *dp;
    struct dirent *dirp;
    if((dp = opendir(dir)) == NULL){
        //printf("cannot open /home\n");
    }
    while((dirp = readdir(dp))!= NULL){
        //printf("%s, %d\n", dirp->d_name, dirp->d_type);
        char *filename = dirp->d_name;
        char temp[128];
        strcpy(temp, dir);
        strcat(temp, "/");
        strcat(temp, filename);

        if(strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0){
           continue;
        }
        if(dirp->d_type == 4){
           //printf("A dir!\n");
           find(temp, magicnum);
           continue;
        }
        int fd;
        if((fd = open(temp, O_RDONLY)) < 0){
           //printf("not a file!\n");
           continue;
        }
        //printf("here!\n");
        char buffer[1024];
        if((read(fd, buffer, sizeof(buffer)))> 0){
            //printf("read something!\n");
            //printf("%s\n", buffer);
           if(strncmp(buffer, magicnum, strlen(magicnum)) == 0){
             //printf("read something!\n");
              printf("%s\n", temp);
           }
        }
    }
    closedir(dp);


}
int main(int argc, char *argv[]){
    DIR *dp;
    struct dirent *dirp;
    char* magicnum = argv[2];
    if((dp = opendir(argv[1])) == NULL){
        //printf("cannot open /home\n");
    }
    while((dirp = readdir(dp))!= NULL){
        //printf("%s, %d\n", dirp->d_name, dirp->d_type);
        char *filename = dirp->d_name;
        char temp[128];
        strcpy(temp, argv[1]);
        strcat(temp, "/");
        strcat(temp, filename);

        if(strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0){
           continue;
        }
        if(dirp->d_type == 4){
           //printf("A dir!\n");
           find(temp, magicnum);
           continue;
        }
        int fd;
        if((fd = open(temp, O_RDONLY)) < 0){
           //printf("not a file!\n");
           continue;
        }
        //printf("here!\n");
        char buffer[1024];
        if((read(fd, buffer, sizeof(buffer)))> 0){
            //printf("read something!\n");
            //printf("%s\n", buffer);
           if(strncmp(buffer, magicnum, strlen(magicnum)) == 0){
             //printf("read something!\n");
              printf("%s\n", temp);
           }
        }
    }
    closedir(dp);
    return 0;
}
