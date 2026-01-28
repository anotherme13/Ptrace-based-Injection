#define _GNU_SOURCE
#include <stdio.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/mman.h>
unsigned long long find_libc_base(pid_t pid)
{
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *fp = fopen(maps_path, "r");
    if (!fp)
    {
        perror("fopen /proc/self/maps");
        return 0;
    }

    unsigned long long libc_base = 0;
    char line[256], perms[5], pathname[256];

    while (fgets(line, sizeof(line), fp))
    {
        unsigned long start, end;
        sscanf(line, "%lx-%lx %s %*s %*s %*s %s", &start, &end, perms, pathname);
        if (strstr(pathname, "libc.so") && strchr(perms, 'x'))
        {
            libc_base = start;
            printf("libc base address: 0x%llx\n", libc_base);
            break;
        }
    }

    fclose(fp);
    return libc_base;
}

unsigned long long find_function_offset(const char *func_name)
{
    void *libc = dlopen("libc.so.6", RTLD_LAZY);
    if (!libc)
    {
        perror("dlopen libc");
        return 0;
    }

    
    unsigned long func_addr = (unsigned long)dlsym(libc, func_name);
    Dl_info info;
    dladdr((void *)func_addr, &info);
    unsigned long libc_base = (unsigned long)info.dli_fbase;

    dlclose(libc);
    return func_addr - libc_base;

}

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        puts("Usage: ./injector <pid> <path_to_shared_library>");
        return 1;
    }

    pid_t target = atoi(argv[1]);
    const char *lib_path = argv[2];
    size_t lib_len = strlen(lib_path) + 1;
    


    if (ptrace(PTRACE_ATTACH, target, NULL, NULL) == -1)
    {
        perror("ptrace attach");
        return 1;
    }

    int status;
    waitpid(target, &status, 0);
    printf("[+] attached to process %d\n", target);

    struct user_regs_struct regs, orig_regs;
    if (ptrace(PTRACE_GETREGS, target, NULL, &regs) == - 1)
    {
        perror("ptrace getregs");
        ptrace(PTRACE_DETACH, target, NULL, NULL);
        return 1;
    }

    memcpy(&orig_regs, &regs, sizeof(regs));
    printf("[*] Original RIP: 0x%llx\n", regs.rip);

    // find libc base address
    unsigned long long target_libc_base = find_libc_base(target);
    if (target_libc_base == 0)
    {
        ptrace(PTRACE_DETACH, target, NULL, NULL);
        perror("find libc base");
        return 1;
    }

    unsigned long long mmap_offset = find_function_offset("mmap");
    unsigned long long mmap_addr = target_libc_base + mmap_offset;
    printf("target mmap address: 0x%llx\n", mmap_addr);

    unsigned long long dlopen_offset = find_function_offset("dlopen");
    unsigned long long dlopen_addr = target_libc_base + dlopen_offset;
    printf("target dlopen address: 0x%llx\n", dlopen_addr);


    // Ok, finish finding addresses, now do the injection

    unsigned long orig_rsp = regs.rsp;
    printf("[*] Original RSP: 0x%lx\n", orig_rsp);
    unsigned long sentinel = 0xdeadbeefdeadbeef;
    
    regs.rsp -= 8;
    unsigned long return_addr = regs.rsp;
    
    if (ptrace(PTRACE_POKETEXT, target, return_addr, sentinel) == -1)
    {
        perror("ptrace poketext");
        ptrace(PTRACE_DETACH, target, NULL, NULL);
        return 1;
    }
    
    regs.rsp -= 8;
    return_addr = regs.rsp;
    if (ptrace(PTRACE_POKETEXT, target, return_addr, sentinel) == -1)
    {
        perror("ptrace poketext");
        ptrace(PTRACE_DETACH, target, NULL, NULL);
        return 1;
    }
    // ABI x86-64 needs alignment of stack to 16 bytes before a call, hence we need do it one more time!
    
    regs.rdi = 0;
    regs.rsi = 0x1000;
    regs.rdx = PROT_READ | PROT_WRITE;
    regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS;
    regs.r8 = -1;
    regs.r9 = 0;
    regs.rip = mmap_addr;

    if (ptrace(PTRACE_SETREGS, target, NULL, &regs) == -1)
    {
        perror("ptrace setregs");
        ptrace(PTRACE_DETACH, target, NULL, NULL);
        return 1;
    }

    if (ptrace(PTRACE_CONT, target, NULL, NULL) == -1)
    {
        perror("ptrace cont");
        ptrace(PTRACE_DETACH, target, NULL, NULL);
        return 1;
    }

    for (int i = 0; i < 10000; i++)
    {
        if (ptrace(PTRACE_SINGLESTEP, target, NULL, NULL) == -1)
        {
            perror("ptrace singlestep");
            ptrace(PTRACE_DETACH, target, NULL, NULL);
            return 1;
        }
        waitpid(target, &status, 0);

        if (ptrace(PTRACE_GETREGS, target, NULL, &regs) == -1)
        {
            perror("ptrace getregs");
            ptrace(PTRACE_DETACH, target, NULL, NULL);
            return 1;
        }

        if (regs.rip == return_addr)            break;

        if (WIFSIGNALED(status))
        {
            perror("target process crashed");
            ptrace(PTRACE_DETACH, target, NULL, NULL);
            return 1;   
        }

        if (WIFEXITED(status))
        {
            perror("target process exited");
            ptrace(PTRACE_DETACH, target, NULL, NULL);
            return 1;
        }
    }

    if (ptrace(PTRACE_GETREGS, target, NULL, &regs) == -1)
    {
        perror("ptrace getregs");
        ptrace(PTRACE_DETACH, target, NULL, NULL);
        return 1;
    }

    unsigned long long allocated_mem = regs.rax;

    printf("[+] allocated memory at: 0x%llx\n", allocated_mem);



}