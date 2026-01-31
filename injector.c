#define _GNU_SOURCE
#include <stdio.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
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
        if (strstr(pathname, "libc.so"))
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

int check_memory_writeable(pid_t pid, unsigned long long addr)
{
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *fp = fopen(maps_path, "r");
    if (!fp)
    {
        perror("fopen /proc/self/maps");
        return 0;
    }

    char line[256], perms[5];
    while (fgets(line, sizeof(line), fp))
    {
        unsigned long long start, end;
        if (sscanf(line,"%llx-%llx %s", &start, &end, perms) >= 3)
        {
            if (start <= addr && addr <= end)
            {
                printf("[*] Ok, found the segment for address)\n");
                fclose(fp);
                return (strchr(perms, 'w') != NULL);
            }
        }
    }
    printf("[-] Fail! Cannot find segment for address!\n");
    fclose(fp);
    return 0;
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


    printf("[*] Original RIP: 0x%llx\n", regs.rip);
 
   
    // ABI x86-64: RSP must be 16-byte aligned BEFORE call instruction
    regs.rsp = (regs.rsp - 128) & ~0xFULL; 
    

    // Save the return address (original RIP) BEFORE we change it
    unsigned long long return_addr = regs.rip;
    long orig_instruction = ptrace(PTRACE_PEEKTEXT, target, return_addr, NULL);
    long breakpoint_instruction = (orig_instruction & ~0xFF) | 0xCC;
    ptrace(PTRACE_POKETEXT, target, return_addr, breakpoint_instruction);
    

    // Push return address onto the stack 
    regs.rsp -= 8;  
    if (ptrace(PTRACE_POKETEXT, target, regs.rsp, return_addr) == -1) {
        perror("ptrace poketext (push return addr)");
        ptrace(PTRACE_DETACH, target, NULL, NULL);
        return 1;
    }

    // Set up mmap parameters in registers
    regs.rdi = 0;
    regs.rsi = 0x1000;
    regs.rdx = PROT_READ | PROT_WRITE;
    regs.rcx = MAP_PRIVATE | MAP_ANONYMOUS;
    regs.r8 = -1;
    regs.r9 = 0;
    regs.rip = mmap_addr;
    
    printf("[*] Set up registers for mmap call\n");
    if (ptrace(PTRACE_SETREGS, target, NULL, &regs) == -1)
    {
        perror("ptrace setregs");
        ptrace(PTRACE_DETACH, target, NULL, NULL);
        return 1;
    }

    int loop_count = 0;
    while (1)
    {
        ptrace(PTRACE_CONT, target, NULL, NULL);
        waitpid(target, &status, 0);
        ptrace(PTRACE_GETREGS, target, NULL, &regs);
       
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
        {
            printf("[*] hit my breakpoint after mmap\n");
            printf("[*] mmap returned: 0x%llx\n", regs.rax);
            break;
        }
    }

        
    // Restore the original instruction
    ptrace(PTRACE_POKETEXT, target, return_addr, orig_instruction);



    // NOW FOR DLOPEN CALL, I do the same steps again


    memcpy(&orig_regs, &regs, sizeof(regs));
    regs.rsp = (regs.rsp - 128) & ~0xFULL; 

    return_addr = regs.rip;
    orig_instruction = ptrace(PTRACE_PEEKTEXT, target, return_addr, NULL);
    breakpoint_instruction = (orig_instruction & ~0xFF) | 0xCC;
    ptrace(PTRACE_POKETEXT, target, return_addr, breakpoint_instruction);
    

    regs.rsp -= 8;  
    if (ptrace(PTRACE_POKETEXT, target, regs.rsp, return_addr) == -1) {
        perror("ptrace poketext (push return addr)");
        ptrace(PTRACE_DETACH, target, NULL, NULL);
        return 1;
    }

    // Save the mmap result (allocated memory address)
    unsigned long long mmap_mem = regs.rax;

    // Write library path to the mmap'd memory
    printf("[*] Writing library path to 0x%llx\n", mmap_mem);
    for (size_t i = 0; i < lib_len; i += sizeof(long))
    {
        long word = 0;
        size_t chunk = (lib_len - i < sizeof(long)) ? (lib_len - i) : sizeof(long);
        memcpy(&word, lib_path + i, chunk);
        
        if (ptrace(PTRACE_POKETEXT, target, mmap_mem + i, word) == -1)
        {
            perror("ptrace poketext (write lib path)");
            ptrace(PTRACE_DETACH, target, NULL, NULL);
            return 1;
        }
    }
    printf("[+] Wrote library path: %s\n", lib_path);


    regs.rdi = mmap_mem;    // pointer to library path string
    regs.rsi = RTLD_NOW;   
    regs.rip = dlopen_addr;
    
    printf("[*] Set up registers for dlopen call\n");
    if (ptrace(PTRACE_SETREGS, target, NULL, &regs) == -1)
    {
        perror("ptrace setregs");
        ptrace(PTRACE_DETACH, target, NULL, NULL);
        return 1;
    }

    // Wait for dlopen to complete
    while (1)
    {
        ptrace(PTRACE_CONT, target, NULL, NULL);
        waitpid(target, &status, 0);
        ptrace(PTRACE_GETREGS, target, NULL, &regs);
       
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
        {
            printf("[*] hit my breakpoint after dlopen\n");
            printf("[*] dlopen returned: 0x%llx\n", regs.rax);
            break;
        }
    }
        
    // Restore the original instruction
    ptrace(PTRACE_POKETEXT, target, return_addr, orig_instruction);

    // Restore original registers
    if (ptrace(PTRACE_SETREGS, target, NULL, &orig_regs) == -1)
    {
        perror("ptrace setregs restore");
    }
    
    // Detach from target
    ptrace(PTRACE_DETACH, target, NULL, NULL);
    printf("[+] Detached from process %d\n", target);
    printf("[+] Injection %s!\n", regs.rax ? "COMPLETE" : "FAILED");

    return regs.rax ? 0 : 1;
}