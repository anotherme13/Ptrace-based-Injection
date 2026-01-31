
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>

int main()
{
    void *libc = dlopen("libc.so.6", RTLD_LAZY);
    if (!libc)
    {
        perror("dlopen libc");
        return 1;
    }
    
    // Get mmap address
    void *mmap_ptr = dlsym(libc, "mmap");
    printf("mmap address from dlsym: %p\n", mmap_ptr);
    
    // Get info about where it actually points
    Dl_info info;
    if (dladdr(mmap_ptr, &info))
    {
        printf("Symbol name: %s\n", info.dli_sname);
        printf("Library base: %p\n", info.dli_fbase);
        printf("Symbol address: %p\n", info.dli_saddr);
        printf("Offset from base: 0x%lx\n", 
               (unsigned long)mmap_ptr - (unsigned long)info.dli_fbase);
    }

    dlclose(libc);

    while(1)
    {
        sleep(1);
    }
    return 0;
}