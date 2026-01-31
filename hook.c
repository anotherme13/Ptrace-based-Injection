#define _GNU_SOURCE
#include<stdio.h>
#include<dlfcn.h>

// Constructor - runs when library is loaded
__attribute__((constructor))
void on_load(void)
{
    printf("\n");
    printf("=============================================\n");
    printf(" Library successfully injected!\n");
    printf("=============================================\n");
    printf("\n");
}


void notifier(const char *filename, const char *mode)
{
    printf("SUCCESSFULLY HOOK A FUNCTION USING PTRACE!!!!!!!\n");
}
FILE *fopen(const char *filename, const char *mode)
{
    notifier(filename, mode);
    static FILE *(*real_fopen)(const char *, const char *) = NULL;
    if (!real_fopen) {
        real_fopen = dlsym(RTLD_NEXT, "fopen");
    }
    return real_fopen(filename, mode);
}