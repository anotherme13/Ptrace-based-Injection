#define _GNU_SOURCE
#include<stdio.h>
#include<dlfcn.h>

void notifier(const char *filename, const char *mode)
{
    printf("[HOOKED] fopen called: %s, %s\n", filename, mode);
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