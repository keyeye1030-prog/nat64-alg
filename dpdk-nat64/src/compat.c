#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

#ifndef __NR_memfd_create
#define __NR_memfd_create 319
#endif

int memfd_create(const char *name, unsigned int flags) {
    return syscall(__NR_memfd_create, name, flags);
}

int fcntl64(int fd, int cmd, ...) {
    va_list ap;
    va_start(ap, cmd);
    void *arg = va_arg(ap, void *);
    va_end(ap);
    return fcntl(fd, cmd, arg);
}

int rte_cpu_is_supported(void) {
    return 1;
}

static uint64_t __rand_state = 0x853c49e6748fea9bULL;

void rte_srand(uint64_t seedval) {
    __rand_state = seedval ? seedval : 0x853c49e6748fea9bULL;
}

uint64_t rte_rand(void) {
    uint64_t z = (__rand_state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

uint64_t rte_rand_max(uint64_t max) {
    if (max == 0) return 0;
    return rte_rand() % max;
}

double rte_drand(void) {
    return (double)rte_rand() / (double)18446744073709551615ULL;
}

/* Force fmemopen to bind to GLIBC_2.2.5 */
__asm__(".symver glibc_fmemopen, fmemopen@GLIBC_2.2.5");
extern FILE *glibc_fmemopen(void *buf, size_t size, const char *mode);

FILE *fmemopen(void *buf, size_t size, const char *mode) {
    return glibc_fmemopen(buf, size, mode);
}
