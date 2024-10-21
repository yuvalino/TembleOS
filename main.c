#include <unistd.h>
#include <stdio.h>
#include <tvm.h>
#include <setjmp.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/wait.h>
#include <signal.h>

void xxd(void *addr, int len)
{
    char *caddr = (char *) addr;
    int off = 0;
    while (off < len)
    {
        size_t start_off = off;

        char currptr[17];
        printf("%08x: ", off);

        memset(currptr, ' ', sizeof(currptr)-1); currptr[sizeof(currptr)-1] = 0;
        for (int i = 0; off < len, i < 8; off++, i++) {
            char a[3];
            snprintf(a, 3, "%02hhx", caddr[off]);
            memcpy(currptr + (2*(7-i)), a, 2);
        }
        printf("%s", currptr);

        printf(" ");

        memset(currptr, ' ', sizeof(currptr)-1);
        if (off < len) {
            for (int i = 0; off < len, i < 8; off++, i++) {
                char a[3];
                snprintf(a, 3, "%02hhx", caddr[off]);
                memcpy(currptr + (2*(7-i)), a, 2);
            }
        }
        printf("%s", currptr);

        printf("  ");

        for (; start_off < off; start_off++) {
            printf("%c", (isprint(caddr[start_off]))?caddr[start_off]:'.');
        }

        printf("\n");
    }
}

int mksh_main(int argc, char **argv);
int dropbear_main(int argc, char **argv);
int scp_main(int argc, char **argv);

// int main(int argc, char **argv)
// {
//     tvm_init();
//     printf("Hello, World!\n");
//     char *nargv[] = {
//         argv[0],
//         NULL
//     };
//     return mksh_main(sizeof(nargv)/sizeof(char *) - 1, nargv);
// }

int main(int argc, char **argv)
{
    tvm_init();
    tvm_register_program("/bin/sh", (main_func_t) mksh_main);
    tvm_register_program("/usr/bin/scp", (main_func_t) scp_main);
    printf("Hello, World!\n");
    char *nargv[] = {
        argv[0],
        //"-vvvvvv",
        "-F",
        "-E",
        NULL
    };
    return dropbear_main(sizeof(nargv)/sizeof(char *) - 1, nargv);
}