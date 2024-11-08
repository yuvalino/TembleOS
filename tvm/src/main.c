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
int _toybox_main(int argc, char **argv);
void toybox_iter_toy_names(void (*fn)(const char *, void *), void * arg);

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

static void add_toy(const char *toy_name, void *arg)
{
    char pathname[4096] = {0};
    snprintf(pathname, sizeof(pathname), "/usr/bin/%s", toy_name);
    tvm_register_program(pathname, (main_func_t) _toybox_main);
}

int main(int argc, char **argv)
{
    tvm_init();
    tvm_register_program("/bin/sh", (main_func_t) mksh_main);
    tvm_register_program("/usr/bin/scp", (main_func_t) scp_main);
    tvm_register_program("/usr/bin/toybox", (main_func_t) _toybox_main);
    toybox_iter_toy_names(add_toy, NULL);

    char *addr_port = (char *)"2222";
    if (argc >= 2)
        addr_port = argv[1];
    
    char *nargv[] = {
        argv[0],
        //"-vvvvvv",
        "-F",
        "-E",
        "-p",
        addr_port,
        NULL
    };
    return dropbear_main(sizeof(nargv)/sizeof(char *) - 1, nargv);
}