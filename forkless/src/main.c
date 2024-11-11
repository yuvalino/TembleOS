#include <unistd.h>
#include <stdio.h>
#include <tvm.h>
#include <setjmp.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/wait.h>
#include <signal.h>

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