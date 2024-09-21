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

#  define PTR_MANGLE(var)	asm ("xor %%fs:%c2, %0\n"		      \
				     "rol $2*" LP_SIZE "+1, %0"		      \
				     : "=r" (var)			      \
				     : "0" (var),			      \
				       "i" (offsetof (tcbhead_t,	      \
						      pointer_guard)))
#define PTR_DEMANGLE(var)	asm ("ror $2*8+1, %0\n"	      \
				     "xor %%fs:0x30, %0"			      \
				     : "=r" (var) \
				     : "r" (var))

int main()
{
    tvm_init();
    
    pid_t p = forkless();
    if (p == 0)
    {
        sleep(5);
    }

    if (0 != kill(p, SIGFPE)) {
        perror("kill");
        return 1;
    }

    int status = 0;
    if (p != waitpid(-1, &status, 0)) {
        perror("waitpid");
        return 1;
    }

    if (!WIFSIGNALED(status)) {
        printf("not signaled\n");
        return 1;
    }
    if (WTERMSIG(status) != SIGFPE) {
        printf("not termsig=%d\n", WTERMSIG(status));
        return 1;
    }

    printf("done\n");
    return 0;
}

int main_forkwait()
{
    tvm_init();
    
    pid_t p1 = forkless();
    if (p1 == 0)
    {
        sleep(1);
        printf("p1\n");
        exit(69);
    }

    pid_t p2 = forkless();
    if (p2 == 0)
    {
        printf("p2\n");
        exit(68);
    }

    int status = 0;
    if (p2 != waitpid(-1, &status, 0)) {
        perror("waitpid");
        return 1;
    }

    printf("parent\n");

    if (!WIFEXITED(status)) {
        printf("not exited\n");
        return 1;
    }
    if (WEXITSTATUS(status) != 68) {
        printf("not exitstatus=%d\n", WEXITSTATUS(status));
        return 1;
    }

    if (p1 != waitpid(p1, NULL, 0)) {
        perror("waitpid2");
        return 1;
    }

    printf("done\n");
    return 0;
}

int mksh_main(int argc, char **argv);
int dropbear_main(int argc, char **argv);

int main2(int argc, char **argv)
{
    tvm_init();
    printf("Hello, World!\n");
    char *nargv[] = {
        argv[0],
        "-F",
        "-E",
        NULL
    };
    return dropbear_main(sizeof(nargv)/sizeof(char *) - 1, nargv);
}