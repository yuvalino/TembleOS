#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <getopt.h>
#include <sys/select.h>
#include <poll.h>
#include <pty.h>

#include "tvm.h"

//////////
//// API
//////////

#define __S(X) #X
#define _S(X) __S(X)

void _add_test(const char *n, void (*f)());
#define TEST(Name) void _test_ ## Name (); __attribute__((constructor)) void _c_ ## Name () { _add_test(#Name , _test_ ## Name); } void _test_ ## Name ()

#define FAIL(Msg, ...) do { fprintf(stderr, "FAIL (errno %d):\n  File \"" __FILE__ "\", line " _S(__LINE__) ", in ", errno); (strncmp("_test_", __FUNCTION__, 6)?fputs(__FUNCTION__, stderr):fprintf(stderr, "TEST(%s)", __FUNCTION__+6)); fprintf(stderr, "\n" Msg "\n", ##__VA_ARGS__); fflush(stderr); exit(1); } while (0)
#define ASSERT_EQ(X, Y) do { __auto_type __X = (X); __auto_type __Y = (Y); if (__X != __Y) FAIL("    ASSERT_EQ(" #X ", " #Y ");\n    ----\n    %lld != %lld", (long long) __X, (long long)__Y); } while (0)
#define ASSERT_NEQ(X, Y) do { __auto_type __X = (X); __auto_type __Y = (Y); if (__X == __Y) FAIL("    ASSERT_NEQ(" #X ", " #Y ");\n    ----\n    %lld == %lld", (long long) __X, (long long)__Y); } while (0)

//////////
//// Tests
//////////

TEST(ProcWait) {
    ASSERT_EQ(-1, wait(NULL));
    ASSERT_EQ(errno, ECHILD);
}

TEST(ProcExit) {
    printf("begin\n");

    pid_t p = fork();
    ASSERT_NEQ(p, -1);
    if (!p) {
        printf("p 1\n");
        exit(25);
    }
        
    int s;
    ASSERT_EQ(p, wait(&s));
    ASSERT_EQ(WIFEXITED(s), 1);
    ASSERT_EQ(WIFSIGNALED(s), 0);
    ASSERT_EQ(WEXITSTATUS(s), 25);

    printf("again\n");

    p = fork();
    ASSERT_NEQ(p, -1);
    if (!p) {
        printf("p 2");
        exit(26);
    }
    ASSERT_EQ(p, wait(&s));
    ASSERT_EQ(WIFEXITED(s), 1);
    ASSERT_EQ(WIFSIGNALED(s), 0);
    ASSERT_EQ(WEXITSTATUS(s), 26);

    printf("done\n");
}

TEST(ProcWNOHANG) {
    pid_t p = fork();
    ASSERT_NEQ(p, -1);

    if (!p) {
        usleep(100000);
        _exit(0);
    }
    
    ASSERT_EQ(0, waitpid(-1, NULL, WNOHANG));

    usleep(200000);
    
    int s;
    ASSERT_EQ(p, waitpid(-1, &s, WNOHANG));
    ASSERT_EQ(WIFEXITED(s), 1);
    ASSERT_EQ(WEXITSTATUS(s), 0);
}

TEST(ProcWaitPgrp) {
    pid_t p = fork();
    ASSERT_NEQ(p, -1);

    if (!p) {
        if (0 != setpgid(0, 0))
            _exit(1);
        _exit(0);
    }
    
    usleep(100000);

    ASSERT_EQ(-1, waitpid(0, NULL, WNOHANG));
    ASSERT_EQ(errno, ECHILD);

    int s;
    ASSERT_EQ(p, waitpid(-p, &s, WNOHANG));
    ASSERT_EQ(WIFEXITED(s), 1);
    ASSERT_EQ(WEXITSTATUS(s), 0);
}

TEST(ProcRaise) {
    pid_t p = fork();
    ASSERT_NEQ(p, -1);

    if (!p)
        raise(15);
    
    int s;
    ASSERT_EQ(p, wait(&s));
    ASSERT_EQ(WIFEXITED(s), 0);
    ASSERT_EQ(WIFSIGNALED(s), 1);
    ASSERT_EQ(WTERMSIG(s), 15);
}

TEST(ProcKill) {
    pid_t p = fork();
    ASSERT_NEQ(p, -1);

    if (!p)
        pause();
    
    usleep(200000);
    ASSERT_EQ(kill(p, 11), 0);

    int s;
    ASSERT_EQ(p, wait(&s));
    ASSERT_EQ(WIFEXITED(s), 0);
    ASSERT_EQ(WIFSIGNALED(s), 1);
    ASSERT_EQ(WTERMSIG(s), 11);
}

TEST(ProcParent) {
    int pip[2];
    ASSERT_EQ(pipe(pip), 0);
    printf("[%d] start\n", getpid());
    pid_t p2;
    pid_t p1 = fork();
    ASSERT_NEQ(p1, -1);

    if (!p1) {
        printf("[%d] p1 start\n", getpid());
        if (0 != close(pip[0]))
            exit(1);

        pid_t p_2 = fork();
        if (p_2 == -1)
            exit(2);

        if (!p_2) {
            printf("[%d] p2 start\n", getpid());
            pid_t pz_1 = getppid();
            usleep(200000); // wait for p1 to die
            pid_t pz_2 = getppid();

            if (sizeof(pz_1) != write(pip[1], &pz_1, sizeof(pz_1)))
                exit(3);
            
            if (sizeof(pz_2) != write(pip[1], &pz_2, sizeof(pz_2)))
                exit(4);
            
            printf("[%d] p2 end\n", getpid());
            exit(0);
        }
        
        printf("[%d] forked %d\n", getpid(), p_2);

        usleep(100000); // let p2 do pz_1 = getppid() and get p1
                        // also let parent do kill(p1, 0)

        if (sizeof(p_2) != write(pip[1], &p_2, sizeof(p_2)))
            exit(5);
        
        exit(0);
    }

    printf("[%d] forked %d\n", getpid(), p1);

    ASSERT_EQ(0, close(pip[1]));

    ASSERT_EQ(0, kill(p1, 0));
    ASSERT_EQ(sizeof(p2), read(pip[0], &p2, sizeof(p2)));

    ASSERT_EQ(0, kill(p2, 0));

    usleep(200000); // wait for p1 to die completely

    ASSERT_EQ(-1, kill(p1, 0));
    ASSERT_EQ(ESRCH, errno);

    ASSERT_EQ(p1, waitpid(p1, NULL, 0));

    ASSERT_EQ(-1, kill(p1, 0));
    ASSERT_EQ(ESRCH, errno);

    pid_t pzz_1, pzz_2;
    ASSERT_EQ(sizeof(pzz_1), read(pip[0], &pzz_1, sizeof(pzz_1)));
    ASSERT_EQ(pzz_1, p1);
    ASSERT_EQ(sizeof(pzz_2), read(pip[0], &pzz_2, sizeof(pzz_2)));
    ASSERT_EQ(pzz_2, 1);
}

TEST(ProcSid) {
    ASSERT_EQ(getpid(), getsid(0));
    ASSERT_EQ(-1, setsid());
    ASSERT_EQ(EPERM, errno);

    pid_t p = fork();
    ASSERT_NEQ(p, -1);

    if (!p) {
        if (getppid() != getsid(0)) {
            fprintf(stderr, "bad sid\n");
            exit(1);
        }
        usleep(100000);
        if (getpid() != setsid() || getpid() != getsid(0)) {
            perror("child: setsid");
            exit(2);
        }

        exit(0);
    }

    ASSERT_EQ(getpid(), getsid(p));

    usleep(200000);
    ASSERT_EQ(p, getsid(p));

    int s;
    ASSERT_EQ(p, wait(&s));
    ASSERT_EQ(WIFEXITED(s), 1);
    ASSERT_EQ(WEXITSTATUS(s), 0);
}

TEST(ProcPgid) {
    ASSERT_EQ(getpid(), getpgrp());
    ASSERT_EQ(-1, setpgrp());
    ASSERT_EQ(EPERM, errno);

    pid_t p = fork();
    ASSERT_NEQ(p, -1);

    if (!p) {
        if (getppid() != getpgrp()) {
            fprintf(stderr, "bad pgid\n");
            exit(1);
        }

        usleep(100000);

        if (0 != setpgrp() || getpid() != getpgrp()) {
            perror("child: setpgid");
            exit(2);
        }

        exit(0);
    }

    ASSERT_EQ(getpid(), getpgid(p));

    usleep(200000);

    ASSERT_EQ(getpid(), getsid(p));
    ASSERT_EQ(p, getpgid(p));

    int s;
    ASSERT_EQ(p, wait(&s));
    ASSERT_EQ(WIFEXITED(s), 1);
    ASSERT_EQ(WEXITSTATUS(s), 0);
}

TEST(ProcPgidSet) {
    pid_t p1 = fork();
    ASSERT_NEQ(p1, -1);
    if (!p1) {
        usleep(100000);
        
        if (getpid() != getpgrp()) {
            fprintf(stderr, "p1 pgrp\n");
            exit(1);
        }
        
        exit(0);
    }

    pid_t p2 = fork();
    ASSERT_NEQ(p2, -1);
    if (!p2) {
        usleep(100000);
        
        if (p1 != getpgrp()) {
            fprintf(stderr, "p2 pgrp\n");
            exit(1);
        }

        exit(0);
    }

    ASSERT_EQ(0, setpgid(p1, 0));
    ASSERT_EQ(p1, getpgid(p1));
    ASSERT_EQ(0, setpgid(p2, p1));
    ASSERT_EQ(p1, getpgid(p2));

    int s;
    ASSERT_EQ(p1, waitpid(p1, &s, 0));
    ASSERT_EQ(WIFEXITED(s), 1);
    ASSERT_EQ(WEXITSTATUS(s), 0);

    ASSERT_EQ(p2, wait(&s));
    ASSERT_EQ(WIFEXITED(s), 1);
    ASSERT_EQ(WEXITSTATUS(s), 0);
}

static __thread int sigged = 0;
void my_handler(int signo, siginfo_t *si, void * ctx) {
    sigged = 1;
}

TEST(SignalsHandler) {

    struct sigaction old_act, act = {
        .sa_sigaction = my_handler,
        .sa_flags = SA_SIGINFO,
    };
    ASSERT_EQ(0, sigaction(SIGFPE, &act, &old_act));

    pid_t p = fork();
    ASSERT_NEQ(p, -1);

    if (!p) {
        if (0 != sigaction(SIGFPE, &old_act, NULL))
            exit(1);
        raise(SIGFPE);
    }

    int s;
    ASSERT_EQ(p, wait(&s));
    ASSERT_EQ(WIFSIGNALED(s), 1);
    ASSERT_EQ(WTERMSIG(s), SIGFPE);
    // child died , but parent will live!
    ASSERT_EQ(0, raise(SIGFPE));
    ASSERT_EQ(1, sigged);
}

static int testhandlersig = 0;
static void testhandler(int) {
    testhandlersig++;
}

TEST(SignalsSIGCHLD) {

    struct sigaction act = {
        .sa_handler = SIG_IGN,
        .sa_flags = 0,
    };
    ASSERT_EQ(0, sigaction(SIGCHLD, &act, NULL));

    pid_t p = fork();
    ASSERT_NEQ(p, -1);
    if (!p) {
        usleep(100000);
        exit(0);
    }
    ASSERT_EQ(-1, wait(NULL));
    ASSERT_EQ(errno, ECHILD);

    p = fork();
    ASSERT_NEQ(p, -1);
    if (!p) {
        exit(0);
    }
    usleep(100000);
    ASSERT_EQ(-1, wait(NULL));
    ASSERT_EQ(errno, ECHILD);

    act.sa_handler = testhandler;
    ASSERT_EQ(0, sigaction(SIGCHLD, &act, NULL));

    p = fork();
    ASSERT_NEQ(p, -1);
    if (!p) {
        exit(0);
    }
    ASSERT_EQ(p, wait(NULL));
    ASSERT_EQ(testhandlersig, 1);

    act.sa_flags = SA_NOCLDWAIT;
    ASSERT_EQ(0, sigaction(SIGCHLD, &act, NULL));

    p = fork();
    ASSERT_NEQ(p, -1);
    if (!p) {
        exit(0);
    }
    ASSERT_EQ(-1, wait(NULL));
    ASSERT_EQ(errno, ECHILD);
    ASSERT_EQ(testhandlersig, 2);
}

TEST(SignalsPgrp) {
    pid_t p1 = fork();
    ASSERT_NEQ(p1, -1);
    if (!p1) {
        if (0 != setpgid(0, 0))
            _exit(1);
        pause();
        _exit(0);
    }

    usleep(100000);
    
    ASSERT_EQ(0, kill(-p1, SIGTERM));

    int s;
    ASSERT_EQ(p1, wait(&s));
    ASSERT_EQ(WIFSIGNALED(s), 1);
    ASSERT_EQ(WTERMSIG(s), SIGTERM);
}

TEST(FDsInit) {
    ASSERT_EQ(-1, close(3));
    ASSERT_EQ(3, open("/dev/random", O_RDONLY));
    ASSERT_EQ(-1, close(4));
    
    pid_t p = fork();
    ASSERT_NEQ(p, -1);

    if (!p) {
        if (close(3) != 0)
            exit(255);
        exit(open("/dev/random", O_RDONLY));
    }
    
    usleep(200000); // 200ms is more than enough
    ASSERT_EQ(4, open("/dev/random", O_RDONLY)); // child had exited, so its FDs were cleared
    ASSERT_EQ(0, close(3)); // child fd table and parent are different, so can close 3 if child closed 3
    ASSERT_EQ(-1, close(3));

    int s;
    ASSERT_EQ(p, wait(&s));
    ASSERT_EQ(WIFEXITED(s), 1);
    ASSERT_EQ(WEXITSTATUS(s), 3);  // parent has 0-3, child closed 3 and opened, so its 3
}

TEST(FDsPoll) {
    pid_t p = fork();
    ASSERT_NEQ(p, -1);

    if (!p) {
        int pp[2];
        if (0 != pipe(pp))
            _exit(1);

        usleep(200000);
        _exit(0);
    }

    usleep(100000);

    int pp[2];
    ASSERT_EQ(0, pipe(pp));

    // the point of the fork is to make sure our pipes are bigger than other FDs

    int s;
    ASSERT_EQ(p, wait(&s));
    ASSERT_EQ(WIFEXITED(s), 1);
    ASSERT_EQ(WEXITSTATUS(s), 0);
    
    fd_set rfds;
    fd_set wfds;
    int nfds = ((pp[0]<pp[1])?pp[1]:pp[0]) + 1;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    struct pollfd fd[2] = {{.fd = pp[0], POLLIN, 0}, {.fd = pp[1], POLLOUT, 0}};
    struct timeval t = {0, 0};

    ASSERT_EQ(poll(fd, 2, 0), 1);
    ASSERT_NEQ(fd[1].revents & POLLOUT, 0);
    fd[1].revents = 0;
    FD_SET(pp[0], &rfds);
    FD_SET(pp[1], &wfds);
    ASSERT_EQ(select(nfds, &rfds, &wfds, NULL, &t), 1);
    ASSERT_EQ(FD_ISSET(pp[1], &wfds), 1);
    ASSERT_EQ(FD_ISSET(pp[0], &rfds), 0);
    
    ASSERT_EQ(1, write(pp[1], (void *)&rfds, 1));
    ASSERT_EQ(poll(fd, 2, 0), 2);
    ASSERT_EQ(fd[0].revents & POLLIN, POLLIN);
    ASSERT_EQ(fd[1].revents & POLLOUT, POLLOUT);
    FD_SET(pp[0], &rfds);
    FD_SET(pp[1], &wfds);
    ASSERT_EQ(select(nfds, &rfds, &wfds, NULL, &t), 2);
    ASSERT_EQ(FD_ISSET(pp[1], &wfds), 1);
    ASSERT_EQ(FD_ISSET(pp[0], &rfds), 1);
}

TEST(FDsFcntl) {
    pid_t p = fork();
    ASSERT_NEQ(p, -1);

    if (!p) {
        int pp[2];
        if (0 != pipe(pp))
            _exit(1);

        usleep(200000);
        _exit(0);
    }

    usleep(100000);

    int pp[2];
    ASSERT_EQ(0, pipe(pp));

    // the point of the fork is to make sure our pipes are bigger than other FDs

    int s;
    ASSERT_EQ(p, wait(&s));
    ASSERT_EQ(WIFEXITED(s), 1);
    ASSERT_EQ(WEXITSTATUS(s), 0);
    
    int nf = fcntl(pp[0], F_DUPFD, 10);
    ASSERT_EQ(nf, 10);
    int nf2 = fcntl(pp[0], F_DUPFD, 10);
    ASSERT_EQ(nf2, 11);
}

static COW_IMPL(int, cow_int);

TEST(COWSingleThreaded) {
    cow_int = 69;

    pid_t p = fork();
    ASSERT_NEQ(p, -1);

    if (!p) {
        if (cow_int != 69)
            _exit(1);
        cow_int = 5;
        usleep(200000);
        if (cow_int != 5)
            _exit(2);
        _exit(0);
    }

    usleep(100000);

    ASSERT_EQ(cow_int, 69);
    cow_int = 420;

    usleep(200000);

    ASSERT_EQ(cow_int, 420);

    int s;
    ASSERT_EQ(p, wait(&s));
    ASSERT_EQ(WIFEXITED(s), 1);
    ASSERT_EQ(WEXITSTATUS(s), 0);
}

static COW_IMPL(struct {
    int val;
    char *ptr;  
}, cow_deep);

TEST(COWDeepCopy) {
    cow_deep.val = 69;
    cow_deep.ptr = malloc(0x69);
    ASSERT_NEQ(NULL, cow_deep.ptr);
    memset(cow_deep.ptr, 'A', 0x69);

    pid_t p = fork();
    ASSERT_NEQ(p, -1);

    if (!p) {
        if (cow_deep.ptr == NULL)
            _exit(1);
        for (int i = 0; i < 0x69; i++) {
            if (cow_deep.ptr[i] != 'A')
                _exit(2);
        }
        
        usleep(200000);

        for (int i = 0; i < 0x69; i++) {
            if (cow_deep.ptr[i] != 'A')
                _exit(3);
        }

        _exit(0);
    }

    usleep(100000);

    for (int i = 0; i < 0x69; i++) {
        if (cow_deep.ptr[i] != 'A')
            _exit(4);
    }
    memset(cow_deep.ptr, 'B', 0x69);

    usleep(200000);

    int s;
    ASSERT_EQ(p, wait(&s));
    ASSERT_EQ(WIFEXITED(s), 1);
    ASSERT_EQ(WEXITSTATUS(s), 0);
}

TEST(COWDeepCopyMidBufferUnaligned)
{
    char *ptr = malloc(0x69);
    ASSERT_NEQ(NULL, ptr);

    cow_deep.val = 69;
    cow_deep.ptr = ptr + 5;
    int i;
    for (i = 0; i < 10; i++)
        ptr[i] = 'A'+i;
    ptr[i] = 0;
    ASSERT_EQ(0, strcmp(cow_deep.ptr, "FGHIJ"));

    pid_t p = fork();
    ASSERT_NEQ(p, -1);

    if (!p) {
        if (cow_deep.ptr == NULL)
            _exit(1);
        
        usleep(100000);
        
        if (0 != strcmp(cow_deep.ptr, "FGHIJ"))
            _exit(2);
        
        _exit(0);
    }

    for (i = 0; i < 10; i++)
        ptr[i] = '0' + i;

    int s;
    ASSERT_EQ(p, wait(&s));
    ASSERT_EQ(WIFEXITED(s), 1);
    ASSERT_EQ(WEXITSTATUS(s), 0);
}

TEST(COWDeepCopyInStack)
{
    char *ptr = malloc(0x69);
    int i;
    for (i = 0; i < 10; i++)
        ptr[i] = 'A'+i;
    ptr[i] = 0;

    ptr += 5;
    ASSERT_EQ(0, strcmp(ptr, "FGHIJ"));

    pid_t p = fork();
    ASSERT_NEQ(p, -1);

    if (!p) {
        if (ptr == NULL)
            _exit(1);
        
        usleep(100000);
        
        if (0 != strcmp(ptr, "FGHIJ"))
            _exit(2);
        
        _exit(0);
    }

    for (i = 5; i < 10; i++)
        ptr[i] = '0' + i;

    int s;
    ASSERT_EQ(p, wait(&s));
    ASSERT_EQ(WIFEXITED(s), 1);
    ASSERT_EQ(WEXITSTATUS(s), 0);
}


extern char **environ;

TEST(EnvBasic) {
    for (char **e = environ, **te = tvm_environ; *e != NULL; e++, te++) {
        ASSERT_NEQ(NULL, *te);
        ASSERT_EQ(0, strcmp(*e, *te));
    }

    ASSERT_EQ(NULL, getenv("kd85n2lk2"));
    ASSERT_EQ(0, putenv("kd85n2lk2=1"));
    ASSERT_NEQ(NULL, getenv("kd85n2lk2"));
    ASSERT_EQ(0, strcmp("1", getenv("kd85n2lk2")));
    
    char **e;
    for (e = tvm_environ; *(e+1) != NULL; e++) { }
    ASSERT_EQ(0, strcmp(*e, "kd85n2lk2=1"));

    ASSERT_EQ(0, unsetenv("kd85n2lk2"));
    ASSERT_EQ(NULL, getenv("kd85n2lk2"));

    ASSERT_EQ(0, putenv("kd85n2lk2=2"));
    ASSERT_NEQ(NULL, getenv("kd85n2lk2"));
    ASSERT_EQ(0, strcmp("2", getenv("kd85n2lk2")));
    ASSERT_EQ(0, unsetenv("kd85n2lk2"));

    ASSERT_EQ(0, setenv("kd85n2lk2", "3", 0));
    ASSERT_NEQ(NULL, getenv("kd85n2lk2"));
    ASSERT_EQ(0, strcmp("3", getenv("kd85n2lk2")));

    ASSERT_EQ(0, setenv("kd85n2lk2", "4", 0));
    ASSERT_NEQ(NULL, getenv("kd85n2lk2"));
    ASSERT_EQ(0, strcmp("3", getenv("kd85n2lk2")));

    ASSERT_NEQ(NULL, tvm_environ[0]);
}

TEST(EnvFork) {
    ASSERT_EQ(NULL, getenv("kd85n2lk2"));
    ASSERT_EQ(0, putenv("kd85n2lk2=1"));
    ASSERT_EQ(0, strcmp(getenv("kd85n2lk2"), "1"));

    pid_t p = fork();
    ASSERT_NEQ(p, -1);

    if (!p) {
        tvm_environ[0] = "lol";
        if (!getenv("kd85n2lk2"))
            _exit(1);
        if (0 != strcmp(getenv("kd85n2lk2"), "1"))
            _exit(2);
        if (0 != setenv("kd85n2lk2", "2", 1))
            _exit(3);
        if (0 != strcmp(getenv("kd85n2lk2"), "2"))
            _exit(4);
        
        usleep(200000);
        
        if (0 != strcmp(getenv("kd85n2lk2"), "2"))
            _exit(5);
        _exit(0);
    }

    usleep(100000);

    ASSERT_EQ(0, strcmp(getenv("kd85n2lk2"), "1"));
    ASSERT_EQ(0, setenv("kd85n2lk2", "3", 1));
    ASSERT_NEQ(0, strcmp(tvm_environ[0], "lol"));

    int s;
    ASSERT_EQ(p, wait(&s));
    ASSERT_EQ(WIFEXITED(s), 1);
    ASSERT_EQ(WEXITSTATUS(s), 0);
}

TEST(EnvNULL) {
    ASSERT_NEQ(NULL, getenv("PATH"));
    ASSERT_EQ(0, clearenv());
    ASSERT_EQ(tvm_environ, NULL);
    ASSERT_EQ(NULL, getenv("PATH"));
    ASSERT_EQ(0, unsetenv("PATH"));
    ASSERT_EQ(tvm_environ, NULL);

    ASSERT_EQ(0, putenv("hello=world"));
    ASSERT_NEQ(NULL, getenv("hello"));
    ASSERT_EQ(0, strcmp(getenv("hello"), "world"));
    ASSERT_NEQ(tvm_environ, NULL);
}

static int my_basic_prog()
{
    return 69;
}

TEST(ExecBasic) {
    ASSERT_EQ(-1, execl("/aaa", "/aaa", NULL));
    ASSERT_EQ(ENOENT, errno);

    tvm_register_program("/basic_prog", (main_func_t)my_basic_prog);
    pid_t p = fork();
    ASSERT_NEQ(p, -1);

    if (!p) {
        execl("/basic_prog", "/basic_prog", NULL);
        _exit(1);
    }

    int s;
    ASSERT_EQ(p, wait(&s));
    ASSERT_EQ(WIFEXITED(s), 1);
    ASSERT_EQ(WEXITSTATUS(s), 69);
}

static int my_args_prog(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    
    if (0 != strcmp(argv[0], "arg0"))
        return 3;

    if (0 != strcmp(argv[1], "arg1"))
        return 4;
    
    if (NULL != argv[2])
        return 5;
    
    return 0;
}

TEST(ExecArgs) {
    tvm_register_program("/args_prog", (main_func_t)my_args_prog);
    pid_t p = fork();
    ASSERT_NEQ(p, -1);

    if (!p) {
        execl("/args_prog", "arg0", "arg1", NULL);
        _exit(1);
    }

    int s;
    ASSERT_EQ(p, wait(&s));
    ASSERT_EQ(WIFEXITED(s), 1);
    ASSERT_EQ(WEXITSTATUS(s), 0);
}

char *ptsname(int fd);

TEST(TTYBasic) {
    int master, slave;
	ASSERT_EQ(0, openpty(&master, &slave, NULL, NULL, NULL));
    ASSERT_EQ(1, isatty(master));
    ASSERT_EQ(1, isatty(slave));

    ASSERT_NEQ(NULL, ttyname(master));
    ASSERT_EQ(0, strcmp(ttyname(master), "/dev/ptmx"));

    ASSERT_NEQ(NULL, ttyname(slave));
    ASSERT_EQ(0, strncmp(ttyname(slave), "/tvm/pts/", 9));
    ASSERT_EQ(0, strncmp(ptsname(master), "/tvm/pts/", 9));
    ASSERT_EQ(0, strcmp(ptsname(master), ttyname(slave)));
}

TEST(TTYCloseMasterFork) {
    int master, slave;
	ASSERT_EQ(0, openpty(&master, &slave, NULL, NULL, NULL));
    ASSERT_EQ(1, isatty(slave));
    ASSERT_EQ(0, strncmp(ttyname(slave), "/tvm/pts/", 9));

    pid_t p = fork();
    ASSERT_NEQ(p, -1);
    if (!p) {
        ASSERT_EQ(1, isatty(slave));
        ASSERT_EQ(0, close(master));
        ASSERT_EQ(1, isatty(slave));
        exit(0);
    }
    ASSERT_EQ(p, wait(NULL));
    
    ASSERT_EQ(0, close(master));
    ASSERT_EQ(NULL, ttyname(slave));
    ASSERT_EQ(0, isatty(slave));
}

TEST(TTYCloseMasterDup2) {
    int master, slave;
	ASSERT_EQ(0, openpty(&master, &slave, NULL, NULL, NULL));
    
    int master2 = dup(master);
    ASSERT_NEQ(master2, -1);
    ASSERT_EQ(master, dup2(slave, master));
    ASSERT_EQ(1, isatty(master));
    ASSERT_EQ(master2, dup2(master, master2));
    ASSERT_EQ(0, isatty(master));
}

TEST(TTYCloseSlave) {
    int master, slave;
	ASSERT_EQ(0, openpty(&master, &slave, NULL, NULL, NULL));
    ASSERT_EQ(1, isatty(master));
    ASSERT_EQ(0, strncmp(ptsname(master), "/tvm/pts/", 9));

    ASSERT_EQ(0, close(slave));
    ASSERT_EQ(1, isatty(master));
    ASSERT_EQ(0, strncmp(ptsname(master), "/tvm/pts/", 9));

    ASSERT_NEQ(-1, open(ptsname(master), O_RDWR | O_NOCTTY));
}

static COW_IMPL_INIT(int, got_sig, 0);
static void sighup_handler(int signo) {
    got_sig++;
}

TEST(TTYDetachCloseMaster) {
    int master, slave;
	ASSERT_EQ(0, openpty(&master, &slave, NULL, NULL, NULL));

    struct sigaction act = { .sa_handler = sighup_handler };

    pid_t p = fork();
    ASSERT_NEQ(-1, p);

    if (!p) {
        ASSERT_EQ(0, sigaction(SIGHUP, &act, NULL));
        ASSERT_EQ(0, close(master));
        ASSERT_EQ(getpid(), setsid());
        ASSERT_EQ(0, ioctl(slave, TIOCSCTTY, 0));

        usleep(200000);
        exit(got_sig-1);
    }

    usleep(100000);

    ASSERT_EQ(0, close(master));

    int s;
    ASSERT_EQ(p, wait(&s));
    ASSERT_EQ(WIFEXITED(s), 1);
    ASSERT_EQ(WEXITSTATUS(s), 0);
}

TEST(TTYDetachTIOCNOTTY) {
    int master, slave;
	ASSERT_EQ(0, openpty(&master, &slave, NULL, NULL, NULL));

    struct sigaction act = { .sa_handler = sighup_handler };

    pid_t p = fork();
    ASSERT_NEQ(-1, p);

    if (!p) {
        ASSERT_EQ(0, sigaction(SIGHUP, &act, NULL));
        ASSERT_EQ(0, close(master));
        ASSERT_EQ(getpid(), setsid());
        ASSERT_EQ(0, ioctl(slave, TIOCSCTTY, 0));

        pid_t p2 = fork();
        ASSERT_NEQ(-1, p2);

        if (!p2) {
            usleep(200000);
            exit(got_sig-1);
        }

        ASSERT_EQ(0, setpgid(p2, p2));
        ASSERT_EQ(0, tcsetpgrp(slave, p2));

        usleep(100000);

        ASSERT_EQ(0, ioctl(slave, TIOCNOTTY, 0));

        int s;
        ASSERT_EQ(p2, wait(&s));
        ASSERT_EQ(WIFEXITED(s), 1);
        ASSERT_EQ(WEXITSTATUS(s), 0);

        exit(got_sig);
    }

    usleep(100000);

    int s;
    ASSERT_EQ(p, wait(&s));
    ASSERT_EQ(WIFEXITED(s), 1);
    ASSERT_EQ(WEXITSTATUS(s), 0);
}

//////////
//// Framework
//////////

#define MAX_TESTS 1024

struct testinfo_t {
    void (*f)();
    const char * n;
    int r;
    void *out;
    size_t out_s;
    void *err;
    size_t err_s;
} tests[MAX_TESTS + 1] = {0};

static int get_next_test_idx() {
    int idx;
    for (idx = 0; idx < MAX_TESTS; idx++) {
        if (tests[idx].f == NULL)
            return idx;
    }

    return -1;
}

void _add_test(const char *n, void (*f)())
{
    int idx = get_next_test_idx();
    if (idx == -1) {
        fprintf(stderr, "too many tests for %s", (n));
        abort();
    }
    tests[idx].f = f;
    tests[idx].n = n;
}

static int runtest(struct testinfo_t *testinfo, int verbose)
{
    int outp[2] = {-1, -1};
    if (-1 == pipe(outp)) {
        perror("test_tvm: pipe");
        abort();
    }

    int errp[2] = {-1, -1};
    if (-1 == pipe(errp)) {
        perror("test_tvm: pipe");
        abort();
    }

    if (-1 == fcntl(outp[0], F_SETFL, O_NONBLOCK) || -1 == fcntl(errp[0], F_SETFL, O_NONBLOCK)) {
        perror("test_tvm: fcntl");
        abort();
    }

    pid_t p = fork();
    if (p == -1) {
        perror("test_tvm: fork");
        abort();
    }

    if (0 == p) {
        close(outp[0]);
        close(errp[0]);
        dup2(outp[1], 1);
        dup2(errp[1], 2);
        close(outp[1]);
        close(errp[1]);

        if (getpid() != setsid()) {
            perror("test_tvm: set sid");
            exit(1);
        }

        tvm_init();
        testinfo->f();
        exit(0);
    }

    close(outp[1]);
    close(errp[1]);
    int status = 0;
    char tmp[0x4000] = {0};
    int newline = 1;

    while (1) {
        if (-1 == usleep(2)) {
            perror("test_tvm: usleep");
            abort();
        }

        ssize_t b = read(outp[0], tmp, 0x4000);
        if (b == -1) {
            if (errno != EAGAIN) {
                perror("read(outp)");
                abort();
            }
            b = 0;
        }
        if (b) {
            if (verbose)
            {
                if (newline) {
                    printf("\n");
                    newline = 0;
                }
                write(1, tmp, b);
            }
            testinfo->out = realloc(testinfo->out, testinfo->out_s + b);
            if (!testinfo->out) {
                perror("realloc(out)");
                abort();
            }
            memcpy(((char *) testinfo->out) + testinfo->out_s, tmp, b);
            testinfo->out_s += b;
        }

        b = read(errp[0], tmp, 0x4000);
        if (b == -1) {
            if (errno != EAGAIN) {
                perror("read(errp)");
                abort();
            }
            b = 0;
        }
        if (b) {
            if (verbose) {
                if (newline) {
                    printf("\n");
                    newline = 0;
                }
                write(1, tmp, b);
            }
            testinfo->err = realloc(testinfo->err, testinfo->err_s + b);
            if (!testinfo->err) {
                perror("realloc(err)");
                abort();
            }
            memcpy(((char *) testinfo->err) + testinfo->err_s, tmp, b);
            testinfo->err_s += b;
        }

        pid_t a = 0;
        if (-1 == (a = waitpid(p, &status, WNOHANG))) {
            perror("test_tvm: waitpid");
            abort();
        }

        if (a == p) {
            break;
        }

        if (a != 0) {
            fprintf(stderr, "test_tvm: waitpid: unknown pid %d (want %d)\n", a, p);
            abort();
        }
    }

    close(outp[1]);
    close(errp[1]);

    if (!WIFEXITED(status)) {
        testinfo->r = -WTERMSIG(status);
        return testinfo->r;
    }

    testinfo->r = WEXITSTATUS(status);;
    return testinfo->r;
}

void helpexit(char *exe)
{
    printf("USAGE: %s [OPTION]...\n", exe);
    printf("Run tests\n\n");
    printf("  -l             print test list and exit\n");
    printf("  -k=TEST        only run TEST (can be passed multiple times)\n");
    printf("  -v             verbose output\n");
    printf("  -g             debug with gdb\n");
    printf("  -h             display this help and exit\n");
    exit(0);
}

void listtests(char *exe)
{
    printf("Tests list for %s:\n\n", exe);
    int i = 0;
    for (; tests[i].f; i++) {
        printf("  %d. %s\n", i+1, tests[i].n);
    }
    if (!i)
        printf("  - no tests\n");
    exit(0);
}

int gdb(int argc, char **argv)
{
    const char *gargv[] = {
        "gdb",
        "-ex",
        "set follow-fork-mode child",
        "-ex",
        "r",
        "--args"
    };
    int gargc = sizeof(gargv)/sizeof(*gargv);

    putenv("TEST_IN_GDB=1");

    int nargc = gargc + argc;
    char **nargv = malloc((nargc+1) * sizeof(char *));
    if (!nargv) {
        errno = ENOMEM;
        perror("gdb");
        exit(1);
    }
    memcpy(nargv, gargv, gargc * sizeof(char *));
    memcpy(nargv + gargc, argv, argc * sizeof(char *));
    nargv[nargc] = 0;

    execvp("gdb", nargv);
    perror("execvp(\"gdb\")");
    exit(1);
}

int main(int argc, char **argv)
{
    setbuf(stdout, NULL);
    
    int test_names_s = 0;
    char **test_names = NULL;
    int c;
    int verbose = 0;

    do {
        c = getopt(argc, argv, "hlgvk:");

        if (c == 'h') {
            helpexit(argv[0]);
        }
        else if (c == 'l') {
            listtests(argv[0]);
        }
        else if (c == 'g') {
            if (!getenv("TEST_IN_GDB") || 0 != strcmp(getenv("TEST_IN_GDB"), "1"))
                gdb(argc, argv);
        }
        else if (c == 'v') {
            verbose++;
        }
        else if (c == 'k') {
            test_names = realloc(test_names, sizeof(char *) * (test_names_s+1));
            if (!test_names) {
                fprintf(stderr, "out of memory\n");
                return 1;
            }
            test_names[test_names_s] = strdup(optarg);
            test_names_s++;
        }
        else {
            if (c == -1) {
                if (!argv[optind])
                    break;
                fprintf(stderr, "%s: invalid argument '%s'\n", argv[0], argv[optind]);
            }
            fprintf(stderr, "Try '%s -h' for more information.\n", argv[0]);
            exit(1);
        }
    }
    while (c >= 0);

    if (test_names_s) {
        for (int j = 0; j < test_names_s; j++) {
            int found = 0;
            for (int i = 0; tests[i].f; i++) {
                if (strcmp(test_names[j], tests[i].n) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                fprintf(stderr, "%s: invalid test \"%s\"\n", argv[0], test_names[j]);
                fprintf(stderr, "Try '%s -l' for tests list.\n", argv[0]);
                exit(1);
            }
        }
    }

    printf("tvm ");
    int r = 0, i = 0;
    for (; tests[i].f; i++) {
        if (test_names_s) {
            int skip = 1;
            for (int j = 0; j < test_names_s; j++) {
                if (strcmp(test_names[j], tests[i].n) == 0) {
                    skip = 0;
                    break;
                }
            }
            if (skip)
                continue;
        }

        r = runtest(tests + i, verbose);
        if (r) {
            printf((r>0)?"F":"C");
            break;
        }
        else {
            printf(".");
        }
    }
    printf("\n");

    if (r) {
        printf("\n======== TEST FAILED: %s ========\n", tests[i].n);
        if (r<0) {
            printf("** CRASHED !!! ***\nSignal: %d\n", -r);
        }
        if (tests[i].out_s) {
            printf("\n==== captured stdout ====\n");
            while (tests[i].out_s) {
                size_t w = write(1, tests[i].out, tests[i].out_s);
                if (w == -1 || 0 == w) {
                    perror("write(out)");
                    break;
                }
                tests[i].out_s -= w;
                tests[i].out = (void *) (((char *) tests[i].out) + w);
            }
        }
        if (tests[i].err_s) {
            printf("\n==== captured stderr ====\n");
            while (tests[i].err_s) {
                size_t w = write(1, tests[i].err, tests[i].err_s);
                if (w == -1 || 0 == w) {
                    perror("write(err)");
                    break;
                }
                tests[i].err_s -= w;
                tests[i].err = (void *) (((char *) tests[i].err) + w);
            }
        }
    }

    return r;
}