#define _GNU_SOURCE
#include <dlfcn.h>

#include <sys/uio.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <setjmp.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <limits.h>
#include <termios.h>
#include <pty.h>
#include <malloc.h>
#include <getopt.h>
#include <grp.h>

#include "tvm.h"

/**
 * TODOs:
 * 1. thread exits
 * 2. signals - masks
 * 4. syscalls: posix_fadvise, posix_fallocate, posix_openpt, grantpt, ptsname, unlockpt
 */

#define panic(Msg, ...) do { char __MSG[0x1000] = {0}; snprintf(__MSG, sizeof(__MSG), Msg, ##__VA_ARGS__); __panic(__MSG, __FILE__, __LINE__); } while (0)
static void __panic(const char *m, const char *f, int l);


#ifdef __O_TMPFILE
#define __OPEN_NEEDS_MODE(oflag) \
  (((oflag) & O_CREAT) != 0 || ((oflag) & __O_TMPFILE) == __O_TMPFILE)
#else
# define __OPEN_NEEDS_MODE(oflag) (((oflag) & O_CREAT) != 0)
#endif

#define WRITE_ONCE(x, val) x=(val)
#define READ_ONCE(x) (x)

#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)((char *)__mptr - offsetof(type,member));})

#define INFO(Msg, ...) do { CALL_FUNC(printf, "Kernel(%d): %s: " Msg "\n", __gettid(), __FUNCTION__, ##__VA_ARGS__); } while (0)

#define MALLOC_MAGIC ((uintptr_t) 0xFACEFACE)

/////////////
// List
/////////////

#define LIST_POISON1  ((void *) 0x100)
#define LIST_POISON2  ((void *) 0x122)

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

struct list_head {
    struct list_head *next, *prev;
};

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	WRITE_ONCE(list->next, list);
	WRITE_ONCE(list->prev, list);
}

static inline void __list_add(struct list_head *new,
			      struct list_head *prev,
			      struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	WRITE_ONCE(prev->next, new);
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head);
}

static inline void list_del(struct list_head *entry)
{
    entry->next->prev = entry->prev;
	WRITE_ONCE(entry->prev->next, entry->next);
    
	entry->next = LIST_POISON1;
	entry->prev = LIST_POISON2;
}

static inline int list_empty(const struct list_head *head)
{
	return READ_ONCE(head->next) == head;
}

#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)

static inline int list_is_head(const struct list_head *list, const struct list_head *head)
{
	return list == head;
}

#define list_entry_is_head(pos, head, member)				\
	list_is_head(&pos->member, (head))

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
	     !list_entry_is_head(pos, head, member);			\
	     pos = list_next_entry(pos, member))

/////////////
// Functions
/////////////

#define LOCAL_SYM(Name) o_##Name
#define DECL_FUNC(Name) \
    static typeof(Name) *LOCAL_SYM(Name) = NULL; \
    static struct original_func_t _of_ ## Name = { .ptrdest = (void *)&LOCAL_SYM(Name), .name = #Name }; \
    __attribute__((constructor)) \
    static void _ofc_ ## Name () { list_add_tail( & (_of_ ## Name).list, &original_functions); }
#define CALL_FUNC(Name, ...) (LOCAL_SYM(Name) (__VA_ARGS__))

struct original_func_t {
    struct list_head list;
    void **ptrdest;
    const char *name;
};

static LIST_HEAD(original_functions);

DECL_FUNC(fdopen);
DECL_FUNC(fwrite);
DECL_FUNC(fread);
DECL_FUNC(fclose);
DECL_FUNC(fseek);
DECL_FUNC(ftell);
DECL_FUNC(fflush);
DECL_FUNC(setbuf);
DECL_FUNC(setbuffer);
DECL_FUNC(setlinebuf);
DECL_FUNC(setvbuf);
DECL_FUNC(fputc);
DECL_FUNC(fputs);
DECL_FUNC(putc);
DECL_FUNC(putchar);
DECL_FUNC(puts);
DECL_FUNC(fgetc);
DECL_FUNC(fgets);
DECL_FUNC(getc);
DECL_FUNC(getchar);
DECL_FUNC(ungetc);
DECL_FUNC(clearerr);
DECL_FUNC(feof);
DECL_FUNC(ferror);
DECL_FUNC(fileno);

DECL_FUNC(printf);
DECL_FUNC(fprintf);
DECL_FUNC(dprintf);
DECL_FUNC(vprintf);
DECL_FUNC(vfprintf);
DECL_FUNC(vdprintf);
DECL_FUNC(scanf);
DECL_FUNC(fscanf);
DECL_FUNC(vscanf);
DECL_FUNC(vfscanf);
DECL_FUNC(perror);

DECL_FUNC(open);
DECL_FUNC(creat);
DECL_FUNC(openat);
DECL_FUNC(read);
DECL_FUNC(write);
DECL_FUNC(close);
DECL_FUNC(readv);
DECL_FUNC(writev);
DECL_FUNC(lseek);
DECL_FUNC(fsync);
DECL_FUNC(dup);
DECL_FUNC(dup2);
DECL_FUNC(pipe);
DECL_FUNC(select);
DECL_FUNC(poll);
DECL_FUNC(fcntl);
DECL_FUNC(ftruncate);
DECL_FUNC(stat);
DECL_FUNC(fstat);
DECL_FUNC(fstatat);
DECL_FUNC(faccessat);
DECL_FUNC(chmod);
DECL_FUNC(fchmod);
DECL_FUNC(fchmodat);
DECL_FUNC(chown);
DECL_FUNC(fchown);
DECL_FUNC(fchownat);
DECL_FUNC(flock);
DECL_FUNC(lockf);
DECL_FUNC(readlinkat);
DECL_FUNC(symlinkat);
DECL_FUNC(linkat);
DECL_FUNC(renameat);
DECL_FUNC(unlinkat);
DECL_FUNC(mknodat);
DECL_FUNC(mkdirat);

DECL_FUNC(socket);
DECL_FUNC(accept);
DECL_FUNC(bind);
DECL_FUNC(listen);
DECL_FUNC(connect);
DECL_FUNC(getpeername);
DECL_FUNC(getsockname);
DECL_FUNC(getsockopt);
DECL_FUNC(setsockopt);
DECL_FUNC(send);
DECL_FUNC(sendto);
DECL_FUNC(sendmsg);
DECL_FUNC(recv);
DECL_FUNC(recvfrom);
DECL_FUNC(recvmsg);
DECL_FUNC(shutdown);
DECL_FUNC(socketpair);
DECL_FUNC(ioctl);

DECL_FUNC(pthread_create);
DECL_FUNC(pthread_exit);

DECL_FUNC(exit);
DECL_FUNC(_exit);
DECL_FUNC(_Exit);
DECL_FUNC(abort);

DECL_FUNC(getpid);
DECL_FUNC(getppid);

DECL_FUNC(fork);
DECL_FUNC(wait);
DECL_FUNC(waitpid);

DECL_FUNC(setsid);
DECL_FUNC(getsid);
DECL_FUNC(setpgid);
DECL_FUNC(getpgid);
DECL_FUNC(getpgrp);
DECL_FUNC(setpgrp);

DECL_FUNC(signal);
DECL_FUNC(sigaction);
DECL_FUNC(raise);
DECL_FUNC(kill);

DECL_FUNC(getenv);
DECL_FUNC(putenv);
DECL_FUNC(setenv);
DECL_FUNC(unsetenv);
DECL_FUNC(clearenv);

DECL_FUNC(execve);
DECL_FUNC(execl);
DECL_FUNC(execlp);
DECL_FUNC(execle);
DECL_FUNC(execv);
DECL_FUNC(execvp);
DECL_FUNC(execvpe);

DECL_FUNC(openpty);

DECL_FUNC(tcgetpgrp);
DECL_FUNC(tcsetpgrp);
DECL_FUNC(isatty);
DECL_FUNC(ttyname);
DECL_FUNC(ttyname_r);
DECL_FUNC(ptsname);
DECL_FUNC(ptsname_r);

DECL_FUNC(tcgetattr);
DECL_FUNC(tcsetattr);
DECL_FUNC(tcsendbreak);
DECL_FUNC(tcdrain);
DECL_FUNC(tcflush);
DECL_FUNC(tcflow);

DECL_FUNC(malloc);
DECL_FUNC(realloc);
DECL_FUNC(free);

DECL_FUNC(getopt);
DECL_FUNC(getopt_long);
DECL_FUNC(getopt_long_only);

__attribute__((constructor))
static void init_funcs()
{
    struct original_func_t *curr_func;
    list_for_each_entry(curr_func, &original_functions, list) {
        *curr_func->ptrdest = dlsym(RTLD_NEXT, curr_func->name );
        if (NULL == *curr_func->ptrdest)
            panic("function '%s' not found", curr_func->name);
    }
};

/////////////
// Helpers
/////////////

static pid_t __gettid()
{
#ifdef __linux__
    return syscall(SYS_gettid);
#else
#error platform
#endif
}

#define	__W_EXITCODE(ret, sig)	((ret) << 8 | (sig))

static int mkwstatus(int is_exit, int status_or_signal)
{
    if (is_exit) {
        return __W_EXITCODE(status_or_signal, 0);
    }

    return __W_EXITCODE(0, status_or_signal);
}

static int intparse(const char *s, long long *out, int base)
{
    char *endp;

    errno = 0;
    long long r = strtoll(s, &endp, base);
    if (0 != errno)
        return -1;
    
    // not entire string is valid
    if (*endp)
        return -1;
    
    *out = r;
    return 0;
}

/////////////
// Jmpbuf manipulation
/////////////

#ifdef __linux__
#ifdef __x86_64__

#define JB_RBX	0
#define JB_RBP	1
#define JB_R12	2
#define JB_R13	3
#define JB_R14	4
#define JB_R15	5
#define JB_RSP	6
#define JB_PC	7
#define JB_SIZE (8*8)

#define PTR_MANGLE(var)	asm ("xor %%fs:0x30, %0\n"		      \
				     "rol $2*8+1, %0"		      \
				     : "=r" (var)			      \
				     : "0" (var))
#define PTR_DEMANGLE(var) asm ("ror $2*8+1, %0\n"	      \
				     "xor %%fs:0x30, %0"			      \
				     : "=r" (var) \
				     : "r" (var))

static void jmpbuf_mangle(jmp_buf *jmpbuf)
{
    void **jb = (void **) (jmpbuf);
    PTR_MANGLE(jb[JB_RBP]);
    PTR_MANGLE(jb[JB_RSP]);
    PTR_MANGLE(jb[JB_PC]);
}

static void jmpbuf_demangle(jmp_buf *jmpbuf)
{
    void **jb = (void **) (jmpbuf);
    PTR_DEMANGLE(jb[JB_RBP]);
    PTR_DEMANGLE(jb[JB_RSP]);
    PTR_DEMANGLE(jb[JB_PC]);
}

static void *jmpbuf_getstack(jmp_buf *jmpbuf)
{
    void **jb = (void **) (jmpbuf);
    return jb[JB_RSP];
}

static void jmpbuf_setstack(jmp_buf *jmpbuf, uintptr_t new_stack, uintptr_t old_stack, size_t stack_size)
{
    uintptr_t *jb = (uintptr_t*) (jmpbuf);
    intptr_t diff = old_stack - new_stack;
 
    for (int i = 0; i < (JB_SIZE/8); i++)
    {
        if (jb[i] >= old_stack && jb[i] < (old_stack + stack_size))
            jb[i] -= diff;
    }

    for (uintptr_t *p = (uintptr_t *)new_stack; p < (uintptr_t *)(new_stack + stack_size); p++) {
        if ((*p >= old_stack) && (*p < (old_stack + stack_size)))
            *p -= diff;
    }
}

static void jmpbuf_dupstack(jmp_buf *jmpbuf, uintptr_t new_stack, uintptr_t old_stack, size_t stack_size)
{
    uintptr_t x;

    uintptr_t jmpbuf_old_sp = (uintptr_t) jmpbuf_getstack(jmpbuf);

    if (!(jmpbuf_old_sp >= old_stack && jmpbuf_old_sp < (old_stack + stack_size)))
        panic("jmpbuf's sp not in old_stack");

    memcpy(
        (void *) new_stack,
        (void *) old_stack,
        stack_size - 0x1000
    );

    jmpbuf_setstack(jmpbuf, new_stack, old_stack, stack_size);
}

#undef PTR_MANGLE
#undef PTR_DEMANGLE

#endif
#endif

/////////////
// Environment
/////////////

extern char **environ;

/**
 * Excluding last NULL byte.
 */
static size_t envsize(char **env)
{
    int sz = 0;
    if (env) {
        for (char **e = env; *e != NULL; e++)
            sz++;
    }
    return sz;
}

static char **copyenv(char **env)
{
    if (!env)
        return NULL;
    
    int ok = 0;
    int sz = envsize(env);

    char **r = malloc(sizeof(char *) * (sz+1));
    if (!r)
        goto out;
    memset(r, 0, sizeof(char *) * (sz+1));
    
    for (int i = 0; i < sz; i++) {
        r[i] = strdup(env[i]);
        if (!r[i]) {
            goto out;
        }
    }

    ok = 1;

out:

    if (!ok) {
        if (r) {
            for (char **e = r; *e != NULL; e++)
                free(e);
            free(r);
        }
        return NULL;
    }

    return r;
}

static char **addenv(char **env, char *string)
{
    int sz = envsize(env);
    char **newenv = malloc(sizeof(char *) * (sz+2));
    if (!newenv)
        return NULL;
    
    newenv[sz] = string;
    newenv[sz + 1] = 0;

    if (env)
        memcpy(newenv, env, sizeof(char *) * sz);
    
    return newenv;
}

static char **findenv(char **env, const char *name, size_t name_len)
{
    if (env) {
        for (char **e = env; *e != NULL; e++) {
            if (0 == strncmp(*e, name, name_len)) {
                if ((*e)[name_len] == '=') {
                    return e;
                }
                if ((*e)[name_len] == 0) {
                    return e;
                }
            }
        }
    }

    return NULL;
}

/////////////
// Declarations
/////////////

struct fops;
struct task;

struct fops *fops_for_fd_locked(struct task *t, int fd);
int fops_fdflag(struct fops *fops);
int fops_dup(struct fops *fops, int oldfd, int newfd);

/////////////
// Task
/////////////

#define MAX_FILES 1024
#define MAX_SIGNALS 32

#define TS_ZOMBIE  0x1
#define TS_CTTY    0x2

#define TFD_MASK 0x0F000000
#define TFD_TTY  0x01000000

struct pthread_entry {
    struct list_head ptl_entry;
    pthread_t ptl_value;
};

struct pthread_entry *make_pthread_entry(pthread_t t)
{
    struct pthread_entry *pentry = malloc(sizeof(struct pthread_entry));
    if (pentry) {
        INIT_LIST_HEAD(&pentry->ptl_entry);
        pentry->ptl_value = t;
    }
    return pentry;
}

struct task {
    struct list_head tsk_list;
    struct task *tsk_parent;
    unsigned tsk_refcount;
    pid_t tsk_pid;
    int tsk_result;  // wstatus as returned from `waitpid()`
    pthread_mutex_t tsk_lock;
    int tsk_fd[MAX_FILES];
    FILE *tsk_f[3];
    int tsk_state;
    pthread_cond_t tsk_wait_cond;
    pthread_mutex_t tsk_wait_lock;
    struct sigaction tsk_sighandlers[MAX_SIGNALS];
    unsigned tsk_pthreads_count;
    struct list_head tsk_pthreads;  // pthread_entry
    pid_t tsk_sid;
    pid_t tsk_pgid;
    char **tsk_environ;
};

static pthread_t main_pthread;
static struct task *main_task = NULL;
static pthread_mutex_t tasks_lock = PTHREAD_MUTEX_INITIALIZER;
static __thread struct task *current;

static void task_lock(struct task *t)
{
    pthread_mutex_lock(&t->tsk_lock);
}

static void task_unlock(struct task *t)
{
    pthread_mutex_unlock(&t->tsk_lock);
}

static int t_fd(int fd)
{
    if (!main_task)
        return fd;
    
    if (!current)
        panic("t_fd");
    
    if (fd < 0 || fd >= MAX_FILES)
        return -1;

    if (current->tsk_fd[fd] >= 0)
        return current->tsk_fd[fd] & (~TFD_MASK);
    return current->tsk_fd[fd];
}

static int t_fdr(int fd, int lock)
{
    if (!main_task)
        return fd;
    
    if (lock)
        task_lock(current);
    
    if (fd >= 0) {
        for (int i = 0; i < MAX_FILES; i++) {
            if (fd == (current->tsk_fd[i] & ~TFD_MASK)) {
                if (lock)
                    task_unlock(current);
                return i;
            }
        }
    }

    if (lock)
        task_unlock(current);
    return -1;
}

static struct task *taskalloc()
{
    struct task *t = malloc(sizeof(struct task));
    if (!t)
        panic("taskalloc");
    
    INIT_LIST_HEAD(&t->tsk_list);
    INIT_LIST_HEAD(&t->tsk_pthreads);

    t->tsk_parent = NULL;
    t->tsk_refcount = 1;
    t->tsk_state = 0;
    t->tsk_pthreads_count = 0;

    if (pthread_mutex_init(&t->tsk_lock, NULL) != 0) {
        panic("taskalloc::pthread_mutex_init(lock)");
    }
    if (pthread_mutex_init(&t->tsk_wait_lock, NULL) != 0) {
        panic("taskalloc::pthread_mutex_init(wait_lock)");
    }
    if (pthread_cond_init(&t->tsk_wait_cond, NULL) != 0) {
        panic("taskalloc::pthread_cond_init(wait_cond)");
    }

    for (int i = 0; i < MAX_FILES; i++)
        t->tsk_fd[i] = -1;
    for (int i = 0; i < 3; i++)
        t->tsk_f[i] = NULL;

    
    if (main_pthread == pthread_self() && !current) {
        main_task = t;
        t->tsk_pid = __gettid();
        for (int i = 0; i < 3; i++)
            t->tsk_fd[i] = i;
        t->tsk_f[0] = stdin;
        t->tsk_f[1] = stdout;
        t->tsk_f[2] = stderr;

        t->tsk_environ = copyenv(environ);
        if (!t->tsk_environ)
            panic("copyenv");

        if (-1 == (t->tsk_sid = CALL_FUNC(getsid, 0)))
            panic("getsid");
        if (-1 == (t->tsk_pgid = CALL_FUNC(getpgid, 0)))
            panic("getpgid");

        struct pthread_entry *pent = make_pthread_entry(pthread_self());
        if (!pent)
            panic("taskalloc make_pthread_entry");
        list_add_tail(&pent->ptl_entry, &t->tsk_pthreads);
        ++t->tsk_pthreads_count;
    } else {
        task_lock(current);
        t->tsk_parent = current;
        t->tsk_pid = -1;
        t->tsk_sid = current->tsk_sid;
        t->tsk_pgid = current->tsk_pgid;
        t->tsk_state = current->tsk_state & TS_CTTY;

        t->tsk_environ = copyenv(current->tsk_environ);
        if (!t->tsk_environ)
            panic("copyenv");

        for (int i = 0; i < MAX_FILES; i++) {
            if (t_fd(i) == -1)
                continue;
            
            int newfd = CALL_FUNC(dup, t_fd(i));
            if (newfd == -1)
                panic("taskalloc::dup");
            t->tsk_fd[i] = newfd;
            
            struct fops *fops = fops_for_fd_locked(current, i);
            t->tsk_fd[i] |= fops_fdflag(fops);
            if (0 != fops_dup(fops, t_fd(i), newfd)) {
                CALL_FUNC(close, newfd);
                panic("taskalloc::f_dup");
            }
        }
        for (int i = 0; i < 3; i++) {
            t->tsk_f[i] = CALL_FUNC(fdopen, t->tsk_fd[i] & ~TFD_MASK, (i?"w":"r"));
            if (!t->tsk_f[i])
                panic("taskalloc::fdopen");
        }

        memcpy(t->tsk_sighandlers, t->tsk_parent->tsk_sighandlers, sizeof(t->tsk_sighandlers));

        pthread_mutex_lock(&tasks_lock);
        list_add_tail(&t->tsk_list, &main_task->tsk_list);
        pthread_mutex_unlock(&tasks_lock);
        task_unlock(current);
    }

    return t;
}

static void taskdealloc(struct task *t)
{
    pthread_mutex_lock(&tasks_lock);
    list_del(&t->tsk_list);
    pthread_mutex_unlock(&tasks_lock);

    if (t->tsk_pthreads_count != 1)
        panic("taskdealloc tsk_pthreads_count");
    --t->tsk_pthreads_count;
    if (list_empty(&t->tsk_pthreads))
        panic("taskalloc tsk_pthreads empty");
    
    struct pthread_entry *pentry = list_entry(t->tsk_pthreads.next, struct pthread_entry, ptl_entry);
    list_del(&pentry->ptl_entry);
    free(pentry);
    if (!list_empty(&t->tsk_pthreads))
        panic("taskalloc tsk_pthreads not one");

    // TODO might be bad to free env
    //for (char **e = t->tsk_environ; *e != NULL; e++)
        //free(*e);

    pthread_cond_destroy(&t->tsk_wait_cond);
    pthread_mutex_destroy(&t->tsk_wait_lock);
    pthread_mutex_unlock(&t->tsk_lock);
    pthread_mutex_destroy(&t->tsk_lock);

    free(t);
}

/**
 * `t` locked.
 */
static void taskfreelastref(struct task *t, int dealloc)
{
    for (int i = 0; i < 3; i++) {
        if (t->tsk_f[i] != NULL)
            CALL_FUNC(fclose, t->tsk_f[i]);
        else if (t->tsk_fd[i] != -1)
            CALL_FUNC(close, t->tsk_fd[i]);
        t->tsk_fd[i] = -1;
        t->tsk_f[i] = NULL;
    }

    for (int i = 3; i < MAX_FILES; i++) {
        if (t->tsk_fd[i] != -1)
            CALL_FUNC(close, t->tsk_fd[i]);
        t->tsk_fd[i] = -1;
    }

    pthread_mutex_lock(&tasks_lock);
    struct task *child;
    list_for_each_entry(child, &main_task->tsk_list, tsk_list) {
        if (child->tsk_parent == current) {
            task_lock(child); // TODO no way there aint deadlock here right?
            child->tsk_parent = NULL;
            task_unlock(child);
        }
    }
    pthread_mutex_unlock(&tasks_lock);


    if (dealloc)
        taskdealloc(t);
}

static int task_get_fd_locked(struct task *t, int min_fd)
{
    if (min_fd < 0)
        return -1;
    
    for (int i = min_fd; i < MAX_FILES; i++) {
        if (t->tsk_fd[i] == -1)
            return i;
    }

    return -1;
}

static int task_reserve_fd(struct task *t, int min_fd)
{
    task_lock(t);
    int f = task_get_fd_locked(t, min_fd);
    if (f != -1)
        current->tsk_fd[f] = -2;
    task_unlock(t);
    return f;
}

static int task_set_fd(struct task *t, int f, int r)
{
    if (f < 0 || f >= MAX_FILES)
        panic("f %d", f);
    
    task_lock(t);
    t->tsk_fd[f] = r;
    task_unlock(t);
    
    return r;
}

static int task_new_fd(struct task *t, int min_fd, int new_fd) {
    
    task_lock(current);
    int fd = task_get_fd_locked(current, min_fd);
    if (fd != -1) {
        current->tsk_fd[fd] = new_fd;
    }
    task_unlock(current);

    return fd;

}

static struct task *task_for_pid(pid_t pid) {
    if (main_task->tsk_pid == pid)
        return main_task;

    pthread_mutex_lock(&tasks_lock);
    struct task *t;
    list_for_each_entry(t, &main_task->tsk_list, tsk_list) {
        if (t->tsk_pid == pid) {
            break;
        }
    }

    // TODO prolly should lock task here, but need to not deadlock

    pthread_mutex_unlock(&tasks_lock);

    if (t == main_task)
        return NULL;

    return t;
}

static int task_kill_locked(struct task *t, int signum) {
    if (list_empty(&t->tsk_pthreads))
        return ESRCH;
    
    struct pthread_entry *pent = list_entry(t->tsk_pthreads.next, struct pthread_entry, ptl_entry);
    return pthread_kill(pent->ptl_value, signum);
}

/**
 * `t->tsk_wait_lock` held
 */
static struct task *task_next_zombie_child(struct task *t, pid_t pid, int *found) {
    pthread_mutex_lock(&tasks_lock);

    *found = 0;

    struct task *childt;
    list_for_each_entry(childt, &main_task->tsk_list, tsk_list) {
        if (childt->tsk_parent != t)
            continue;

        if (pid == -1)
            *found = 1;
        else if (pid > 0 && pid == childt->tsk_pid)
            *found = 1;
        else if (pid < -1 && (-pid) == childt->tsk_pgid)
            *found = 1;

        if ((childt->tsk_state & TS_ZOMBIE) == 0)
            continue;

        if (pid > 0 && childt->tsk_pid != pid)
            continue;

        if (pid < -1 && (-pid) != childt->tsk_pgid)
            continue;
        
        break;
    }

    pthread_mutex_unlock(&tasks_lock);

    if (childt == main_task)
        childt = NULL;
    
    return childt;
}

__attribute__((noreturn))
static void terminate_current_locked(int result)
{
    // TODO kill all threads, make sure refcount==1
    if (current->tsk_refcount != 1)
        panic("_exit refcount");
    --current->tsk_refcount;

    // SIGCHLD special cases
    struct task *parent = NULL;
    int notify_parent = 0;
    int auto_reap = 1;
    if (current->tsk_parent) {
        task_lock(current->tsk_parent);

        parent = current->tsk_parent;
        auto_reap = 0;
        notify_parent = 1;

        struct sigaction *parent_act = &current->tsk_parent->tsk_sighandlers[SIGCHLD];
        void *handler = ((parent_act->sa_flags & SA_SIGINFO) ? ((void *) parent_act->sa_sigaction) : ((void *) parent_act->sa_handler));
        
        if (handler == ((void *) SIG_IGN))
            notify_parent = 0;
    
        if ((parent_act->sa_flags & SA_NOCLDWAIT) || handler == ((void *) SIG_IGN))
            auto_reap = 1;

        task_unlock(current->tsk_parent);
    }

    if (auto_reap) {
        taskfreelastref(current, 1);
        //pthread_detach(pthread_self());
    }
    else {
        if (!parent)
            panic("auto_reap=0 but parent is NULL");
        
        taskfreelastref(current, 0);
        pthread_mutex_lock(&parent->tsk_wait_lock);

        current->tsk_state |= TS_ZOMBIE;
        current->tsk_result = result;
        
        pthread_mutex_unlock(&parent->tsk_wait_lock);

        task_unlock(current);
    }
    current = NULL;

    if (parent)
        task_lock(parent);

    if (notify_parent && 0 != task_kill_locked(parent, SIGCHLD))
        panic("terminate_current_locked notify parent failed (%d)", errno);
    
    // parent may be blocked on waitpid but no more pids, wake him up!
    if (parent) {
        task_unlock(parent);
        pthread_cond_signal(&parent->tsk_wait_cond);
    }

    CALL_FUNC(pthread_exit, 0);
    __builtin_unreachable();
}

static FILE *t_f(FILE *f)
{
    if (!main_task)
        return f;
    
    if (!current)
        panic("t_f");

    if (f == stdin)
        return current->tsk_f[0];
    if (f == stdout)
        return current->tsk_f[1];
    if (f == stderr)
        return current->tsk_f[2];
    return f;
}

/////////////
// Signals
/////////////

#define SAD_TERM 0
#define SAD_IGN  1
#define SAD_CORE 2
#define SAD_STOP 3
#define SAD_CONT 4
#define SAD_CTCH 5

static const int default_signal_actions[MAX_SIGNALS] = {
    [SIGHUP]    = SAD_TERM, // 1
    [SIGINT]    = SAD_TERM, // 2
    [SIGQUIT]   = SAD_CORE, // 3
    [SIGILL]    = SAD_CORE, // 4
    [SIGTRAP]   = SAD_CORE, // 5
    [SIGABRT]   = SAD_CORE, // 6
    [SIGBUS]    = SAD_CORE, // 7
    [SIGFPE]    = SAD_CORE, // 8
    [SIGKILL]   = SAD_TERM, // 9
    [SIGUSR1]   = SAD_TERM, // 10
    [SIGSEGV]   = SAD_CORE, // 11
    [SIGUSR2]   = SAD_TERM, // 12
    [SIGPIPE]   = SAD_TERM, // 13
    [SIGALRM]   = SAD_TERM, // 14
    [SIGTERM]   = SAD_TERM, // 15
    [SIGSTKFLT] = SAD_TERM, // 16
    [SIGCHLD]   = SAD_IGN,  // 17
    [SIGCONT]   = SAD_CONT, // 18
    [SIGSTOP]   = SAD_STOP, // 19
    [SIGTSTP]   = SAD_STOP, // 20
    [SIGTTIN]   = SAD_STOP, // 21
    [SIGTTOU]   = SAD_STOP, // 22
    [SIGURG]    = SAD_IGN,  // 23
    [SIGXCPU]   = SAD_CORE, // 24
    [SIGXFSZ]   = SAD_CORE, // 25
    [SIGVTALRM] = SAD_TERM, // 26
    [SIGPROF]   = SAD_TERM, // 27
    [SIGWINCH]  = SAD_IGN,  // 28
    [SIGIO]     = SAD_TERM, // 29
    [SIGPWR]    = SAD_TERM, // 30
    [SIGSYS]    = SAD_CORE, // 31
};

static __thread int sigshutup = 0;

void signal_handler(int signum, siginfo_t *siginfo, void *ucontext)
{
    if (!sigshutup) {
        INFO("signum=%d", signum);
    }

    if (!current)
        panic("signal %d on pthread_exit", signum);
    
    task_lock(current);

    struct sigaction *act = current->tsk_sighandlers + signum;

    // need to figure out what to do first
    int whatdo = SAD_CTCH;
    if ((act->sa_flags & SA_SIGINFO) == 0) {
        if (act->sa_handler == SIG_IGN)
            whatdo = SAD_IGN;
        else if (act->sa_handler == SIG_DFL)
            whatdo = default_signal_actions[signum];
    }

    if (whatdo == SAD_TERM || whatdo == SAD_CORE)
        terminate_current_locked(mkwstatus(0, signum));
    if (whatdo == SAD_IGN) {
        task_unlock(current);
        return;
    }
    if (whatdo == SAD_STOP) {
        task_unlock(current);
        panic("signal_handler STOP"); // TODO what do we do
    }
    if (whatdo == SAD_CONT) {
        task_unlock(current);
        // TODO anything else we need to do?
        return;
    }
    
    if ((act->sa_flags & SA_SIGINFO) == 0) {
        void (*hand)(int) = act->sa_handler;
        task_unlock(current);
        return hand(signum);
    }
    
    void (*hand)(int, siginfo_t *, void *) = act->sa_sigaction;
    task_unlock(current);
    return hand(signum, siginfo, ucontext);
}

/////////////
// Devices
/////////////

struct fops {
    struct list_head list;

    int f_fdflag; // TFD_*

    int (*f_openchk)(const char *pathname);
    int (*f_open)(const char *pathname, int flags, mode_t mode);
    int (*f_dup)(int oldfd, int newfd);
    int (*f_stat)(int fd, struct stat *st);
    int (*f_chown)(int fd, uid_t owner, gid_t group);
    int (*f_chmod)(int fd, mode_t mode);
    int (*f_ioctl)(int fd, unsigned long request, void *arg);
    ssize_t (*f_read)(int fd, void *buf, size_t count, int offset);
    ssize_t (*f_write)(int fd, const void *buf, size_t count, int offset);
    int (*f_close)(int fd);
};

static LIST_HEAD(devices);
#define REGISTER_DEV(Fops) __attribute__((constructor)) \
    static void _tvm_dreg_ ## Fops () { list_add_tail(&((Fops).list), &devices); }

int fops_open(const char *pathname, int flags, mode_t mode)
{
    struct fops *f;
    
    list_for_each_entry(f, &devices, list) {
        if (f->f_openchk && f->f_open && f->f_openchk(pathname))
            return f->f_open(pathname, flags, mode);
    }

    return -1;
}

int fops_fdflag(struct fops *fops)
{
    if (!fops)
        return 0;
    
    return fops->f_fdflag;
}

int fops_dup(struct fops *fops, int oldfd, int newfd)
{
    if (!fops || !fops->f_dup)
        return 0;
    
    return fops->f_dup(oldfd, newfd);
}

struct fops *fops_for_fd_locked(struct task *t, int fd)
{
    if (fd < 0 || fd >= MAX_FILES || t->tsk_fd[fd] < 0)
        return NULL;
    
    struct fops *f;
    list_for_each_entry(f, &devices, list) {
        if (f->f_fdflag && (t->tsk_fd[fd] & f->f_fdflag))
            return f;
    }

    return NULL;
}

struct fops *fops_for_fd(struct task *t, int fd) {
    task_lock(current);
    struct fops *f = fops_for_fd_locked(t, fd);
    task_unlock(current);
    return f;
}

struct fops *fops_for_stream(struct task *t, FILE *stream) {
    task_lock(current);
    struct fops *f = fops_for_fd_locked(t, t_fdr(fileno(stream), 0));
    task_unlock(current);
    return f;
}

struct fops *fops_for_pathname(const char *pathname)
{
    struct fops *f;
    
    list_for_each_entry(f, &devices, list) {
        if (f->f_openchk && f->f_open && f->f_openchk(pathname))
            return f;
    }

    return NULL;
}

struct fops *fops_for_open(const char *pathname)
{
    struct fops *f;
    list_for_each_entry(f, &devices, list) {
        if (f->f_openchk && f->f_openchk(pathname))
            return f;
    }

    return NULL;
}

#define FOPS_PATH(Fops, Func, Pathname, ...) do { \
        if (!(Fops -> Func)) { \
            errno = ENOTSUP; \
            return -1; \
        } \
        int __FD = open(pathname, O_RDONLY | O_NOCTTY); \
        if (__FD == -1) \
            return -1; \
        int __R = (Fops -> Func)(t_fd(__FD), ##__VA_ARGS__); \
        if (0 == __R) \
            __R = close(__FD); \
        else \
            close(__R); \
        return __R; \
    } while (0)

ssize_t fops_read(struct fops *fops, int fd, void *buf, size_t count)
{
    if (!fops->f_read) {
        errno = ENOTSUP;
        return -1;
    }

    return fops->f_read(fd, buf, count, -1);
}



ssize_t fops_write(struct fops *fops, int fd, const void *buf, size_t count)
{
    if (!fops->f_write) {
        errno = ENOTSUP;
        return -1;
    }

    return fops->f_write(fd, buf, count, -1);
}

/////////////
// PTY/TTY
/////////////

#define TTY_DIR "/tvm/pts"
#define PTMX_FILE "/dev/ptmx"
#define TTY_FILE "/dev/tty"

#define TTM_MASTER 1
#define TTM_SLAVE  2
#define TTM_ALL    (TTM_MASTER | TTM_SLAVE)

struct tty {
    struct list_head t_list;
    pthread_mutex_t t_lock;
    unsigned t_refcnt;

    pid_t t_sid;
    pid_t t_pgid;

    uid_t t_uid;
    gid_t t_gid;
    mode_t t_mode;

    struct winsize t_winsize;
    struct termios t_termios;
#define t_iflag  t_termios.c_iflag
#define t_oflag  t_termios.c_oflag
#define t_cflag  t_termios.c_cflag
#define t_lflag  t_termios.c_lflag
#define t_cc     t_termios.c_cc
#define t_ispeed t_termios.c_ispeed
#define t_ospeed t_termios.c_ospeed

    int t_mfd;
    ino_t t_mfd_ino;
    int t_sfd;
    ino_t t_sfd_ino;

    int t_col;
};

LIST_HEAD(ttys);
pthread_mutex_t ttys_lock = PTHREAD_MUTEX_INITIALIZER;

static COW_IMPL(char[PATH_MAX], tty_name);
static COW_IMPL(char[PATH_MAX], pts_name);

static cc_t ttydefchars[NCCS] = {
	CEOF, CEOL, CEOL, CERASE, CWERASE, CKILL, CREPRINT,
	_POSIX_VDISABLE, CINTR, CQUIT, CSUSP, CDSUSP, CSTART, CSTOP, CLNEXT,
	CDISCARD, CMIN, CTIME, CSTATUS, _POSIX_VDISABLE
};

static void tty_lock(struct tty *tt) { pthread_mutex_lock(&tt->t_lock); }
static void tty_unlock(struct tty *tt) { pthread_mutex_unlock(&tt->t_lock); }

static struct tty *ttyalloc()
{
    int ends[2] = {-1, -1};
    
    if (-1 == CALL_FUNC(socketpair, AF_UNIX, SOCK_STREAM, 0, ends))
        return NULL;
    
    struct tty *tt = malloc(sizeof(*tt));
    if (!tt) {
        CALL_FUNC(close, ends[0]);
        CALL_FUNC(close, ends[1]);
        return NULL;
    }

    tt->t_mfd = ends[0];
    tt->t_sfd = ends[1];

    tt->t_sid = -1;
    tt->t_pgid = -1;

    tt->t_mode = S_IRUSR | S_IWUSR | S_IWGRP;
    tt->t_uid = getuid();
    struct group *grp = getgrnam("tty");
    if (grp)
        tt->t_gid = grp->gr_gid;
    else
        tt->t_gid = getgid();

    memcpy(tt->t_termios.c_cc, ttydefchars, sizeof(ttydefchars));
    tt->t_termios.c_iflag = TTYDEF_IFLAG;
    tt->t_termios.c_oflag = TTYDEF_OFLAG;
    tt->t_termios.c_lflag = TTYDEF_LFLAG;
    tt->t_termios.c_cflag = TTYDEF_CFLAG;
    tt->t_termios.c_ispeed = tt->t_termios.c_ospeed = TTYDEF_SPEED;
    
    struct stat st;
    if (-1 == CALL_FUNC(fstat, tt->t_mfd, &st)) {
        goto fail;
    }
    tt->t_mfd_ino = st.st_ino;

    if (-1 == CALL_FUNC(fstat, tt->t_sfd, &st)) {
        goto fail;
    }
    tt->t_sfd_ino = st.st_ino;

    if (pthread_mutex_init(&tt->t_lock, NULL) != 0) {
        goto fail;
    }

    tty_lock(tt);

    pthread_mutex_lock(&ttys_lock);
    list_add_tail(&tt->t_list, &ttys);
    pthread_mutex_unlock(&ttys_lock);

    return tt;

fail:

    CALL_FUNC(close, ends[0]);
    CALL_FUNC(close, ends[1]);
    free(tt);

    return NULL;
}

static void ttydealloc(struct tty *tt)
{
    pthread_mutex_lock(&ttys_lock);
    list_del(&tt->t_list);
    pthread_mutex_unlock(&ttys_lock);

    if (tt->t_mfd != -1)
        CALL_FUNC(close, tt->t_mfd);
    if (tt->t_sfd != -1)
        CALL_FUNC(close, tt->t_sfd);

    pthread_mutex_unlock(&tt->t_lock);
    pthread_mutex_destroy(&tt->t_lock);

    free(tt);
}

/**
 * Locks
 */
static struct tty *tty_for_fd(int fd, int mode)
{
    struct stat st;
    if (-1 == CALL_FUNC(fstat, fd, &st))
        return NULL;

    pthread_mutex_lock(&ttys_lock);
    struct tty *tt;
    list_for_each_entry(tt, &ttys, t_list) {
        if (((mode & TTM_MASTER) && tt->t_mfd_ino == st.st_ino) || 
            ((mode & TTM_SLAVE)  && tt->t_sfd_ino == st.st_ino)) {
            tty_lock(tt);
            pthread_mutex_unlock(&ttys_lock);
            return tt;
        }
    }
    pthread_mutex_unlock(&ttys_lock);

    return NULL;
}

/**
 * Returns 1 if local (tvm) tty, 0 if not.
 */
static int islocaltty(int fd)
{
    task_lock(current);

    // make its in `tsk_fd` first
    if (t_fd(fd) == -1)
        return 0;

    if (0 == (current->tsk_fd[fd] & TFD_TTY)) {
        task_unlock(current);
        return 0;
    }

    struct tty *tt = tty_for_fd(t_fd(fd), TTM_ALL);
    if (!tt) {
        task_unlock(current);
        return 0;
    }

    tty_unlock(tt);
    task_unlock(current);
    return 1;
}

static int ttyop_openchk(const char *pathname) {
    return (0 == strncmp(pathname, TTY_DIR "/", sizeof(TTY_DIR "/") - 1) || 0 == strcmp(pathname, TTY_FILE));
}

/**
 * Returns locked.
 */
static struct tty *tty_for_path(const char *pathname) {
    if (!(ttyop_openchk(pathname)))
        return NULL;
    
    // Open the controlling TTY
    if (0 == strcmp(pathname, TTY_FILE)) {
        task_lock(current);
        if (0 == (current->tsk_state & TS_CTTY)) {
            task_unlock(current);
            return NULL;
        }

        pthread_mutex_lock(&ttys_lock);
        struct tty *tt;
        list_for_each_entry(tt, &ttys, t_list) {
            tty_lock(tt);
            if (tt->t_sid == current->tsk_sid) {
                pthread_mutex_unlock(&ttys_lock);
                task_unlock(current);
                return tt;
            }
            tty_unlock(tt);
        }
        pthread_mutex_unlock(&ttys_lock);

        panic("TS_CTTY but no TTY found");
    }

    // Open some other TTY

    long long n;
    if (0 != intparse(pathname + sizeof(TTY_DIR "/") - 1, &n, 10))
        return NULL;
    
    pthread_mutex_lock(&ttys_lock);
    struct tty *tt;
    list_for_each_entry(tt, &ttys, t_list) {
        tty_lock(tt);
        if (((int) n) == tt->t_mfd) {
            pthread_mutex_unlock(&ttys_lock);
            return tt;
        }
        tty_unlock(tt);
    }
    pthread_mutex_unlock(&ttys_lock);

    return NULL;
}

static int ttyop_open(const char *pathname, int flags, mode_t mode)
{
    struct tty *tt = tty_for_path(pathname);
    if (!tt) {
        errno = ENOTTY;
        return -1;
    }
    
    // tt is locked

    if (0 == (flags & O_NOCTTY)) {
        task_lock(current);

        // gotta have no terminal and be session leader
        if (current->tsk_state & TS_CTTY || current->tsk_pid != current->tsk_sid) {
            task_unlock(current);
            flags |= O_NOCTTY;
        }
        else
        {
            // no stealing!
            if (tt->t_sid != current->tsk_sid && tt->t_sid != -1) {
                task_unlock(current);
                errno = EIO;
                return -1;
            }

            // tt is still locked in this case!
        }
    }

    if (tt->t_sfd == -1)
        panic("%s t_sfd invalid?", pathname);

    int r_sfd = CALL_FUNC(dup, tt->t_sfd);

    if (0 == (flags & O_NOCTTY)) {
        if (-1 != r_sfd) {
            current->tsk_state |= TS_CTTY;
            tt->t_sid = current->tsk_sid;
            tt->t_pgid = current->tsk_pgid;
        }

        task_unlock(current);
    }

    tty_unlock(tt);
    return r_sfd;
}

static int ttyop_dup(int oldfd, int newfd) {
    struct tty *tt = tty_for_fd(oldfd, TTM_MASTER);
    if (!tt)
        return 0;
    
    tt->t_refcnt++;
    tty_unlock(tt);
    return 0;
}

static int ttyop_stat(int fd, struct stat *st)
{
    struct tty *tt = tty_for_fd(fd, TTM_ALL);
    if (!tt) {
        errno = ENOTTY;
        return -1;
    }

    if (!st) {
        tty_unlock(tt);
        return 0;
    }

    memset(st, 0, sizeof(*st));

    st->st_ino = tt->t_mfd_ino;
    st->st_uid = tt->t_uid;
    st->st_gid = tt->t_gid;
    st->st_mode = tt->t_mode;

    tty_unlock(tt);
    return 0;
}

static int ttyop_chmod(int fd, mode_t mode)
{
    struct tty *tt = tty_for_fd(fd, TTM_ALL);
    if (!tt) {
        errno = ENOTTY;
        return -1;
    }

    tt->t_mode = mode;

    tty_unlock(tt);
    return 0;
}

static int ttyop_chown(int fd, uid_t owner, gid_t group)
{
    struct tty *tt = tty_for_fd(fd, TTM_ALL);
    if (!tt) {
        errno = ENOTTY;
        return -1;
    }

    tt->t_uid = owner;
    tt->t_gid = group;

    tty_unlock(tt);
    return 0;
}

static int ttyop_ioctl(int fd, unsigned long request, void *arg)
{
    int is_master = 1;
    struct tty *tt = tty_for_fd(fd, TTM_MASTER);
    if (!tt) {
        tt = tty_for_fd(fd, TTM_SLAVE);
        if (!tt) {
            errno = ENOTTY;
            return -1;
        }
        is_master = 0;
    }
    
    pid_t pgid;
    struct task *t;

    int ret = -1;

    switch (request) {
        case TCGETS:
            memcpy(arg, &tt->t_termios, sizeof(tt->t_termios));
            ret = 0;
            break;
        
        case TCSETS:
        case TCSETSW:
            memcpy(&tt->t_termios, arg, sizeof(tt->t_termios));
            ret = 0;
            break;
        

        case TIOCGWINSZ:
            memcpy(arg, &tt->t_winsize, sizeof(tt->t_winsize));
            ret = 0;
            break;
        
        case TIOCSWINSZ:
            memcpy(&tt->t_winsize, arg, sizeof(tt->t_winsize));
            if (tt->t_sid == -1 || tt->t_pgid == -1) {
                ret = 0;
                break;
            }
            
            pgid = tt->t_pgid;
            tty_unlock(tt);
            kill(-pgid, SIGWINCH);
            tty_lock(tt);
            ret = 0;
            break;
        
        case TIOCSCTTY:
            task_lock(current);
            if ((current->tsk_state & TS_CTTY) ||
                (current->tsk_sid != current->tsk_pid)) {
                task_unlock(current);
                errno = EINVAL;
                break;
            }

            // we don't allow stealing ttys
            if (tt->t_sid != -1 || 0 != (long)arg) {
                task_unlock(current);
                errno = EPERM;
                break;
            }

            current->tsk_state |= TS_CTTY;
            tt->t_sid = current->tsk_sid;
            tt->t_pgid = current->tsk_pgid;
            task_unlock(current);
            ret = 0;
            break;

        case TIOCNOTTY:
            task_lock(current);
            if (current->tsk_sid != current->tsk_pid) {
                current->tsk_state &= ~TS_CTTY;
                task_unlock(current);
                ret = 0;
                break;
            }
            task_unlock(current);

            pthread_mutex_lock(&tasks_lock);
            list_for_each_entry(t, &main_task->tsk_list, tsk_list) {
                task_lock(t);
                if (t->tsk_sid == tt->t_sid)
                    t->tsk_state &= ~TS_CTTY;
                task_unlock(t);
            }
            pthread_mutex_unlock(&tasks_lock);

            pgid = tt->t_pgid;
            tty_unlock(tt);
            kill(-pgid, SIGHUP);
            kill(-pgid, SIGCONT);
            tty_lock(tt);
            ret = 0;
            break;

        case TIOCGPGRP:
            task_lock(current);
            if (!is_master &&
                (0 == (current->tsk_state & TS_CTTY) || tt->t_sid != current->tsk_sid)) {
                task_unlock(current);
                errno = ENOTTY;
                break;
            }
            task_unlock(current);

            *((pid_t *) arg) = tt->t_pgid;
            ret = 0;
            break;
        
        case TIOCSPGRP:
            task_lock(current);
            if (!is_master &&
                (0 == (current->tsk_state & TS_CTTY) || tt->t_sid != current->tsk_sid)) {
                task_unlock(current);
                errno = ENOTTY;
                break;
            }
            task_unlock(current);

            pthread_mutex_lock(&tasks_lock);
            list_for_each_entry(t, &main_task->tsk_list, tsk_list) {
                if (t->tsk_pgid == *((pid_t *)arg)) {
                    break;
                }
            }
            pthread_mutex_unlock(&tasks_lock);

            // group non-existed / empty
            if (t == main_task && main_task->tsk_pgid != *((pid_t *) arg)) {
                errno = -ESRCH;
                break;
            }

            tt->t_pgid = *((pid_t *) arg);
            ret = 0;
            break;

        case TIOCGSID:
            task_lock(current);
            if (!is_master &&
                (0 == (current->tsk_state & TS_CTTY) || tt->t_sid != current->tsk_sid)) {
                task_unlock(current);
                errno = ENOTTY;
                break;
            }
            task_unlock(current);

            *((pid_t *) arg) = tt->t_sid;
            ret = 0;
            break;

        default:
            errno = ENOTSUP;
    }

    tty_unlock(tt);
    return ret;
}

static ssize_t ttyop_read(int fd, void *buf, size_t count, int offset)
{
    if (offset != -1) {
        errno = EINVAL;
        return -1;
    }

    int is_master = 1;
    struct tty *tt = tty_for_fd(fd, TTM_MASTER);
    if (!tt) {
        tt = tty_for_fd(fd, TTM_SLAVE);
        if (!tt) {
            errno = ENOTTY;
            return -1;
        }
        is_master = 0;
    }

    // if (is_master) {
    //     static int f = -1;
    //     if (f == -1) {
    //         unlink("/tmp/tty.read");
    //         f = CALL_FUNC(open, "/tmp/tty.read", O_CREAT | O_WRONLY | O_TRUNC, 0777);
    //     }
    //     CALL_FUNC(write, f, buf, count);
    // }

    tty_unlock(tt);
    return CALL_FUNC(read, fd, buf, count);
}

#define TTY_CHARMASK    0x000000ff      /* Character mask */

#define E       0x00    /* Even parity. */
#define O       0x80    /* Odd parity. */

#define ALPHA   0x40    /* Alpha or underscore. */

#define CCLASSMASK      0x3f
#define CCLASS(c)       (char_type[c] & CCLASSMASK)

#define SET(T, F)       (T) |= (F)
#define CLR(T, F)       (T) &= ~(F)
#define ISSET(T, F)     ((T) & (F))

#define ORDINARY        0
#define CONTROL         1
#define BACKSPACE       2
#define NEWLINE         3
#define TAB             4
#define VTAB            5
#define RETURN          6

#define BS      BACKSPACE
#define CC      CONTROL
#define CR      RETURN
#define NA      ORDINARY | ALPHA
#define NL      NEWLINE
#define NO      ORDINARY
#define TB      TAB
#define VT      VTAB

static u_char const char_type[] = {
	E | CC, O | CC, O | CC, E | CC, O | CC, E | CC, E | CC, O | CC, /* nul - bel */
	O | BS, E | TB, E | NL, O | CC, E | VT, O | CR, O | CC, E | CC, /* bs - si */
	O | CC, E | CC, E | CC, O | CC, E | CC, O | CC, O | CC, E | CC, /* dle - etb */
	E | CC, O | CC, O | CC, E | CC, O | CC, E | CC, E | CC, O | CC, /* can - us */
	O | NO, E | NO, E | NO, O | NO, E | NO, O | NO, O | NO, E | NO, /* sp - ' */
	E | NO, O | NO, O | NO, E | NO, O | NO, E | NO, E | NO, O | NO, /* ( - / */
	E | NA, O | NA, O | NA, E | NA, O | NA, E | NA, E | NA, O | NA, /* 0 - 7 */
	O | NA, E | NA, E | NO, O | NO, E | NO, O | NO, O | NO, E | NO, /* 8 - ? */
	O | NO, E | NA, E | NA, O | NA, E | NA, O | NA, O | NA, E | NA, /* @ - G */
	E | NA, O | NA, O | NA, E | NA, O | NA, E | NA, E | NA, O | NA, /* H - O */
	E | NA, O | NA, O | NA, E | NA, O | NA, E | NA, E | NA, O | NA, /* P - W */
	O | NA, E | NA, E | NA, O | NO, E | NO, O | NO, O | NO, O | NA, /* X - _ */
	E | NO, O | NA, O | NA, E | NA, O | NA, E | NA, E | NA, O | NA, /* ` - g */
	O | NA, E | NA, E | NA, O | NA, E | NA, O | NA, O | NA, E | NA, /* h - o */
	O | NA, E | NA, E | NA, O | NA, E | NA, O | NA, O | NA, E | NA, /* p - w */
	E | NA, O | NA, O | NA, E | NO, O | NO, E | NO, E | NO, O | CC, /* x - del */
	/*
	 * Meta chars; should be settable per character set;
	 * for now, treat them all as normal characters.
	 */
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
	NA, NA, NA, NA, NA, NA, NA, NA,
};
#undef  BS
#undef  CC
#undef  CR
#undef  NA
#undef  NL
#undef  NO
#undef  TB
#undef  VT

static int tty_putc(struct tty *tt, int fd, int c)
{
    // assumes fd is O_NONBLOCK

    ssize_t ret = CALL_FUNC(write, fd, &c, 1);
    if (ret == 1)
        return 0;
    if (ret == 0)
        panic("what?");
    if (errno != EWOULDBLOCK && errno != EAGAIN)
        return -1;
    
    // would block, try with blocking
    if (-1 == CALL_FUNC(fcntl, fd, F_SETFL, 0))
        return -1;
    
    tty_unlock(tt);
    ret = CALL_FUNC(write, fd, &c, 1);
    tty_lock(tt);

    if (-1 == CALL_FUNC(fcntl, fd, F_SETFL, O_NONBLOCK))
        return -1;

    if (ret == 0)
        panic("what?");
    if (ret == 1)
        return 0;
    return -1;
}

static int tty_output(struct tty *tt, int fd, int c)
{
    int col;

    if (!ISSET(tt->t_oflag, OPOST)) {
        if (ISSET(tt->t_lflag, FLUSHO))
            return 0;
        return tty_putc(tt, fd, c);
    }

    // expand tabs or smth

    // if ONLCR is set, translate newline into "\r\n"
    if (c == '\n' && ISSET(tt->t_oflag, ONLCR)) {
		if (tty_putc(tt, fd, '\r'))
			return -1;
	}
    // if OCRNL is set, translate "\r" into "\n"
	else if (c == '\r' && ISSET(tt->t_oflag, OCRNL))
		c = '\n';
    // if ONOCR is set, don't transmit CRs when on column 0
    else if (c == '\r' && ISSET(tt->t_oflag, ONOCR) && tt->t_col == 0)
		return 0;

    if (!ISSET(tt->t_lflag, FLUSHO) && tty_putc(tt, fd, c))
		return -1;
    
    col = tt->t_col;
	switch (CCLASS(c)) {
	case BACKSPACE:
		if (col > 0) {
			--col;
		}
		break;
	case CONTROL:
		break;
	case NEWLINE:
	case RETURN:
		col = 0;
		break;
	case ORDINARY:
		++col;
		break;
	case TAB:
		col = (col + 8) & ~7;
		break;
	}
	tt->t_col = col;
	return 0;
}

static ssize_t tty_output_buffer(struct tty *tt, int fd, const uint8_t *buf, size_t count)
{
    int fflags;
    ssize_t ret = -1;

    if (-1 == (fflags = CALL_FUNC(fcntl, fd, F_GETFL)))
        return -1;

    if (-1 == CALL_FUNC(fcntl, fd, F_SETFL, O_NONBLOCK))
        return -1;

    size_t i;
    for (i = 0; i < count; i++)
        if (0 != tty_output(tt, fd, (int)buf[i]))
            break;
    
    ret = i;

    CALL_FUNC(fcntl, fd, F_SETFL, fflags);

    return ret;
}

static void tty_echo(struct tty *tt, int c)
{
	if ((!ISSET(tt->t_lflag, ECHO) &&
	    (c != '\n' || !ISSET(tt->t_lflag, ECHONL))) ||
	    ISSET(tt->t_lflag, EXTPROC)) {
		return;
	}

    int slave = CALL_FUNC(dup, tt->t_sfd);
    if (-1 == slave)
        return;
    
    if (-1 == CALL_FUNC(fcntl, slave, F_SETFL, O_NONBLOCK)) {
        CALL_FUNC(close, slave);
        return;
    }

	if (ISSET(tt->t_lflag, ECHOCTL) &&
	    ((ISSET(c, TTY_CHARMASK) <= 037 && c != '\t' && c != '\n') ||
	    ISSET(c, TTY_CHARMASK) == 0177)) {
		(void)tty_output(tt, slave, '^');
		CLR(c, ~TTY_CHARMASK);
		if (c == 0177) {
			c = '?';
		} else {
			c += 'A' - 1;
		}
	}

	tty_output(tt, slave, c);
    CALL_FUNC(close, slave);
}

static int tty_input(struct tty *tt, int fd, int c)
{
    if (ISSET(tt->t_iflag, ISTRIP))
		CLR(c, 0x80);
    
    if (!ISSET(tt->t_lflag, EXTPROC)) {
        // Signals
        if (ISSET(tt->t_lflag, ISIG)) {
            if (CCEQ(tt->t_cc[VINTR], c) || CCEQ(tt->t_cc[VQUIT], c) || CCEQ(tt->t_cc[VSUSP], c)) {
                tty_echo(tt, c);
                int pgid = tt->t_pgid;
                int sig = CCEQ(tt->t_cc[VINTR], c) ? SIGINT : (CCEQ(tt->t_cc[VQUIT], c) ? SIGQUIT : SIGTSTP);
                tty_unlock(tt);
                kill(-pgid, sig); // TODO check TS_CTTY
                tty_lock(tt);
                return 0;
            }
        }

        // IGNCR, ICRNL, & INLCR
		if (c == '\r') {
			if (ISSET(tt->t_iflag, IGNCR))
				return 0;
			if (ISSET(tt->t_iflag, ICRNL))
				c = '\n';
		} else if (c == '\n' && ISSET(tt->t_iflag, INLCR))
			c = '\r';
        
    }

    return tty_putc(tt, fd, c);
}

static ssize_t tty_input_buffer(struct tty *tt, int fd, const uint8_t *buf, size_t count)
{
    int fflags;
    ssize_t ret = -1;

    if (-1 == (fflags = CALL_FUNC(fcntl, fd, F_GETFL)))
        return -1;

    if (-1 == CALL_FUNC(fcntl, fd, F_SETFL, O_NONBLOCK))
        return -1;

    size_t i;
    for (i = 0; i < count; i++)
        if (0 != tty_input(tt, fd, (int)buf[i]))
            break;
    
    ret = i;

    CALL_FUNC(fcntl, fd, F_SETFL, fflags);

    return ret;
}

static ssize_t ttyop_write(int fd, const void *buf, size_t count, int offset)
{
    if (offset != -1) {
        errno = EINVAL;
        return -1;
    }

    int is_master = 1;
    struct tty *tt = tty_for_fd(fd, TTM_MASTER);
    if (!tt) {
        tt = tty_for_fd(fd, TTM_SLAVE);
        if (!tt) {
            errno = ENOTTY;
            return -1;
        }
        is_master = 0;
    }

    // if (is_master) {
    //     static int f = -1;
    //     if (f == -1) {
    //         unlink("/tmp/tty.write");
    //         f = CALL_FUNC(open, "/tmp/tty.write", O_CREAT | O_WRONLY | O_TRUNC, 0777);
    //         if (f == -1)
    //             CALL_FUNC(printf, "ERR %d\n", errno);
    //     }
    //     CALL_FUNC(write, f, buf, count);
    // }

    ssize_t ret;
    if (is_master)
        ret = tty_input_buffer(tt, fd, buf, count);
    else
        ret = tty_output_buffer(tt, fd, buf, count);
    tty_unlock(tt);
    return ret;
}


static int ttyop_close(int fd) {
    struct tty *tt = tty_for_fd(fd, TTM_MASTER);
    if (!tt)
        return 0;

    tt->t_refcnt--;
    if (tt->t_refcnt) {
        tty_unlock(tt);
        return 0;
    }

    // Disassociate the entire session
    struct task *signaltask = NULL;
    if (tt->t_sid != -1) {
        pthread_mutex_lock(&tasks_lock);
        struct task *t;
        list_for_each_entry(t, &main_task->tsk_list, tsk_list) {
            task_lock(t);
            if (t->tsk_sid == tt->t_sid)
                t->tsk_state &= ~TS_CTTY;
            if (t->tsk_pid == tt->t_sid)
                signaltask = t;
            else
                task_unlock(t);
        }
        pthread_mutex_unlock(&tasks_lock);
    }

    ttydealloc(tt);

    if (signaltask) {
        pid_t p = signaltask->tsk_pid;
        task_unlock(signaltask);
        kill(p, SIGHUP);
        kill(p, SIGCONT);
    }

    return 0;
}

static struct fops ttyops = {
    .f_fdflag = TFD_TTY,

    .f_openchk = ttyop_openchk,
    .f_open = ttyop_open,
    .f_dup = ttyop_dup,
    .f_stat = ttyop_stat,
    .f_chmod = ttyop_chmod,
    .f_chown = ttyop_chown,
    .f_ioctl = ttyop_ioctl,
    .f_read = ttyop_read,
    .f_write = ttyop_write,
    .f_close = ttyop_close,
};
REGISTER_DEV(ttyops);

static int ptm_open()
{
    struct tty *tt = ttyalloc();
    if (!tt) {
        errno = ENOMEM;
        return -1;
    }

    // tt is locked

    int mfd = CALL_FUNC(dup, tt->t_mfd);
    if (-1 == mfd) {
        ttydealloc(tt);
        return -1;
    }

    tt->t_refcnt++;
    tty_unlock(tt);
    return mfd;
}

static int tty_slavename(int fd, char *buf, size_t buflen)
{
    struct tty *tt = tty_for_fd(fd, TTM_ALL);
    if (!tt)
        return ENOTTY;

    if (tt->t_mfd == -1) {
        tty_unlock(tt);
        return EINVAL;
    }

    snprintf(buf, buflen, TTY_DIR "/%d", tt->t_mfd);
    tty_unlock(tt);
    return 0;
}

/////////////
// Copy-On-Write (COW)
/////////////

#define COW_DEEPCOPY 0x1

struct cow_variable_t {
    struct list_head list;
    void *(*getptr_fn)();
    void (*init_fn)();
    char *name; // for debugging purposes
    size_t size;
    int flags;
};
static LIST_HEAD(cow_variables);

void _tvm_register_cow(void *(*getptr_fn)(), unsigned size, void (*init_fn)(), int deepcopy, char *name)
{
    struct cow_variable_t *cowvar;
    if (NULL == (cowvar = malloc(sizeof(*cowvar))))
        panic("cowvar");
    
    list_add_tail(&cowvar->list, &cow_variables);
    cowvar->getptr_fn = getptr_fn;
    cowvar->init_fn = init_fn;
    cowvar->name = name;
    cowvar->size = size;
    if (deepcopy) 
        cowvar->flags |= COW_DEEPCOPY;
}

static int cow_get_thread_ptrs(void ***out_data)
{
    size_t cows = 0;
    struct cow_variable_t *cow;

    list_for_each_entry(cow, &cow_variables, list)
        cows++;
    
    void **data = malloc((cows+1)*sizeof(void *));
    if (!data)
        return 1;
    memset(data, 0, (cows+1)*sizeof(void *));
    
    int i = 0;
    list_for_each_entry(cow, &cow_variables, list) {
        if (i >= (cows)) {
            free(data);
            return 2;
        }
        data[i] = cow->getptr_fn();
        if (data[i++] == NULL) {
            free(data);
            return 3;
        }
    }

    if (i != (cows)) {
        free(data);
        return 4;
    }

    *out_data = data;
    return 0;
}

// TODO words cannot explain how retarded this is
static pthread_mutex_t ptrchk_lock = PTHREAD_MUTEX_INITIALIZER;
static jmp_buf ptrchk_retbuf;
static void ptrchk_handler(int) { siglongjmp(ptrchk_retbuf, 2); }
static int is_valid_ptr(void *ptr)
{
    int jmpval;
    struct sigaction segvoldact, busoldact, act = { .sa_handler = ptrchk_handler };

    pthread_mutex_lock(&ptrchk_lock);
    int oldsigshutup = sigshutup;
    sigshutup = 1;

    if (0 != sigaction(SIGSEGV, &act, &segvoldact))
        panic("sigaction(SIGSEGV, act)");
    if (0 != sigaction(SIGBUS, &act, &busoldact))
        panic("sigaction(SIGBUS, act)");

    // need sigsetjmp because we're longjmp'ing from signal handler
    if (0 != (jmpval = sigsetjmp(ptrchk_retbuf, 1)))
    {
        if (0 != sigaction(SIGSEGV, &segvoldact, NULL))
            panic("sigaction(SIGSEGV, oldact)");
        if (0 != sigaction(SIGBUS, &busoldact, NULL))
            panic("sigaction(SIGBUS, oldact)");
        
        sigshutup = oldsigshutup;
        pthread_mutex_unlock(&ptrchk_lock);

        return (jmpval == 1);
    }

    int a = *((int *)ptr);
    siglongjmp(ptrchk_retbuf, 1);
}

struct cow_deepcopy_ctx {
    struct {
        void *new;
        void *old;
        size_t size;
    } *ptrs;
    size_t count;
};

static void *cow_deepcopy_ctx_find(struct cow_deepcopy_ctx *dctx, void *needle)
{
    for (int i = 0; i < dctx->count; i++) {
        uintptr_t off = ((uintptr_t) needle) - ((uintptr_t) dctx->ptrs[i].new);
        if (off < dctx->ptrs[i].size)
            return (void *) ((dctx->ptrs[i].new) + off);
        
        off = ((uintptr_t) needle) - ((uintptr_t) dctx->ptrs[i].old);
        if (off < dctx->ptrs[i].size)
            return (void *) ((dctx->ptrs[i].new) + off);
    }

    return NULL;
}

static void cow_deepcopy_ctx_add(struct cow_deepcopy_ctx *dctx, void *new, void *old, size_t size)
{
    dctx->ptrs = realloc(dctx->ptrs, sizeof(dctx->ptrs[0]) * (dctx->count + 1));
    if (!dctx->ptrs)
        panic("realloc ptrs count %zu", dctx->count);
    
    dctx->ptrs[dctx->count].new = new;
    dctx->ptrs[dctx->count].old = old;
    dctx->ptrs[dctx->count].size = size;
    dctx->count++;
}

static int heap_offset(uintptr_t *p)
{
    int check = 1;
    // must make sure `p` is pointer-aligned (since the MALLOC_MAGIC is pointer-sized) or we might miss it
    for (uintptr_t *pp = (uintptr_t *)(((uintptr_t) p) & ~(7UL)); pp >= (p - (0x1000 / sizeof(uintptr_t))); pp--)
    {
        // only perform valid ptrs on first pointer or when crossing to a new page
        // since checking VERY pointer is waste of time
        if ((check || ((((uintptr_t) pp) & 0xfff) == 0xff8)) && !is_valid_ptr(pp))
            break;
        check = 0;

        if (((*pp) & 0xffffffff) == MALLOC_MAGIC) {
            // some of our functions that use `MALLOC_MAGIC` may have that magic near its instructions (generated by the compiler)
            // for now we just hard-coded ignore places near those functions but should probably find a better solution
            if ((((uintptr_t) pp) - ((uintptr_t) &calloc)) < 0x1000)
                return -1;
            if ((((uintptr_t) pp) - ((uintptr_t) &free)) < 0x1000)
                return -1;
            if ((((uintptr_t) pp) - ((uintptr_t) &heap_offset)) < 0x1000)
                return -1;
            
            return (((uintptr_t) p) - ((uintptr_t) pp));
        }
    }

    return -1;
}

static void cow_deepcopy(void *buffer, size_t size, struct cow_deepcopy_ctx *dctx)
{
    uintptr_t **end = (uintptr_t **) (((char *) buffer) + size);

    for (uintptr_t **p = (uintptr_t **)buffer; (p+1) <= end; p++) {
        // fight circular dependency!
        uintptr_t *cached = (uintptr_t *) cow_deepcopy_ctx_find(dctx, (void *)*p);
        if (cached) {
            *p = cached;
            continue;
        }

        int heapoff = heap_offset(*p);
        if (-1 == heapoff)
            continue;

        uint64_t *p_heapbase = (uint64_t *) (((uintptr_t) (*p)) - heapoff);
        size_t heap_size = (size_t) ((*p_heapbase) >> 32); // we stash the size near the MALLOC_MAGIC
        if (!heap_size)
            continue;

        uintptr_t *newptr = CALL_FUNC(malloc, heap_size);
        if (!newptr)
            panic("newptr = malloc(0x%zx)", heap_size);
        memset(newptr, 0, heap_size);
        
        cow_deepcopy_ctx_add(dctx, (void *) newptr, p_heapbase, heap_size);
        memcpy(newptr, p_heapbase, heap_size);
        *p = (uintptr_t *) (((uintptr_t) newptr) + heapoff);
        cow_deepcopy(newptr+1, heap_size-sizeof(uintptr_t), dctx);
    }
}

static int cow_set_thread_ptrs(void **data, struct cow_deepcopy_ctx *dctx)
{
    struct cow_variable_t *cow;

    void **d = data;
    list_for_each_entry(cow, &cow_variables, list) {
        if (*d == NULL)
            return 1;

        void *ptr = cow->getptr_fn();
        memcpy(ptr, *d, cow->size);
        cow_deepcopy_ctx_add(dctx, ptr, *d, cow->size);
        
        d++;
    }

    // deep copy on a second pass after the dctx is built
    d = data;
    list_for_each_entry(cow, &cow_variables, list) {
        if (cow->flags & COW_DEEPCOPY)
            cow_deepcopy(cow->getptr_fn(), cow->size, dctx);
        d++;
    }

    if (*d != NULL)
        return 2;

    return 0;
}

static void cow_run_init_funcs()
{
    struct cow_variable_t *cow;
    list_for_each_entry(cow, &cow_variables, list) {
        if (cow->init_fn)
            cow->init_fn();
        else
            memset(cow->getptr_fn(), 0, cow->size);
    }
}

/////////////
// Getopt
/////////////

__thread char *tvm_optarg;
__thread int   tvm_optind = 1;
__thread int   tvm_opterr;
__thread int   tvm_optopt;
static pthread_mutex_t getopt_lock = PTHREAD_MUTEX_INITIALIZER;

/////////////
// Exec
/////////////

typedef int (*main_func_t)(int, char * const*, char * const*);
struct exec_program {
    struct list_head list;
    const char *file;
    const char *pathname;
    main_func_t main_routine;
};
static LIST_HEAD(exec_programs);
static pthread_mutex_t programs_lock = PTHREAD_MUTEX_INITIALIZER;

void tvm_register_program(const char *pathname, main_func_t main_routine)
{
    if (!pathname || !pathname[0])
        panic("pathname");
    
    struct exec_program *prog;
    if (NULL == (prog = malloc(sizeof(*prog))))
        panic("prog");
    
    prog->pathname = pathname;
    prog->main_routine = main_routine;
    prog->file = strchr(pathname, '/');
    if (prog->file)
        prog->file++;
    else
        prog->file = prog->pathname;
    
    if (!prog->file[0])
        panic("program file \"%s\"", prog->pathname);
    
    pthread_mutex_lock(&programs_lock);
    list_add_tail(&prog->list, &exec_programs);
    pthread_mutex_unlock(&programs_lock);
}

static main_func_t find_program(const char *pathname)
{
    pthread_mutex_lock(&programs_lock);
    struct exec_program *prog;
    list_for_each_entry(prog, &exec_programs, list) {
        if (0 == strcmp(pathname, prog->pathname)) {
            main_func_t f = prog->main_routine;
            pthread_mutex_unlock(&programs_lock);
            return f;
        }
    }
    pthread_mutex_unlock(&programs_lock);

    return NULL;
}

static const char *find_program_pathname(const char *file)
{
    pthread_mutex_lock(&programs_lock);
    struct exec_program *prog;
    list_for_each_entry(prog, &exec_programs, list) {
        if (0 == strcmp(file, prog->file)) {
            const char *p = prog->pathname;
            pthread_mutex_unlock(&programs_lock);
            return p;
        }
    }
    pthread_mutex_unlock(&programs_lock);

    return NULL;
}

/////////////
// tvm_pthread_* API
/////////////

#define TVM_PTHREAD_FORK 1

struct thread_create_arg
{
    int flags;
    struct cow_deepcopy_ctx *cow_context;
};

struct thread_arg
{
    struct thread_create_arg create_arg;
    struct task *task;
    struct pthread_entry *pentry;
    void *(*start_routine) (void *);
    void *arg;
    int wake; // condvar for child<->parent
    void **cow_data;
};

static void *thread_entry(struct thread_arg *arg)
{
    current = arg->task;

    task_lock(current);

    if (current->tsk_pid == -1)
        current->tsk_pid = __gettid();

    ++current->tsk_pthreads_count;
    arg->pentry->ptl_value = pthread_self();
    list_add_tail(&arg->pentry->ptl_entry, &current->tsk_pthreads);

    task_unlock(current);

    struct cow_deepcopy_ctx dctx = {0};

    if (0 != cow_set_thread_ptrs(arg->cow_data, &dctx))
        panic("cow_set_thread_ptrs");
    
    // `fork()` needs dctx, so it will use it and free it in the `start_routine`
    if (arg->create_arg.cow_context)
        memcpy(arg->create_arg.cow_context, &dctx, sizeof(dctx));
    else
        free(dctx.ptrs);

    void *(*start_routine)(void *) = arg->start_routine;
    void *routine_arg = arg->arg;
    
    arg->wake = 1;

    void *retval = start_routine(routine_arg);
    pthread_exit(retval);
}

int tvm_pthread_create_ex(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg, struct thread_create_arg *create_arg)
{
    int ret = ENOMEM;

    struct thread_arg *targ = malloc(sizeof(struct thread_arg));
    if (!targ)
        goto out;

    targ->pentry = malloc(sizeof(struct pthread_entry));
    if (!targ->pentry)
        goto out;

    memcpy(&targ->create_arg, create_arg, sizeof(*create_arg));
    if (create_arg->flags & TVM_PTHREAD_FORK)
    {
        targ->task = taskalloc();
        if (!targ->task)
            goto out;
        
        if (0 != cow_get_thread_ptrs(&targ->cow_data)) {
            goto out;
        }
    }
    else
    {
        task_lock(current);
        ++current->tsk_refcount;
        targ->task = current;
        task_unlock(current);
        
        targ->cow_data = NULL;
    }

    targ->start_routine = start_routine;
    targ->arg = arg;
    targ->wake = 0;

    ret = CALL_FUNC(pthread_create, thread, attr, (void *(*)(void *))thread_entry, (void *)targ);

    if (0 == ret) {
        while (0 == targ->wake) { }
    }

    if (targ->cow_data)
        free(targ->cow_data);
    free(targ);

out:
    if (0 != ret)
    {
        if (targ)
        {
            if (create_arg->flags & TVM_PTHREAD_FORK)
            {
                if (targ->task)
                    taskfreelastref(targ->task, 1);
            }
            else
            {
                if (targ->task) {
                    task_lock(current);
                    --current->tsk_refcount;
                    task_unlock(current);
                }
            }

            if (targ->pentry)
                free(targ->pentry);
            free(targ);
        }
    }

    return ret;
}

int tvm_pthread_fork(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg)
{
    struct thread_create_arg create_arg = { .flags = TVM_PTHREAD_FORK };
    return tvm_pthread_create_ex(thread, attr, start_routine, arg, &create_arg);
}

int tvm_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg)
{
    struct thread_create_arg create_arg = { .flags = 0 };
    return tvm_pthread_create_ex(thread, attr, start_routine, arg, &create_arg);
}

__attribute__ ((noreturn))
void tvm_pthread_exit(void *retval)
{
    if (pthread_self() == main_pthread)
        CALL_FUNC(_exit, (int) ((long) retval));
    
    // TODO task_release(current, 1);
    
    CALL_FUNC(pthread_exit, retval);
    __builtin_unreachable();
}

/////////////
// Forkless API
/////////////

#define FORKLESS_STACK_MAGIC ((uintptr_t)0xCAFEFACF)

struct forkless_arg {
    jmp_buf jmpbuf;
    void **fork_fp;
    void **caller_fp;
    struct cow_deepcopy_ctx dctx;
};

#define FRAME_SIZE 0x1000

static void *forkless_entry(struct forkless_arg *arg)
{
    void *curr_fp = (void **)__builtin_frame_address(0);
    char fake_frame[FRAME_SIZE] = {0};

    uintptr_t jmpbuf_sp = (uintptr_t)jmpbuf_getstack(&arg->jmpbuf);
    uintptr_t caller_frame = (uintptr_t)arg->caller_fp;
    void **new_caller_frame = (void **) (fake_frame + caller_frame - jmpbuf_sp);
    void **new_fork_frame = (void **) (((char *) arg->fork_fp) + ((uintptr_t) fake_frame) - jmpbuf_sp);

    memcpy(fake_frame, (void *)jmpbuf_sp, caller_frame + sizeof(void *) - jmpbuf_sp);
    *new_caller_frame = curr_fp;

    cow_deepcopy((void *) new_fork_frame, ((uintptr_t) new_caller_frame) - ((uintptr_t) new_fork_frame), &arg->dctx);
    free(arg->dctx.ptrs);

    jmpbuf_setstack(
        &arg->jmpbuf,
        (uintptr_t) fake_frame,
        (uintptr_t) jmpbuf_sp,
        caller_frame + sizeof(void *) - jmpbuf_sp
    );
    jmpbuf_mangle(&arg->jmpbuf);

    longjmp(arg->jmpbuf, 1);
}

pid_t fork(void)
{
    if (!main_task)
        return CALL_FUNC(fork);
    
    pid_t pid = -1;
    void **curr_fp = (void **)__builtin_frame_address(0);
    struct forkless_arg arg = {
        .fork_fp = curr_fp,
        .caller_fp = (void **)(*curr_fp)
    };
    pid_t *pidaddr = (pid_t *) (((uintptr_t) &pid) ^ FORKLESS_STACK_MAGIC);
    
    // NOTE: Why do we xor `pidaddr`?
    //       `jmpbuf_setstack` fixes up every pointer in the old stack to the new stack.
    //       This would also make `pidaddr` point to the new stack. But we don't want that,
    //       because we're notifying the parent the child has finished setting up.

    if (0 != setjmp(arg.jmpbuf)) {
        pidaddr = (pid_t *) (((uintptr_t) pidaddr) ^ FORKLESS_STACK_MAGIC);
        *pidaddr = __gettid();
        return 0;
    }
    jmpbuf_demangle(&arg.jmpbuf);

    pthread_t thr;
    struct thread_create_arg create_arg = {
        .flags = TVM_PTHREAD_FORK,
        .cow_context = &arg.dctx,
    };
    tvm_pthread_create_ex(&thr, NULL, (void *(*)(void *)) forkless_entry, (void *)&arg, &create_arg);
    
    while (pid == -1) {}
    return pid;
}

/////////////
// API functions
/////////////

void tvm_init()
{
    main_pthread = pthread_self();
    current = taskalloc();  // special initialization for main thread

    cow_run_init_funcs(); // initialize copy-on-write vars with init statements

    task_lock(current);
    
    struct sigaction act = {
        .sa_sigaction = signal_handler,
        .sa_flags = SA_SIGINFO,
    };

    for (int i = 0; i < MAX_SIGNALS; i++) {
        if (0 == CALL_FUNC(sigaction, i, NULL, current->tsk_sighandlers + i)) {
            if (i == SIGKILL || i == SIGSTOP)
                continue;
            if (0 != CALL_FUNC(sigaction, i, &act, NULL))
                panic("sigaction(%d): %s", i, strerror(errno));
        }
    }

    task_unlock(current);
}

char ***_tvm_environ()
{
    if (!main_task)
        return &environ;
    
    return &current->tsk_environ;
}

#define MAX_BT 16

static void __panic(const char *msg, const char *file, int line)
{
    CALL_FUNC(fprintf, stderr, "\n");
    CALL_FUNC(fprintf, stderr, "panic(caller pid %d tid %d): \"%s\"\n", (current?current->tsk_pid:-1), __gettid(), msg);
    CALL_FUNC(fprintf, stderr, "%s:%d\n\n", file, line);
    
    CALL_FUNC(fprintf, stderr, "Thread Info:\n");
    CALL_FUNC(fprintf, stderr, " ppid: %d\n", (current?(current->tsk_parent?current->tsk_parent->tsk_pid:1):-1));
    CALL_FUNC(fprintf, stderr, " host pid: %d\n", CALL_FUNC(getpid));
    CALL_FUNC(fprintf, stderr, " current: %p\n", current);
    CALL_FUNC(fprintf, stderr, " main_task: %p\n", main_task);
    CALL_FUNC(fprintf, stderr, " errno: %d (%s)\n", errno, strerror(errno));
    CALL_FUNC(fprintf, stderr, "\n");

    CALL_FUNC(exit, 255);
}

/////////////
// Hooks
/////////////

FILE *fdopen(int fd, const char *mode)
{ return CALL_FUNC(fdopen, t_fd(fd), mode); }

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    struct fops *fops;
    if (!main_task || !(fops = fops_for_stream(current, stream)))
        return CALL_FUNC(fwrite, ptr, size, nmemb, t_f(stream));
    
    if (!size)
        return 0;
    
    ssize_t r = fops_write(fops, fileno(stream), ptr, size * nmemb);
    if (r < 0)
        r = 0;
    
    return r / size;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    struct fops *fops;
    if (!main_task || !(fops = fops_for_stream(current, stream)))
        return CALL_FUNC(fread, ptr, size, nmemb, t_f(stream));
    
    if (!size)
        return 0;
    
    ssize_t r = fops_read(fops, fileno(stream), ptr, size * nmemb);
    if (r < 0)
        r = 0;
    
    return r / size;
}

int fseek(FILE *stream, long offset, int whence)
{ return CALL_FUNC(fseek, t_f(stream), offset, whence); }

long ftell(FILE *stream)
{ return CALL_FUNC(ftell, t_f(stream)); }

int fflush(FILE *stream)
{ return CALL_FUNC(fflush, t_f(stream)); }

void setbuf(FILE *stream, char *buf)
{ return CALL_FUNC(setbuf, t_f(stream), buf); }

void setbuffer(FILE *stream, char *buf, size_t size)
{ return CALL_FUNC(setbuffer, t_f(stream), buf, size); }

void setlinebuf(FILE *stream)
{ return CALL_FUNC(setlinebuf, t_f(stream)); }

int setvbuf(FILE *stream, char *buf, int mode, size_t size)
{ return CALL_FUNC(setvbuf, t_f(stream), buf, mode, size); }

int fputc(int c, FILE *stream)
{
    struct fops *fops;
    if (!main_task || !(fops = fops_for_stream(current, stream)))
        return CALL_FUNC(fputc, c, t_f(stream));
    
    if (1 == fops_write(fops, fileno(stream), &c, 1))
        return c;
    return EOF;
}

int fputs(const char *s, FILE *stream)
{
    struct fops *fops;
    if (!main_task || !(fops = fops_for_stream(current, stream)))
        return CALL_FUNC(fputs, s, t_f(stream));
    
    ssize_t r = fops_write(fops, fileno(stream), s, strlen(s));
    if (r >= 0)
        return r;
    return EOF;
}

int putc(int c, FILE *stream)
{ return fputc(c, stream); }

int putchar(int c)
{ return fputc(c, stdout); }

int puts(const char *s)
{
    if (EOF == fputs(s, stdout))
        return EOF;
    return fputc('\n', stdout);
}

int fgetc(FILE *stream)
{
    struct fops *fops;
    if (!main_task || !(fops = fops_for_stream(current, stream)))
        return CALL_FUNC(fgetc, t_f(stream));
    
    char c;
    if (1 == fops_read(fops, fileno(stream), &c, 1))
        return (int)c;
    return EOF;
}

char *fgets(char *s, int size, FILE *stream)
{
    struct fops *fops;
    if (!main_task || !(fops = fops_for_stream(current, stream)))
        return  CALL_FUNC(fgets, s, size, t_f(stream));
    
    if (size <= 0)
        return NULL;
    if (size == 1) {
        s[0] = 0;
        return s;
    }
    
    int err = 0;
    int i;
    char c = 0;
    for (i = 0; i < (size - 1) && c != '\n'; i++)
    {
        ssize_t r = fops_read(fops, fileno(stream), &c, 1);
        if (r == -1)
            err = 1;
        if (1 != r)
            break;
        
        s[i] = c;
    }
    

    if (i == 0 && err)
        return NULL;
    
    s[i] = 0;
    return s;
}

int getc(FILE *stream)
{ return fgetc(stream); }

int getchar(void)
{ return fgetc(stdin); }

int ungetc(int c, FILE *stream)
{ return CALL_FUNC(ungetc, c, t_f(stream)); }

void clearerr(FILE *stream)
{ return CALL_FUNC(clearerr, t_f(stream)); }

int feof(FILE *stream)
{ return CALL_FUNC(feof, t_f(stream)); }

int ferror(FILE *stream)
{ return CALL_FUNC(ferror, t_f(stream)); }

int fileno(FILE *stream)
{ return CALL_FUNC(fileno, t_f(stream)); }



int printf(const char *format, ...)
{
    va_list arg;
    int done;
    va_start (arg, format);
    done = vfprintf(stdout, format, arg);
    va_end (arg);
    return done;
}

int fprintf(FILE *stream, const char *format, ...)
{
    va_list arg;
    int done;
    va_start (arg, format);
    done = vfprintf(stream, format, arg);
    va_end (arg);
    return done;
}

int dprintf(int fd, const char *format, ...)
{
    va_list arg;
    int done;
    va_start (arg, format);
    done = vdprintf(fd, format, arg);
    va_end (arg);
    return done;
}

int vprintf(const char *format, va_list ap)
{ return vfprintf(stdout, format, ap); }

int vfprintf(FILE *stream, const char *format, va_list ap)
{
    struct fops *fops;
    int fd = t_fdr(fileno(stream), 1);
    if (!main_task || !(fops = fops_for_fd(current, fd)))
        return CALL_FUNC(vfprintf, t_f(stream), format, ap);
    
    return vdprintf(fd, format, ap);
}

int vdprintf(int fd, const char *format, va_list ap)
{
    struct fops *fops;
    if (!main_task || !(fops = fops_for_fd(current, fd)))
        return CALL_FUNC(vdprintf, t_fd(fd), format, ap);
    
    va_list ap2;
    va_copy(ap2, ap);
    int size = vsnprintf(NULL, 0, format, ap2);
    va_end(ap2);

    if (size < 0)
        return size;
    
    char *s = malloc(size+1);
    if (!s)
        return -1;
    
    int wsize = vsnprintf(s, size+1, format, ap);
    wsize = (int)fops_write(fops, t_fd(fd), s, wsize);
    free(s);
    return wsize;
}

int scanf(const char *format, ...)
{
    va_list arg;
    int done;
    va_start (arg, format);
    done = CALL_FUNC(vfscanf, t_f(stdin), format, arg);
    va_end (arg);
    return done;
}

int fscanf(FILE *stream, const char *format, ...)
{
    va_list arg;
    int done;
    va_start (arg, format);
    done = CALL_FUNC(vfscanf, t_f(stream), format, arg);
    va_end (arg);
    return done;
}

int vscanf(const char *format, va_list ap)
{ return CALL_FUNC(vfscanf, t_f(stdin), format, ap); }

int vfscanf(FILE *stream, const char *format, va_list ap)
{ return CALL_FUNC(vfscanf, t_f(stream), format, ap); }

void perror(const char *s)
{
    if (!main_task)
        return CALL_FUNC(perror, s);
    
    fprintf(stderr, "%s: %s\n", s, strerror(errno));
}

int open(const char *pathname, int flags, ...)
{
    int f = task_reserve_fd(current, 0);
    if (f == -1) {
        errno = EMFILE;
        return -1;
    }

    struct fops *fops = fops_for_open(pathname);

    int r;
    if (__OPEN_NEEDS_MODE(flags)) {
        va_list ap;
        va_start(ap, flags);
        mode_t m = va_arg(ap, mode_t);
        va_end(ap);
        
        if (fops && fops->f_open)
            r = fops->f_open(pathname, flags, m) | fops->f_fdflag;
        else
            r = CALL_FUNC(open, pathname, flags, m);
    }
    else {
        if (fops && fops->f_open)
            r = fops->f_open(pathname, flags, 0) | fops->f_fdflag;
        else
            r = CALL_FUNC(open, pathname, flags);
    }
    
    if (r == -1) {
        task_set_fd(current, f, -1);
        return r;
    }

    task_set_fd(current, f, r);
    return f;
}

int creat(const char *pathname, mode_t mode)
{
    int r = CALL_FUNC(creat, pathname, mode);
    if (r == -1) {
        return r;
    }

    int f = task_new_fd(current, 0, r);
    if (f == -1) {
        CALL_FUNC(close, r);
        errno = ENOMEM;
    }
    return f;
}

int openat(int dirfd, const char *pathname, int flags, ...)
{
    int r;
    if (__OPEN_NEEDS_MODE(flags)) {
        va_list ap;
        va_start(ap, flags);
        mode_t m = va_arg(ap, mode_t);
        va_end(ap);
        r = CALL_FUNC(openat, dirfd, pathname, flags, m);
    }
    else
        r = CALL_FUNC(openat, dirfd, pathname, flags);
    
    if (r == -1) {
        return r;
    }

    int f = task_new_fd(current, 0, r);
    if (f == -1) {
        CALL_FUNC(close, r);
        errno = ENOMEM;
    }
    return f;
}

ssize_t read(int fd, void *buf, size_t count)
{
    struct fops *fops;
    if (!main_task || !(fops = fops_for_fd(current, fd)))
        return CALL_FUNC(read, t_fd(fd), buf, count);
    
    return fops_read(fops, t_fd(fd), buf, count);
}

ssize_t write(int fd, const void *buf, size_t count)
{
    struct fops *fops;
    if (!main_task || !(fops = fops_for_fd(current, fd)))
        return CALL_FUNC(write, t_fd(fd), buf, count);
    
    return fops_write(fops, t_fd(fd), buf, count);
}

int close(int fd)
{
    if (!main_task)
        return CALL_FUNC(close, fd);
    
    task_lock(current);
    struct fops *f = fops_for_fd_locked(current, fd);
    int rfd = t_fd(fd);
    current->tsk_fd[fd] = -1;
    task_unlock(current);

    // we had to "detach" the fd from `current` so we can call fops->close with task unlocked

    int r = 0;
    if (f && f->f_close)
        r = f->f_close(rfd);
    
    if (!r)
        r = CALL_FUNC(close, rfd);
    else
        CALL_FUNC(close, rfd);
    
    return r;
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt)
{
    struct fops *fops;
    if (!main_task || !(fops = fops_for_fd(current, fd)))
        return CALL_FUNC(readv, t_fd(fd), iov, iovcnt);
    
    // TODO: scatter-gather needs to be "atomic", maybe IO-lock per fops or per device instance?
    ssize_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        ssize_t curr = fops_read(fops, t_fd(fd), iov[i].iov_base, iov[i].iov_len);
        if (curr == 0)
            break;
        if (curr < 0) {
            if (total == 0)
                return -1;
            break;
        }

        total += curr;

        if (curr < iov[i].iov_len)
            break;
    }

    return total;
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
    struct fops *fops;
    if (!main_task || !(fops = fops_for_fd(current, fd)))
        return CALL_FUNC(writev, t_fd(fd), iov, iovcnt);
    
    // TODO: see readv()
    ssize_t total = 0;
    for (int i = 0; i < iovcnt; i++) {
        ssize_t curr = fops_write(fops, t_fd(fd), iov[i].iov_base, iov[i].iov_len);
        if (curr == 0)
            break;
        if (curr < 0) {
            if (total == 0)
                return -1;
            break;
        }

        total += curr;

        if (curr < iov[i].iov_len)
            break;
    }

    return total;
}

off_t lseek(int fd, off_t offset, int whence)
{ return CALL_FUNC(lseek, t_fd(fd), offset, whence); }

int fsync(int fd)
{ return CALL_FUNC(fsync, t_fd(fd)); }

int dup(int oldfd)
{
    if (!main_task)
        return CALL_FUNC(dup, oldfd);
    
    return fcntl(oldfd, F_DUPFD, 0);
}

int dup2(int oldfd, int newfd)
{
    if (!main_task)
        return CALL_FUNC(dup2, oldfd, newfd);
    
    task_lock(current);
    int oldfd_real = t_fd(oldfd);
    int newfd_realprev = t_fd(newfd);
    int newfd_realprevflags = current->tsk_fd[newfd];
    int newfd_realnext = -1;

    if (oldfd_real < 0 || newfd < 0 || newfd >= MAX_FILES) {
        task_unlock(current);
        errno = EBADF;
        return -1;
    }

    // fd is currently reserved
    if (current->tsk_fd[newfd] < -1) {
        task_unlock(current);
        errno = EFAULT;
        return -1;
    }

    if (oldfd == newfd) {
        task_unlock(current);
        return newfd;
    }

    newfd_realnext = CALL_FUNC(dup, oldfd_real);
    if (newfd_realnext == -1) {
        task_unlock(current);
        return -1;
    }

    int newfd_realnextflags = newfd_realnext;

    struct fops *ofops = fops_for_fd_locked(current, oldfd);
    newfd_realnextflags |= fops_fdflag(ofops);
    current->tsk_fd[newfd] = newfd_realnextflags;
    struct fops *nfops = fops_for_fd_locked(current, newfd);
    task_unlock(current);

    // TODO from here on theres an inherent race with other threads in the same process
    //      if `fops_dup` fails. maybe we need to proc_fdlock() or smth

    if ((0 != fops_dup(ofops, oldfd_real, newfd_realnext))) {
        task_lock(current);
        current->tsk_fd[newfd] = newfd_realprevflags;
        CALL_FUNC(close, newfd_realnext);
        task_unlock(current);
        errno = EFAULT;
        return -1;
    }

    // from here on out, no failures

    if (nfops && nfops->f_close) {
        nfops->f_close(newfd_realprev);
    }

    CALL_FUNC(close, newfd_realprev);
    
    return newfd;
}

int pipe(int pipefd[2])
{
    if (!main_task)
        return CALL_FUNC(pipe, pipefd);
    
    int p[2];
    if (0 != CALL_FUNC(pipe, p))
        return -1;
    
    pipefd[0] = task_new_fd(current, 0, p[0]);
    if (pipefd[0] == -1) {
        CALL_FUNC(close, p[0]);
        CALL_FUNC(close, p[1]);
        errno = ENOMEM;
        return -1;
    }

    pipefd[1] = task_new_fd(current, 0, p[1]);
    if (pipefd[1] == -1) {
        close(pipefd[0]);
        CALL_FUNC(close, p[1]);
        errno = ENOMEM;
        return -1;
    }

    return 0;
}

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
    if (!main_task)
        return CALL_FUNC(select, nfds, readfds, writefds, exceptfds, timeout);
    
    int fdcount = 0;
    struct pollfd *fds = NULL;

    for (int i = 0; i < nfds; i++) {
        struct pollfd currfd = { .fd = i, 0, 0 };

        if (readfds && FD_ISSET(i, readfds))
            currfd.events |= POLLIN;
        if (writefds && FD_ISSET(i, writefds))
            currfd.events |= POLLOUT;
        if (exceptfds && FD_ISSET(i, exceptfds))
            currfd.events |= POLLPRI;
        
        if (!currfd.events)
            continue;
        
        fds = realloc(fds, sizeof(*fds) * (fdcount+1));
        if (!fds) {
            errno = ENOMEM;
            return -1;
        }

        memcpy(fds + fdcount, &currfd, sizeof(currfd));
        fdcount++;
    }

    int timeout_p = -1;
    if (timeout)
        timeout_p = (timeout->tv_sec * 1000) + (timeout->tv_usec / 1000);

    int r = poll(fds, fdcount, timeout_p);

    if (r == -1) {
        free(fds);
        return -1;
    }

    r = 0;

    if (readfds)
        FD_ZERO(readfds);
    if (writefds)
        FD_ZERO(writefds);
    if (exceptfds)
        FD_ZERO(exceptfds);

    for (int i = 0; i < fdcount; i++) {
        if (fds[i].revents & POLLIN) {
            FD_SET(fds[i].fd, readfds);
            r++;
        }
        if (fds[i].revents & POLLOUT) {
            FD_SET(fds[i].fd, writefds);
            r++;
        }
        if (fds[i].revents & POLLPRI) {
            FD_SET(fds[i].fd, exceptfds);
            r++;
        }
    }

    free(fds);
    return r;
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    if (!main_task)
        return CALL_FUNC(poll, fds, nfds, timeout);
    
    int ret = -1;
    struct pollfd *realfds = malloc(nfds * sizeof(*fds));
    if (!realfds) {
        errno = ENOMEM;
        return ret;
    }
    memcpy(realfds, fds, nfds * sizeof(*fds));

    for (int i = 0; i < nfds; i++)
        realfds[i].fd = t_fd(realfds[i].fd);

    ret = CALL_FUNC(poll, realfds, nfds, timeout);

    for (int i = 0; i < nfds; i++)
        realfds[i].fd = fds[i].fd;
    memcpy(fds, realfds, nfds * sizeof(*fds));

    free(realfds);
    return ret;
}

int fcntl(int fd, int cmd, ... /* arg */ )
{
    va_list ap;

    va_start (ap, cmd);
    void *arg = va_arg (ap, void *);
    va_end (ap);

    if (!main_task)
        return CALL_FUNC(fcntl, fd, cmd, arg);
    
    if (cmd == F_DUPFD) {
        // TODO: F_DUPFD_CLOEXEC
        int f = task_reserve_fd(current, (int)(long)arg);
        if (-1 == f) {
            errno = EMFILE;
            return -1;
        }

        int r = task_set_fd(current, f, CALL_FUNC(dup, t_fd(fd)));
        if (r == -1) {
            return r;
        }

        task_lock(current);

        struct fops *fops = fops_for_fd_locked(current, fd);
        current->tsk_fd[f] |= fops_fdflag(fops);
        if (0 != fops_dup(fops, t_fd(fd), r)) {
            CALL_FUNC(close, r);
            current->tsk_fd[f] = -1;
            f = -1;
            errno = EFAULT;
        }
    
        task_unlock(current);
        return f;
    }
    return CALL_FUNC(fcntl, t_fd(fd), cmd, arg);
}

int ftruncate(int fd, off_t length)
{ return CALL_FUNC(ftruncate, t_fd(fd), length); }

int stat(const char *pathname, struct stat *statbuf)
{
    struct fops *fops;
    if (!main_task || !(fops = fops_for_pathname(pathname)))
        return CALL_FUNC(stat, pathname, statbuf);

    FOPS_PATH(fops, f_stat, pathname, statbuf);
}

int fstat(int fd, struct stat *statbuf)
{
    struct fops *fops;
    if (!main_task || !(fops = fops_for_fd(current, fd)))
        return CALL_FUNC(fstat, t_fd(fd), statbuf);
    
    if (!fops->f_stat) {
        errno = ENOTSUP;
        return -1;
    }
    
    return fops->f_stat(t_fd(fd), statbuf);
}

int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags)
{ return CALL_FUNC(fstatat, t_fd(dirfd), pathname, statbuf, flags); }

int faccessat(int dirfd, const char *pathname, int mode, int flags)
{ return CALL_FUNC(faccessat, t_fd(dirfd), pathname, mode, flags); }

int chmod(const char *pathname, mode_t mode)
{
    struct fops *fops;
    if (!main_task || !(fops = fops_for_pathname(pathname)))
        return CALL_FUNC(chmod, pathname, mode);

    FOPS_PATH(fops, f_chmod, pathname, mode);
}

int fchmod(int fd, mode_t mode)
{
    struct fops *fops;
    if (!main_task || !(fops = fops_for_fd(current, fd)))
        return CALL_FUNC(fchmod, t_fd(fd), mode);
    
    if (!fops->f_chmod) {
        errno = ENOTSUP;
        return -1;
    }
    
    return fops->f_chmod(t_fd(fd), mode);
}

// TODO support dirfd properly
int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags)
{ return CALL_FUNC(fchmodat, t_fd(dirfd), pathname, mode, flags); }

int chown(const char *pathname, uid_t owner, gid_t group)
{
    struct fops *fops;
    if (!main_task || !(fops = fops_for_pathname(pathname)))
        return CALL_FUNC(chown, pathname, owner, group);

    FOPS_PATH(fops, f_chown, pathname, owner, group);
}

int fchown(int fd, uid_t owner, gid_t group)
{
    struct fops *fops;
    if (!main_task || !(fops = fops_for_fd(current, fd)))
        return CALL_FUNC(fchown, t_fd(fd), owner, group);
    
    if (!fops->f_chown) {
        errno = ENOTSUP;
        return -1;
    }
    
    return fops->f_chown(t_fd(fd), owner, group);
}

int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags)
{ return CALL_FUNC(fchownat, t_fd(dirfd), pathname, owner, group, flags); }

int flock(int fd, int operation)
{ return CALL_FUNC(flock, t_fd(fd), operation); }

int lockf(int fd, int cmd, off_t len)
{ return CALL_FUNC(lockf, t_fd(fd), cmd, len); }

ssize_t readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz)
{ return CALL_FUNC(readlinkat, t_fd(dirfd), pathname, buf, bufsiz); }

int symlinkat(const char *target, int newdirfd, const char *linkpath)
{ return CALL_FUNC(symlinkat, target, t_fd(newdirfd), linkpath); }

int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags)
{ return CALL_FUNC(linkat, t_fd(olddirfd), oldpath, t_fd(newdirfd), newpath, flags); }

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{ return CALL_FUNC(renameat, t_fd(olddirfd), oldpath, t_fd(newdirfd), newpath); }

int unlinkat(int dirfd, const char *pathname, int flags)
{ return CALL_FUNC(unlinkat, t_fd(dirfd), pathname, flags); }

int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev)
{ return CALL_FUNC(mknodat, t_fd(dirfd), pathname, mode, dev); }

int mkdirat(int dirfd, const char *pathname, mode_t mode)
{ return CALL_FUNC(mkdirat, t_fd(dirfd), pathname, mode); }

int socket(int domain, int type, int protocol)
{
    int r = CALL_FUNC(socket, domain, type, protocol);
    if (!main_task)
        return r;
    if (r == -1) {
        return r;
    }

    int f = task_new_fd(current, 0, r);
    if (f == -1) {
        CALL_FUNC(close, r);
        errno = ENOMEM;
    }
    return f;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    int r = CALL_FUNC(accept, t_fd(sockfd), addr, addrlen);
    if (!main_task)
        return r;
    if (r == -1) {
        return r;
    }

    // TODO: allocate before calling `accept()`
    int f = task_new_fd(current, 0, r);
    if (f == -1) {
        CALL_FUNC(close, r);
        errno = ENOMEM;
    }
    return f;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{ return CALL_FUNC(bind, t_fd(sockfd), addr, addrlen); }

int listen(int sockfd, int backlog)
{ return CALL_FUNC(listen, t_fd(sockfd), backlog); }

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{ return CALL_FUNC(connect, t_fd(sockfd), addr, addrlen); }

int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{ return CALL_FUNC(getpeername, t_fd(sockfd), addr, addrlen); }

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{ return CALL_FUNC(getsockname, t_fd(sockfd), addr, addrlen); }

int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{ return CALL_FUNC(getsockopt, t_fd(sockfd), level, optname, optval, optlen); }

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
{ return CALL_FUNC(setsockopt, t_fd(sockfd), level, optname, optval, optlen); }

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{ return CALL_FUNC(send, t_fd(sockfd), buf, len, flags); }

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)
{ return CALL_FUNC(sendto, t_fd(sockfd), buf, len, flags, dest_addr, addrlen); }

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags)
{ return CALL_FUNC(sendmsg, t_fd(sockfd), msg, flags); }

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{ return CALL_FUNC(recv, t_fd(sockfd), buf, len, flags); }

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)
{ return CALL_FUNC(recvfrom, t_fd(sockfd), buf, len, flags, src_addr, addrlen); }

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags)
{ return CALL_FUNC(recvmsg, t_fd(sockfd), msg, flags); }

int shutdown(int sockfd, int how)
{ return CALL_FUNC(shutdown, t_fd(sockfd), how); }

int socketpair(int domain, int type, int protocol, int sv[2])
{
    if (!main_task)
        return CALL_FUNC(socketpair, domain, type, protocol, sv);
    
    int p[2];
    if (0 != CALL_FUNC(socketpair, domain, type, protocol, p))
        return -1;
    
    sv[0] = task_new_fd(current, 0, p[0]);
    if (sv[0] == -1) {
        CALL_FUNC(close, p[0]);
        CALL_FUNC(close, p[1]);
        errno = ENOMEM;
        return -1;
    }

    sv[1] = task_new_fd(current, 0, p[1]);
    if (sv[1] == -1) {
        close(sv[0]);
        CALL_FUNC(close, p[1]);
        errno = ENOMEM;
        return -1;
    }

    return 0;
}

int ioctl(int fd, unsigned long request, ...)
{
    va_list ap;
    va_start(ap, request);
    void* arg = va_arg(ap, void*);
    va_end(ap);

    // TODO can't there be ioctls with multiple args?
    struct fops *fops;
    if (!main_task || !(fops = fops_for_fd(current, fd)))
        return CALL_FUNC(ioctl, fd, request, arg);
    
    if (!fops->f_ioctl) {
        errno = ENOTSUP;
        return -1;
    }
    
    return fops->f_ioctl(t_fd(fd), request, arg);
    
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg) {
    return tvm_pthread_create(thread, attr, start_routine, arg);
}

void pthread_exit(void *retval) { tvm_pthread_exit(retval); }

void exit(int status) { if (!main_task) CALL_FUNC(exit, status); _exit(status); }

void _exit(int status)
{
    if (pthread_self() == main_pthread)
        CALL_FUNC(exit, status);
    
    task_lock(current);

    terminate_current_locked(mkwstatus(1, status));
}

void _Exit(int status) { _exit(status); }

void abort(void)
{
    if (!main_task)
        CALL_FUNC(abort);
    
    raise(SIGABRT);
    exit(1); // unreachable
}

pid_t getpid()
{
    if (!main_task)
        return CALL_FUNC(getpid);
    
    return current->tsk_pid;
}

pid_t getppid()
{
    if (!main_task || (main_task == current))
        return CALL_FUNC(getppid);

    task_lock(current);
    pid_t ppid = (current->tsk_parent ? current->tsk_parent->tsk_pid : 1);
    task_unlock(current);

    return ppid;
}

pid_t wait(int *wstatus)
{ return waitpid(-1, wstatus, 0); }

pid_t waitpid(pid_t pid, int *wstatus, int options)
{
    if (!main_task)
        return CALL_FUNC(waitpid, pid, wstatus, options);

    struct task *zombiet = NULL;
    int found;

    // 0 is current pgid (which is marked in pid as `-pgid`)
    if (pid == 0) {
        task_lock(current);
        pid = -(current->tsk_pgid);
        task_unlock(current);
    }

    pthread_mutex_lock(&current->tsk_wait_lock);
    while (!(zombiet = task_next_zombie_child(current, pid, &found))) {
        if (!found) {
            pthread_mutex_unlock(&current->tsk_wait_lock);
            errno = ECHILD;
            return -1;
        }
        if (options & WNOHANG) {
            pthread_mutex_unlock(&current->tsk_wait_lock);
            return 0;
        }
        pthread_cond_wait(&current->tsk_wait_cond, &current->tsk_wait_lock);
    }
    pthread_mutex_unlock(&current->tsk_wait_lock);

    task_lock(zombiet);
    
    if (list_empty(&zombiet->tsk_pthreads))
        panic("waitpid tsk_pthreads empty");
    struct pthread_entry *pentry = list_entry(zombiet->tsk_pthreads.next, struct pthread_entry, ptl_entry);
    pthread_join(pentry->ptl_value, NULL);
    
    pid_t childpid = zombiet->tsk_pid;
    if (wstatus)
        *wstatus = zombiet->tsk_result;
    taskdealloc(zombiet);

    return childpid;
}

pid_t setsid(void) {
    if (!main_task)
        return CALL_FUNC(setsid);
    
    if (-1 == setpgid(0, 0))
        return -1;
    
    task_lock(current);
    current->tsk_sid = current->tsk_pid;
    current->tsk_state &= ~TS_CTTY;
    task_unlock(current);

    return current->tsk_sid;
}

pid_t getsid(pid_t pid)
{
    if (!main_task)
        return CALL_FUNC(getsid, pid);
    
    if (!pid)
        pid = current->tsk_pid;
    
    struct task *t = task_for_pid(pid);
    if (!t)
        return CALL_FUNC(getsid, pid);
    
    return t->tsk_sid;
}

int setpgid(pid_t pid, pid_t pgid)
{
    if (!main_task)
        return CALL_FUNC(setpgid, pid, pgid);
    
    if (pgid < 0) {
        errno = EINVAL;
        return -1;
    }
    if (!pid)
        pid = current->tsk_pid;
    
    struct task *t = task_for_pid(pid);
    if (!t)
        return CALL_FUNC(setpgid, pid, pgid);

    if (!pgid)
        pgid = pid;

    task_lock(t);

    if (t->tsk_pid == t->tsk_sid) {
        task_unlock(t);
        errno = EPERM;
        return -1;
    }

    pthread_mutex_lock(&tasks_lock);
    struct task *ct;
    list_for_each_entry(ct, &main_task->tsk_list, tsk_list)
    {
        if (pgid == ct->tsk_pgid)
        {
            if (pid == ct->tsk_pid || t->tsk_sid != ct->tsk_sid) {
                errno = EPERM;
                pthread_mutex_unlock(&tasks_lock);
                task_unlock(t);
                return -1;
            }

            pthread_mutex_unlock(&tasks_lock);
            task_unlock(t);
            t->tsk_pgid = ct->tsk_pgid;
            return 0;
        }
    }
    pthread_mutex_unlock(&tasks_lock);

    if (pid != pgid) {
        errno = ESRCH;
        task_unlock(t);
        return -1;
    }

    t->tsk_pgid = pgid;
    task_unlock(t);
    return 0;
}

pid_t getpgid(pid_t pid)
{
    if (!main_task)
        return CALL_FUNC(getpgid, pid);
    
    if (!pid)
        pid = current->tsk_pid;
    
    struct task *t = task_for_pid(pid);
    if (!t)
        return CALL_FUNC(getpgid, pid);
    
    return t->tsk_pgid;
}

pid_t getpgrp(void)
{
    if (!main_task)
        return CALL_FUNC(getpgrp);
    
    return getpgid(0);
}

int setpgrp(void)
{
    if (!main_task)
        return CALL_FUNC(setpgrp);
    
    return setpgid(0, 0);
}

sighandler_t signal(int signum, sighandler_t handler)
{
    struct sigaction oldact, act = {
        .sa_handler = handler,
        .sa_flags = SA_RESTART,
    };

    if (-1 == sigaction(signum, &act, &oldact)) {
        return SIG_ERR;
    }

    return oldact.sa_handler;
}

int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
    if (signum >= MAX_SIGNALS || signum < 1 ||
        signum == SIGKILL || signum == SIGSTOP) {
        errno = EINVAL;
        return -1;
    }

    task_lock(current);
    if (oldact)
        memcpy(oldact, current->tsk_sighandlers + signum, sizeof(*current->tsk_sighandlers));
    if (act)
        memcpy(current->tsk_sighandlers + signum, act, sizeof(*current->tsk_sighandlers));
    task_unlock(current);

    return 0;
}

int raise(int sig) {
    int r = pthread_kill(pthread_self(), sig);
    if (r != 0) {
        errno = r;
        r = -1;
    }
    return r;
}

int kill(pid_t pid, int sig) {
    if (!main_task)
        return CALL_FUNC(kill, pid, sig);
    
    if (pid == 0) {
        task_lock(current);
        pid = current->tsk_pgid;
        task_unlock(current);

        // should be positive but not 1 (-1 isn't want we would like to call kill with)
        if (pid <= 1)
            panic("kill self pgid (%d)", pid);
        
        return kill(-pid, sig);
    }

    // handle single target process
    if (pid > 0) {

        // special case: kill to self
        if (pid == current->tsk_pid)
            return raise(sig);

        struct task *t;
        // special case: kill an external process to the tvm
        if (!(t = task_for_pid(pid)))
            return CALL_FUNC(kill, pid, sig);

        task_lock(t);
        if (t->tsk_state & TS_ZOMBIE) {
            task_unlock(t);
            errno = ESRCH;
            return -1;
        }

        int r = task_kill_locked(t, sig);
        if (r == ESRCH)
            panic("kill(%d) no threads?", pid);
        task_unlock(t);

        if (r != 0) {
            errno = r;
            r = -1;
        }

        return r;
    }

    // Kill all processes with permissions not supported
    if (pid == -1) {
        errno = EINVAL;
        return -1;
    }

    // Kill all processes in process group, pid is -pgid

    int self = 0;
    int ntasks = 0;
    struct task **tasks = NULL;
    
    task_lock(current);
    pthread_mutex_lock(&tasks_lock);
    struct task *t;
    list_for_each_entry(t, &main_task->tsk_list, tsk_list) {
        if (t->tsk_pgid == -pid) {
            if (t == current) {
                self = 1;
                continue;
            }

            struct task **new_tasks = malloc(sizeof(struct task *) * (ntasks + 1));
            if (!new_tasks) {
                for (int i = 0; i < ntasks; i++)
                    task_unlock(tasks[i]);
                free(tasks);
                errno = ENOMEM;
                return -1;
            }

            task_lock(t);
            memmove(new_tasks, tasks, sizeof(struct task *) * ntasks);
            new_tasks[ntasks] = t;
            free(tasks);
            tasks = new_tasks;
            ntasks++;
        }
    }
    pthread_mutex_unlock(&tasks_lock);

    if (!self) {
        task_unlock(current);

        if (!ntasks) {
            errno = ESRCH;
            return -1;
        }
    }
    
    int one_ok = 0;
    for (int i = 0; i < ntasks; i++) {
        int r = task_kill_locked(tasks[i], sig);
        if (0 == r)
            one_ok = 1;
        else
            errno = r;
    }

    for (int i = 0; i < ntasks; i++)
        task_unlock(tasks[i]);
    
    if (self) {
        int r = task_kill_locked(current, sig);
        if (0 == r)
            one_ok = 1;
        else
            errno = r;
        task_unlock(current);
    }

    return (one_ok ? 0 : -1);
}

char *getenv(const char *name)
{
    if (!main_task)
        return CALL_FUNC(getenv, name);

    task_lock(current);
    char **env = NULL;
    if (current->tsk_environ)
        env = findenv(current->tsk_environ, name, strlen(name));

    if (!env) {
        task_unlock(current);
        return NULL;
    }
    
    char *ret = strchr(*env, '=');
    task_unlock(current);
    if (ret)
        return ret+1;
    
    return ret;
}

int putenv(char *string)
{
    if (!main_task)
        return CALL_FUNC(putenv, string);

    char *value = strchr(string, '=');
    size_t klen;
    if (NULL == value) {
        value = string + strlen(string);
        klen = (size_t)(value - string);
    }
    else {
        klen = (size_t)(value - string);
        value++;
    }
    
    task_lock(current);
    char **env = NULL;
    if (current->tsk_environ)
        env = findenv(current->tsk_environ, string, klen);
    
    if (env) {
        *env = string;
        task_unlock(current);
        return 0;
    }

    char **new_environ = addenv(current->tsk_environ, string);
    if (!new_environ) {
        task_unlock(current);
        errno = ENOMEM;
        return -1;
    }

    // TODO not sure if this is a good idea
    //free(current->tsk_environ);
    current->tsk_environ = new_environ;
    task_unlock(current);

    return 0;
}

int setenv(const char *name, const char *value, int overwrite)
{
    if (!main_task)
        return CALL_FUNC(setenv, name, value, overwrite);

    size_t name_len = strlen(name);
    size_t value_len = strlen(value);
    char *string = malloc(name_len + value_len + 2);
    if (!string) {
        errno = ENOMEM;
        return -1;
    }
    memcpy(string, name, name_len);
    string[name_len] = '=';
    memcpy(string + name_len + 1, value, value_len);

    task_lock(current);
    char **env = NULL;
    if (current->tsk_environ)
        env = findenv(current->tsk_environ, name, strlen(name));
    
    if (env) {
        if (overwrite)
            *env = string;
        else
            free(string);
        task_unlock(current);
        return 0;    
    }

    char **new_environ = addenv(current->tsk_environ, string);
    if (!new_environ) {
        task_unlock(current);
        free(string);
        errno = ENOMEM;
        return -1;
    }

    // TODO not sure if this is a good idea
    //free(current->tsk_environ);
    current->tsk_environ = new_environ;
    task_unlock(current);

    return 0;
}

int unsetenv(const char *name)
{
    if (!main_task)
        return CALL_FUNC(unsetenv, name);
    
    if (name == NULL || *name == '\0' || strchr(name, '=') != NULL)
    {
        errno = EINVAL;
        return -1;
    }

    size_t len = strlen(name);

    task_lock(current);
    if (!current->tsk_environ) {
        task_unlock(current);
        return 0;
    }

    for (char **e = current->tsk_environ; *e != NULL;) {
	    if (!strncmp (*e, name, len) && (*e)[len] == '=') {
            for (char **e2 = e; *e2 != NULL; e2++)
                e2[0] = e2[1];
	        continue;
	    }
        e++;
    }

    task_unlock(current);

    return 0;
}

int clearenv(void)
{
    if (!main_task)
        return CALL_FUNC(clearenv);
    
    task_lock(current);
    current->tsk_environ = NULL;
    task_unlock(current);

    return 0;
}

int execve(const char *pathname, char *const argv[], char *const envp[])
{
    if (!main_task)
        return CALL_FUNC(execve, pathname, argv, envp);

    INFO("execve(\"%s\")", pathname);

    int argc = 0;
    for (char * const*a = argv; *a && argc < INT_MAX; a++)
        argc++;
    
    if (argc == INT_MAX) {
        INFO("  failed(E2BIG)");
        errno = E2BIG;
        return -1;
    }

    main_func_t main_func = find_program(pathname);
    if (!main_func) {
        INFO("  failed(ENOENT)");
        errno = ENOENT;
        return -1;
    }

    // No failing from here!

    for (int i = 0; i < MAX_FILES; i++) {
        if (t_fd(i) == -1) 
            continue;
        
        int fd_flags = fcntl(i, F_GETFD);
        if (-1 == fd_flags)
            panic("execve(\"%s\") fcntl(%d, F_GETFD)", pathname, i);
        if (fd_flags & FD_CLOEXEC) {
            if (0 != close(i))
                panic("execve(\"%s\") close(%d)", pathname, i);
        }
    }

    struct sigaction act = { .sa_handler = SIG_DFL };
    for (int i = 1; i < MAX_SIGNALS; i++) {
        if (i == SIGKILL || i == SIGSTOP)
            continue;
        if (0 != sigaction(i, &act, NULL))
            panic("sigaction(%d)", i);
    }
    
    // TODO if 0, 1, 2 are closed we can be nice and open /dev/full, /dev/null and /dev/null for the program

    cow_run_init_funcs(); // re-initialize copy-on-write vars with init statements

    // TODO hack, getopt should have a tvm thread-safe version
    extern int optind;
    optind = 1;

    exit(main_func(argc, argv, envp));
}

int execl(const char *pathname, const char *arg, ... /*, (char *) NULL */)
{
    size_t argc;
    va_list ap;
    
    va_start(ap, arg);
    for (argc = 1; va_arg(ap, const char *) && argc < INT_MAX;)
        argc++;
    va_end(ap);

    if (argc == INT_MAX) {
        errno = E2BIG;
        return -1;
    }

    char **argv = malloc(sizeof(char *) * (argc+1));
    if (!argv) {
        errno = ENOMEM;
        return -1;
    }
    argv[argc] = NULL;
    
    va_start(ap, arg);
    argv[0] = (char *)arg;
    for (char **a = (argv+1); a < (argv + argc); a++)
        *a = va_arg(ap, char *);
    va_end(ap);

    int r = execv(pathname, argv);
    free(argv);
    return r;
}

int execlp(const char *file, const char *arg, ... /*, (char *) NULL */)
{
    size_t argc;
    va_list ap;
    
    va_start(ap, arg);
    for (argc = 0; va_arg(ap, const char *) && argc < INT_MAX;)
        argc++;
    va_end(ap);

    if (argc == INT_MAX) {
        errno = E2BIG;
        return -1;
    }

    char **argv = malloc(sizeof(char *) * (argc+1));
    if (!argv) {
        errno = ENOMEM;
        return -1;
    }
    argv[argc] = NULL;

    va_start(ap, arg);
    for (char **a = argv; a < (argv + argc); a++)
        *a = va_arg(ap, char *);
    va_end(ap);

    int r = execvp(file, argv);
    free(argv);
    return r;
}

int execle(const char *pathname, const char *arg, ... /*, (char *) NULL, char *const envp[] */)
{
    size_t argc;
    va_list ap;
    
    va_start(ap, arg);
    for (argc = 0; va_arg(ap, const char *) && argc < INT_MAX;)
        argc++;
    va_end(ap);

    if (argc == INT_MAX) {
        errno = E2BIG;
        return -1;
    }

    char **argv = malloc(sizeof(char *) * (argc+1));
    if (!argv) {
        errno = ENOMEM;
        return -1;
    }
    argv[argc] = NULL;

    va_start(ap, arg);
    for (char **a = argv; a < (argv + argc); a++)
        *a = va_arg(ap, char *);
    char **envp = va_arg(ap, char **);
    va_end(ap);

    int r = execve(pathname, argv, envp);
    free(argv);
    return r;
}

int execv(const char *pathname, char *const argv[])
{
    if (!main_task)
        return CALL_FUNC(execv, pathname, argv);
    
    return execve(pathname, argv, tvm_environ);
}

int execvp(const char *file, char *const argv[])
{
    if (!main_task)
        return CALL_FUNC(execvp, file, argv);
    
    return execvpe(file, argv, tvm_environ);
}

int execvpe(const char *file, char *const argv[], char *const envp[])
{
    if (!main_task)
        return CALL_FUNC(execvpe, file, argv, envp);
    
    const char *pathname = find_program_pathname(file);
    if (!pathname) {
        errno = ENOENT;
        return -1;
    }

    return execve(pathname, argv, envp);
}

int openpty(int *amaster, int *aslave, char *name, const struct termios *termp, const struct winsize *winp)
{
    if (!main_task)
        return CALL_FUNC(openpty, amaster, aslave, name, termp, winp);

    // TODO
    if (name || termp || winp)
        panic("openpty todo");

    int master = task_reserve_fd(current, 0);
    if (master == -1) {
        errno = EMFILE;
        return -1;
    }

    if (-1 == task_set_fd(current, master, ptm_open() | TFD_TTY))
        return -1;

    char sname[PATH_MAX];
    if (0 != ptsname_r(master, sname, PATH_MAX)) {
        close(master);
        return -1;
    }

    int slave = open(sname, O_RDWR | O_NOCTTY);
    if (-1 == slave) {
        close(master);
        return -1;
    }

    *amaster = master;
    *aslave = slave;
    return 0;
}

int isatty(int fd)
{
    if (!main_task)
        return CALL_FUNC(isatty, t_fd(fd));
    
    if (islocaltty(fd))
        return 1;
    
    return CALL_FUNC(isatty, t_fd(fd));
}

int ttyname_r(int fd, char *buf, size_t buflen)
{
    if (!main_task || !islocaltty(fd))
        return CALL_FUNC(ttyname_r, t_fd(fd), buf, buflen);
    
    struct tty *tt = tty_for_fd(t_fd(fd), TTM_MASTER);
    if (tt) {
        snprintf(buf, buflen, "%s", PTMX_FILE);
        tty_unlock(tt);
        return 0;
    }

    return tty_slavename(t_fd(fd), buf, buflen);
}

char *ttyname(int fd)
{
    if (!main_task || !islocaltty(fd))
        return CALL_FUNC(ttyname, t_fd(fd));

    int r = ttyname_r(fd, tty_name, sizeof(tty_name));
    if (r) {
        INFO("X");
        errno = r;
        return NULL;
    }

    return tty_name;
}

int ptsname_r(int fd, char *buf, size_t buflen)
{
    if (!main_task || !islocaltty(fd))
        return CALL_FUNC(ptsname_r, t_fd(fd), buf, buflen);
    
    return tty_slavename(t_fd(fd), buf, buflen);
}

char *ptsname(int fd)
{
    if (!main_task || !islocaltty(fd))
        return CALL_FUNC(ptsname, t_fd(fd));

    int r = ptsname_r(fd, pts_name, sizeof(pts_name));
    if (r) {
        errno = r;
        return NULL;
    }

    return pts_name;
}

pid_t tcgetpgrp(int fd)
{
    if (!main_task || !islocaltty(fd))
        return CALL_FUNC(tcgetpgrp, t_fd(fd));
    
    pid_t ret;
    if (0 != ttyop_ioctl(t_fd(fd), TIOCGPGRP, &ret))
        return -1;
    return ret;
}

int tcsetpgrp(int fd, pid_t pgrp)
{
    if (!main_task || !islocaltty(fd))
        return CALL_FUNC(tcsetpgrp, t_fd(fd), pgrp);
    
    return ttyop_ioctl(t_fd(fd), TIOCSPGRP, &pgrp); 
}

int tcgetattr(int fd, struct termios *termios_p)
{
    if (!main_task || !islocaltty(fd))
        return CALL_FUNC(tcgetattr, t_fd(fd), termios_p);
    
    return ttyop_ioctl(t_fd(fd), TCGETS, termios_p);
}

int tcsetattr(int fd, int optional_actions, const struct termios *termios_p)
{
    if (!main_task || !islocaltty(fd))
        return CALL_FUNC(tcsetattr, t_fd(fd), optional_actions, termios_p);
    
    int request;
    switch (optional_actions) {
        default:
            errno = EINVAL;
            return -1;
        
        case TCSANOW:
            request = TCSETS;
            break;
        
        case TCSADRAIN:
            request = TCSETSW;
            break;
        
        case TCSAFLUSH:
            request = TCSETSF;
            break;
    }

    return ttyop_ioctl(t_fd(fd), request, (void *)termios_p);
}

int tcsendbreak(int fd, int duration)
{
    if (!main_task || !islocaltty(fd))
        return CALL_FUNC(tcsendbreak, t_fd(fd), duration);
    
    return ttyop_ioctl(t_fd(fd), TCSBRK, (void *)(long)duration);
}

int tcdrain(int fd)
{
    if (!main_task || !islocaltty(fd))
        return CALL_FUNC(tcdrain, t_fd(fd));
    
    return tcsendbreak(fd, 1);
}

int tcflush(int fd, int queue_selector)
{
    if (!main_task || !islocaltty(fd))
        return CALL_FUNC(tcflush, t_fd(fd), queue_selector);
    
    return ttyop_ioctl(t_fd(fd), TCFLSH, (void *)(long)queue_selector);
}

int tcflow(int fd, int action)
{
    if (!main_task || !islocaltty(fd))
        return CALL_FUNC(tcflow, t_fd(fd), action);
    
    return ttyop_ioctl(t_fd(fd), TCXONC, (void *)(long)action);
}

void *malloc(size_t size)
{
    return calloc(1, size);
}

void *calloc(size_t nmemb, size_t size)
{
    if (0 == (nmemb * size))
        return NULL;
    
    uint64_t *p = CALL_FUNC(malloc, (nmemb * size) + sizeof(uint64_t));
    if (NULL == p)
        return p;
    
    *p = MALLOC_MAGIC | (((nmemb * size) + sizeof(uint64_t)) << 32);
    memset(p+1, 0, nmemb * size);
    return p+1;
}

void free(void *ptr)
{
    uint64_t *p = (uint64_t *)ptr;
    if (NULL == p || (p[-1] & 0xffffffff) != MALLOC_MAGIC)
        return CALL_FUNC(free, p);
    
    return CALL_FUNC(free, p-1);
}

void *realloc(void *ptr, size_t size)
{
    void *nptr = malloc(size);
    if (ptr != NULL) {
        if (nptr != NULL)
            memmove(nptr, ptr, size);
        free(ptr);
    }
    return nptr;
}

int getopt(int argc, char * const argv[], const char *optstring)
{
    if (!main_task)
        return CALL_FUNC(getopt, argc, argv, optstring);
    
    pthread_mutex_lock(&getopt_lock);
    optarg = tvm_optarg;
    optind = tvm_optind;
    opterr = tvm_opterr;
    optopt = tvm_optopt;
    int r = CALL_FUNC(getopt, argc, argv, optstring);
    tvm_optarg = optarg;
    tvm_optind = optind;
    tvm_opterr = opterr;
    tvm_optopt = optopt;
    pthread_mutex_unlock(&getopt_lock);
    return r;
}

int getopt_long(int argc, char * const argv[], const char *optstring, const struct option *longopts, int *longindex)
{
    if (!main_task)
        return CALL_FUNC(getopt_long, argc, argv, optstring, longopts, longindex);
    pthread_mutex_lock(&getopt_lock);
    optarg = tvm_optarg;
    optind = tvm_optind;
    opterr = tvm_opterr;
    optopt = tvm_optopt;
    int r = CALL_FUNC(getopt_long, argc, argv, optstring, longopts, longindex);
    tvm_optarg = optarg;
    tvm_optind = optind;
    tvm_opterr = opterr;
    tvm_optopt = optopt;
    pthread_mutex_unlock(&getopt_lock);
    return r;
}

int getopt_long_only(int argc, char * const argv[], const char *optstring, const struct option *longopts, int *longindex)
{
    if (!main_task)
        return CALL_FUNC(getopt_long_only, argc, argv, optstring, longopts, longindex);
    
    pthread_mutex_lock(&getopt_lock);
    optarg = tvm_optarg;
    optind = tvm_optind;
    opterr = tvm_opterr;
    optopt = tvm_optopt;
    int r = CALL_FUNC(getopt_long_only, argc, argv, optstring, longopts, longindex);
    tvm_optarg = optarg;
    tvm_optind = optind;
    tvm_opterr = opterr;
    tvm_optopt = optopt;
    pthread_mutex_unlock(&getopt_lock);
    return r;
}