#include <sys/syscall.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <dirent.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/event.h>
#include <sys/futex.h>
#include <sys/ioctl.h>
#include <sys/ktrace.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/poll.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <tib.h>
#include <time.h>
#include <unistd.h>

int
syscall_emulator(int syscall, ...) {
	int ret = -1;
	va_list args;

	va_start(args, syscall);
	switch(syscall)
	{
		/* Indirect syscalls not supported
		case SYS_syscall: // 0
			// int syscall(int, ...); <unistd.h>
			ret = syscall(va_arg(args,int), va_arg(args,...));
			break;
		*/
		case SYS_exit: // 1
			// void exit(int); <stdlib.h>
			ret = 0; exit(va_arg(args,int));
			break;
		case SYS_fork: // 2
			// int fork(void); <unistd.h>
			ret = fork();
			break;
		case SYS_read: // 3
			// ssize_t read(int, void *, size_t); <unistd.h>
			ret = read(va_arg(args,int), va_arg(args,void *), va_arg(args,size_t));
			break;
		case SYS_write: // 4
			// ssize_t write(int, const void *, size_t); <unistd.h>
			ret = write(va_arg(args,int), va_arg(args,const void *), va_arg(args,size_t));
			break;
		case SYS_open: // 5
			// int open(const char *, int, ...); <fcntl.h>
			ret = open(va_arg(args,const char *), va_arg(args,int), va_arg(args,mode_t));
			break;
		case SYS_close: // 6
			// int close(int); <unistd.h>
			ret = close(va_arg(args,int));
			break;
		case SYS_getentropy: // 7
			// int getentropy(void *, size_t); <unistd.h>
			ret = getentropy(va_arg(args,void *), va_arg(args,size_t));
			break;
		/* No signature found in headers
		case SYS___tfork: // 8
			// int __tfork(const struct __tfork *, size_t);
			ret = __tfork(va_arg(args,const struct __tfork *), va_arg(args,size_t));
			break;
		*/
		case SYS_link: // 9
			// int link(const char *, const char *); <unistd.h>
			ret = link(va_arg(args,const char *), va_arg(args,const char *));
			break;
		case SYS_unlink: // 10
			// int unlink(const char *); <unistd.h>
			ret = unlink(va_arg(args,const char *));
			break;
		case SYS_wait4: // 11
			// pid_t wait4(pid_t, int *, int, struct rusage *); <sys/wait.h>
			ret = wait4(va_arg(args,pid_t), va_arg(args,int *), va_arg(args,int), va_arg(args,struct rusage *));
			break;
		case SYS_chdir: // 12
			// int chdir(const char *); <unistd.h>
			ret = chdir(va_arg(args,const char *));
			break;
		case SYS_fchdir: // 13
			// int fchdir(int); <unistd.h>
			ret = fchdir(va_arg(args,int));
			break;
		case SYS_mknod: // 14
			// int mknod(const char *, mode_t, dev_t); <sys/stat.h>
			ret = mknod(va_arg(args,const char *), va_arg(args,mode_t), va_arg(args,dev_t));
			break;
		case SYS_chmod: // 15
			// int chmod(const char *, mode_t); <sys/stat.h>
			ret = chmod(va_arg(args,const char *), va_arg(args,mode_t));
			break;
		case SYS_chown: // 16
			// int chown(const char *, uid_t, gid_t); <unistd.h>
			ret = chown(va_arg(args,const char *), va_arg(args,uid_t), va_arg(args,gid_t));
			break;
		/* No signature found in headers
		case SYS_break: // 17
			// int break(char *);
			ret = break(va_arg(args,char *));
			break;
		*/
		case SYS_getdtablecount: // 18
			// int getdtablecount(void); <unistd.h>
			ret = getdtablecount();
			break;
		case SYS_getrusage: // 19
			// int getrusage(int, struct rusage *); <sys/resource.h>
			ret = getrusage(va_arg(args,int), va_arg(args,struct rusage *));
			break;
		case SYS_getpid: // 20
			// pid_t getpid(void); <unistd.h>
			ret = getpid();
			break;
		case SYS_mount: // 21
			// int mount(const char *, const char *, int, void *); <sys/mount.h>
			ret = mount(va_arg(args,const char *), va_arg(args,const char *), va_arg(args,int), va_arg(args,void *));
			break;
		case SYS_unmount: // 22
			// int unmount(const char *, int); <sys/mount.h>
			ret = unmount(va_arg(args,const char *), va_arg(args,int));
			break;
		case SYS_setuid: // 23
			// int setuid(uid_t); <unistd.h>
			ret = setuid(va_arg(args,uid_t));
			break;
		case SYS_getuid: // 24
			// uid_t getuid(void); <unistd.h>
			ret = getuid();
			break;
		case SYS_geteuid: // 25
			// uid_t geteuid(void); <unistd.h>
			ret = geteuid();
			break;
		case SYS_ptrace: // 26
			// int ptrace(int, pid_t, caddr_t, int); <sys/ptrace.h>
			ret = ptrace(va_arg(args,int), va_arg(args,pid_t), va_arg(args,caddr_t), va_arg(args,int));
			break;
		case SYS_recvmsg: // 27
			// ssize_t recvmsg(int, struct msghdr *, int); <sys/socket.h>
			ret = recvmsg(va_arg(args,int), va_arg(args,struct msghdr *), va_arg(args,int));
			break;
		case SYS_sendmsg: // 28
			// ssize_t sendmsg(int, const struct msghdr *, int); <sys/socket.h>
			ret = sendmsg(va_arg(args,int), va_arg(args,const struct msghdr *), va_arg(args,int));
			break;
		case SYS_recvfrom: // 29
			// ssize_t recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *); <sys/socket.h>
			ret = recvfrom(va_arg(args,int), va_arg(args,void *), va_arg(args,size_t), va_arg(args,int), va_arg(args,struct sockaddr *), va_arg(args,socklen_t *));
			break;
		case SYS_accept: // 30
			// int accept(int, struct sockaddr *, socklen_t *); <sys/socket.h>
			ret = accept(va_arg(args,int), va_arg(args,struct sockaddr *), va_arg(args,socklen_t *));
			break;
		case SYS_getpeername: // 31
			// int getpeername(int, struct sockaddr *, socklen_t *); <sys/socket.h>
			ret = getpeername(va_arg(args,int), va_arg(args,struct sockaddr *), va_arg(args,socklen_t *));
			break;
		case SYS_getsockname: // 32
			// int getsockname(int, struct sockaddr *, socklen_t *); <sys/socket.h>
			ret = getsockname(va_arg(args,int), va_arg(args,struct sockaddr *), va_arg(args,socklen_t *));
			break;
		case SYS_access: // 33
			// int access(const char *, int); <unistd.h>
			ret = access(va_arg(args,const char *), va_arg(args,int));
			break;
		case SYS_chflags: // 34
			// int chflags(const char *, u_int); <sys/stat.h>
			ret = chflags(va_arg(args,const char *), va_arg(args,u_int));
			break;
		case SYS_fchflags: // 35
			// int fchflags(int, u_int); <sys/stat.h>
			ret = fchflags(va_arg(args,int), va_arg(args,u_int));
			break;
		case SYS_sync: // 36
			// void sync(void); <unistd.h>
			ret = 0; sync();
			break;
		/* No signature found in headers
		case SYS_msyscall: // 37
			// int msyscall(void *, size_t);
			ret = msyscall(va_arg(args,void *), va_arg(args,size_t));
			break;
		*/
		case SYS_stat: // 38
			// int stat(const char *, struct stat *); <sys/stat.h>
			ret = stat(va_arg(args,const char *), va_arg(args,struct stat *));
			break;
		case SYS_getppid: // 39
			// pid_t getppid(void); <unistd.h>
			ret = getppid();
			break;
		case SYS_lstat: // 40
			// int lstat(const char *, struct stat *); <sys/stat.h>
			ret = lstat(va_arg(args,const char *), va_arg(args,struct stat *));
			break;
		case SYS_dup: // 41
			// int dup(int); <unistd.h>
			ret = dup(va_arg(args,int));
			break;
		case SYS_fstatat: // 42
			// int fstatat(int, const char *, struct stat *, int); <sys/stat.h>
			ret = fstatat(va_arg(args,int), va_arg(args,const char *), va_arg(args,struct stat *), va_arg(args,int));
			break;
		case SYS_getegid: // 43
			// gid_t getegid(void); <unistd.h>
			ret = getegid();
			break;
		case SYS_profil: // 44
			// int profil(caddr_t, size_t, u_long, u_int); <unistd.h>
			ret = profil(va_arg(args,caddr_t), va_arg(args,size_t), va_arg(args,u_long), va_arg(args,u_int));
			break;
		case SYS_ktrace: // 45
			// int ktrace(const char *, int, int, pid_t); <sys/ktrace.h>
			ret = ktrace(va_arg(args,const char *), va_arg(args,int), va_arg(args,int), va_arg(args,pid_t));
			break;
		case SYS_sigaction: // 46
			// int sigaction(int, const struct sigaction *, struct sigaction *); <signal.h>
			ret = sigaction(va_arg(args,int), va_arg(args,const struct sigaction *), va_arg(args,struct sigaction *));
			break;
		case SYS_getgid: // 47
			// gid_t getgid(void); <unistd.h>
			ret = getgid();
			break;
		/* Mismatched func: <signal.h> int sigprocmask(int, const sigset_t *, sigset_t *);
		case SYS_sigprocmask: // 48
			// int sigprocmask(int, sigset_t);
			ret = sigprocmask(va_arg(args,int), va_arg(args,sigset_t));
			break;
		*/
		case SYS_mmap: // 49
			// void * mmap(void *, size_t, int, int, int, off_t); <sys/mman.h>
			ret = 0; mmap(va_arg(args,void *), va_arg(args,size_t), va_arg(args,int), va_arg(args,int), va_arg(args,int), va_arg(args,off_t));
			break;
		case SYS_setlogin: // 50
			// int setlogin(const char *); <unistd.h>
			ret = setlogin(va_arg(args,const char *));
			break;
		case SYS_acct: // 51
			// int acct(const char *); <unistd.h>
			ret = acct(va_arg(args,const char *));
			break;
		/* Mismatched func: <signal.h> int sigpending(sigset_t *);
		case SYS_sigpending: // 52
			// int sigpending(void);
			ret = sigpending();
			break;
		*/
		case SYS_fstat: // 53
			// int fstat(int, struct stat *); <sys/stat.h>
			ret = fstat(va_arg(args,int), va_arg(args,struct stat *));
			break;
		case SYS_ioctl: // 54
			// int ioctl(int, u_long, ...); <sys/ioctl.h>
			ret = ioctl(va_arg(args,int), va_arg(args,u_long), va_arg(args,void *));
			break;
		case SYS_reboot: // 55
			// int reboot(int); <unistd.h>
			ret = reboot(va_arg(args,int));
			break;
		case SYS_revoke: // 56
			// int revoke(const char *); <unistd.h>
			ret = revoke(va_arg(args,const char *));
			break;
		case SYS_symlink: // 57
			// int symlink(const char *, const char *); <unistd.h>
			ret = symlink(va_arg(args,const char *), va_arg(args,const char *));
			break;
		case SYS_readlink: // 58
			// ssize_t readlink(const char *, char *, size_t); <unistd.h>
			ret = readlink(va_arg(args,const char *), va_arg(args,char *), va_arg(args,size_t));
			break;
		case SYS_execve: // 59
			// int execve(const char *, char *const *, char *const *); <unistd.h>
			ret = execve(va_arg(args,const char *), va_arg(args,char *const *), va_arg(args,char *const *));
			break;
		case SYS_umask: // 60
			// mode_t umask(mode_t); <sys/stat.h>
			ret = umask(va_arg(args,mode_t));
			break;
		case SYS_chroot: // 61
			// int chroot(const char *); <unistd.h>
			ret = chroot(va_arg(args,const char *));
			break;
		case SYS_getfsstat: // 62
			// int getfsstat(struct statfs *, size_t, int); <sys/mount.h>
			ret = getfsstat(va_arg(args,struct statfs *), va_arg(args,size_t), va_arg(args,int));
			break;
		case SYS_statfs: // 63
			// int statfs(const char *, struct statfs *); <sys/mount.h>
			ret = statfs(va_arg(args,const char *), va_arg(args,struct statfs *));
			break;
		case SYS_fstatfs: // 64
			// int fstatfs(int, struct statfs *); <sys/mount.h>
			ret = fstatfs(va_arg(args,int), va_arg(args,struct statfs *));
			break;
		case SYS_fhstatfs: // 65
			// int fhstatfs(const fhandle_t *, struct statfs *); <sys/mount.h>
			ret = fhstatfs(va_arg(args,const fhandle_t *), va_arg(args,struct statfs *));
			break;
		case SYS_vfork: // 66
			// int vfork(void); <unistd.h>
			ret = vfork();
			break;
		case SYS_gettimeofday: // 67
			// int gettimeofday(struct timeval *, struct timezone *); <sys/time.h>
			ret = gettimeofday(va_arg(args,struct timeval *), va_arg(args,struct timezone *));
			break;
		case SYS_settimeofday: // 68
			// int settimeofday(const struct timeval *, const struct timezone *); <sys/time.h>
			ret = settimeofday(va_arg(args,const struct timeval *), va_arg(args,const struct timezone *));
			break;
		case SYS_setitimer: // 69
			// int setitimer(int, const struct itimerval *, struct itimerval *); <sys/time.h>
			ret = setitimer(va_arg(args,int), va_arg(args,const struct itimerval *), va_arg(args,struct itimerval *));
			break;
		case SYS_getitimer: // 70
			// int getitimer(int, struct itimerval *); <sys/time.h>
			ret = getitimer(va_arg(args,int), va_arg(args,struct itimerval *));
			break;
		case SYS_select: // 71
			// int select(int, fd_set *, fd_set *, fd_set *, struct timeval *); <sys/select.h>
			ret = select(va_arg(args,int), va_arg(args,fd_set *), va_arg(args,fd_set *), va_arg(args,fd_set *), va_arg(args,struct timeval *));
			break;
		case SYS_kevent: // 72
			// int kevent(int, const struct kevent *, int, struct kevent *, int, const struct timespec *); <sys/event.h>
			ret = kevent(va_arg(args,int), va_arg(args,const struct kevent *), va_arg(args,int), va_arg(args,struct kevent *), va_arg(args,int), va_arg(args,const struct timespec *));
			break;
		case SYS_munmap: // 73
			// int munmap(void *, size_t); <sys/mman.h>
			ret = munmap(va_arg(args,void *), va_arg(args,size_t));
			break;
		case SYS_mprotect: // 74
			// int mprotect(void *, size_t, int); <sys/mman.h>
			ret = mprotect(va_arg(args,void *), va_arg(args,size_t), va_arg(args,int));
			break;
		case SYS_madvise: // 75
			// int madvise(void *, size_t, int); <sys/mman.h>
			ret = madvise(va_arg(args,void *), va_arg(args,size_t), va_arg(args,int));
			break;
		case SYS_utimes: // 76
			// int utimes(const char *, const struct timeval *); <sys/time.h>
			ret = utimes(va_arg(args,const char *), va_arg(args,const struct timeval *));
			break;
		case SYS_futimes: // 77
			// int futimes(int, const struct timeval *); <sys/time.h>
			ret = futimes(va_arg(args,int), va_arg(args,const struct timeval *));
			break;
		case SYS_mquery: // 78
			// void * mquery(void *, size_t, int, int, int, off_t); <sys/mman.h>
			ret = 0; mquery(va_arg(args,void *), va_arg(args,size_t), va_arg(args,int), va_arg(args,int), va_arg(args,int), va_arg(args,off_t));
			break;
		case SYS_getgroups: // 79
			// int getgroups(int, gid_t *); <unistd.h>
			ret = getgroups(va_arg(args,int), va_arg(args,gid_t *));
			break;
		case SYS_setgroups: // 80
			// int setgroups(int, const gid_t *); <unistd.h>
			ret = setgroups(va_arg(args,int), va_arg(args,const gid_t *));
			break;
		case SYS_getpgrp: // 81
			// int getpgrp(void); <unistd.h>
			ret = getpgrp();
			break;
		case SYS_setpgid: // 82
			// int setpgid(pid_t, pid_t); <unistd.h>
			ret = setpgid(va_arg(args,pid_t), va_arg(args,pid_t));
			break;
		case SYS_futex: // 83
			// int futex(uint32_t *, int, int, const struct timespec *, uint32_t *); <sys/futex.h>
			ret = futex(va_arg(args,uint32_t *), va_arg(args,int), va_arg(args,int), va_arg(args,const struct timespec *), va_arg(args,uint32_t *));
			break;
		case SYS_utimensat: // 84
			// int utimensat(int, const char *, const struct timespec *, int); <sys/stat.h>
			ret = utimensat(va_arg(args,int), va_arg(args,const char *), va_arg(args,const struct timespec *), va_arg(args,int));
			break;
		case SYS_futimens: // 85
			// int futimens(int, const struct timespec *); <sys/stat.h>
			ret = futimens(va_arg(args,int), va_arg(args,const struct timespec *));
			break;
		/* No signature found in headers
		case SYS_kbind: // 86
			// int kbind(const struct __kbind *, size_t, int64_t);
			ret = kbind(va_arg(args,const struct __kbind *), va_arg(args,size_t), va_arg(args,int64_t));
			break;
		*/
		case SYS_clock_gettime: // 87
			// int clock_gettime(clockid_t, struct timespec *); <time.h>
			ret = clock_gettime(va_arg(args,clockid_t), va_arg(args,struct timespec *));
			break;
		case SYS_clock_settime: // 88
			// int clock_settime(clockid_t, const struct timespec *); <time.h>
			ret = clock_settime(va_arg(args,clockid_t), va_arg(args,const struct timespec *));
			break;
		case SYS_clock_getres: // 89
			// int clock_getres(clockid_t, struct timespec *); <time.h>
			ret = clock_getres(va_arg(args,clockid_t), va_arg(args,struct timespec *));
			break;
		case SYS_dup2: // 90
			// int dup2(int, int); <unistd.h>
			ret = dup2(va_arg(args,int), va_arg(args,int));
			break;
		case SYS_nanosleep: // 91
			// int nanosleep(const struct timespec *, struct timespec *); <time.h>
			ret = nanosleep(va_arg(args,const struct timespec *), va_arg(args,struct timespec *));
			break;
		case SYS_fcntl: // 92
			// int fcntl(int, int, ...); <fcntl.h>
			ret = fcntl(va_arg(args,int), va_arg(args,int), va_arg(args,void *));
			break;
		case SYS_accept4: // 93
			// int accept4(int, struct sockaddr *, socklen_t *, int); <sys/socket.h>
			ret = accept4(va_arg(args,int), va_arg(args,struct sockaddr *), va_arg(args,socklen_t *), va_arg(args,int));
			break;
		/* No signature found in headers
		case SYS___thrsleep: // 94
			// int __thrsleep(const volatile void *, clockid_t, const struct timespec *, void *, const int *);
			ret = __thrsleep(va_arg(args,const volatile void *), va_arg(args,clockid_t), va_arg(args,const struct timespec *), va_arg(args,void *), va_arg(args,const int *));
			break;
		*/
		case SYS_fsync: // 95
			// int fsync(int); <unistd.h>
			ret = fsync(va_arg(args,int));
			break;
		case SYS_setpriority: // 96
			// int setpriority(int, id_t, int); <sys/resource.h>
			ret = setpriority(va_arg(args,int), va_arg(args,id_t), va_arg(args,int));
			break;
		case SYS_socket: // 97
			// int socket(int, int, int); <sys/socket.h>
			ret = socket(va_arg(args,int), va_arg(args,int), va_arg(args,int));
			break;
		case SYS_connect: // 98
			// int connect(int, const struct sockaddr *, socklen_t); <sys/socket.h>
			ret = connect(va_arg(args,int), va_arg(args,const struct sockaddr *), va_arg(args,socklen_t));
			break;
		case SYS_getdents: // 99
			// int getdents(int, void *, size_t); <dirent.h>
			ret = getdents(va_arg(args,int), va_arg(args,void *), va_arg(args,size_t));
			break;
		case SYS_getpriority: // 100
			// int getpriority(int, id_t); <sys/resource.h>
			ret = getpriority(va_arg(args,int), va_arg(args,id_t));
			break;
		case SYS_pipe2: // 101
			// int pipe2(int *, int); <unistd.h>
			ret = pipe2(va_arg(args,int *), va_arg(args,int));
			break;
		case SYS_dup3: // 102
			// int dup3(int, int, int); <unistd.h>
			ret = dup3(va_arg(args,int), va_arg(args,int), va_arg(args,int));
			break;
		/* No signature found in headers
		case SYS_sigreturn: // 103
			// int sigreturn(struct sigcontext *);
			ret = sigreturn(va_arg(args,struct sigcontext *));
			break;
		*/
		case SYS_bind: // 104
			// int bind(int, const struct sockaddr *, socklen_t); <sys/socket.h>
			ret = bind(va_arg(args,int), va_arg(args,const struct sockaddr *), va_arg(args,socklen_t));
			break;
		case SYS_setsockopt: // 105
			// int setsockopt(int, int, int, const void *, socklen_t); <sys/socket.h>
			ret = setsockopt(va_arg(args,int), va_arg(args,int), va_arg(args,int), va_arg(args,const void *), va_arg(args,socklen_t));
			break;
		case SYS_listen: // 106
			// int listen(int, int); <sys/socket.h>
			ret = listen(va_arg(args,int), va_arg(args,int));
			break;
		case SYS_chflagsat: // 107
			// int chflagsat(int, const char *, u_int, int); <sys/stat.h>
			ret = chflagsat(va_arg(args,int), va_arg(args,const char *), va_arg(args,u_int), va_arg(args,int));
			break;
		case SYS_pledge: // 108
			// int pledge(const char *, const char *); <unistd.h>
			ret = pledge(va_arg(args,const char *), va_arg(args,const char *));
			break;
		case SYS_ppoll: // 109
			// int ppoll(struct pollfd *, u_int, const struct timespec *, const sigset_t *); <sys/poll.h>
			ret = ppoll(va_arg(args,struct pollfd *), va_arg(args,u_int), va_arg(args,const struct timespec *), va_arg(args,const sigset_t *));
			break;
		case SYS_pselect: // 110
			// int pselect(int, fd_set *, fd_set *, fd_set *, const struct timespec *, const sigset_t *); <sys/select.h>
			ret = pselect(va_arg(args,int), va_arg(args,fd_set *), va_arg(args,fd_set *), va_arg(args,fd_set *), va_arg(args,const struct timespec *), va_arg(args,const sigset_t *));
			break;
		/* Mismatched func: <signal.h> int sigsuspend(const sigset_t *);
		case SYS_sigsuspend: // 111
			// int sigsuspend(int);
			ret = sigsuspend(va_arg(args,int));
			break;
		*/
		/* No signature found in headers
		case SYS_sendsyslog: // 112
			// int sendsyslog(const char *, size_t, int);
			ret = sendsyslog(va_arg(args,const char *), va_arg(args,size_t), va_arg(args,int));
			break;
		*/
		case SYS_unveil: // 114
			// int unveil(const char *, const char *); <unistd.h>
			ret = unveil(va_arg(args,const char *), va_arg(args,const char *));
			break;
		/* No signature found in headers
		case SYS___realpath: // 115
			// int __realpath(const char *, char *);
			ret = __realpath(va_arg(args,const char *), va_arg(args,char *));
			break;
		*/
		case SYS_recvmmsg: // 116
			// int recvmmsg(int, struct mmsghdr *, unsigned int, int, struct timespec *); <sys/socket.h>
			ret = recvmmsg(va_arg(args,int), va_arg(args,struct mmsghdr *), va_arg(args,unsigned int), va_arg(args,int), va_arg(args,struct timespec *));
			break;
		case SYS_sendmmsg: // 117
			// int sendmmsg(int, struct mmsghdr *, unsigned int, int); <sys/socket.h>
			ret = sendmmsg(va_arg(args,int), va_arg(args,struct mmsghdr *), va_arg(args,unsigned int), va_arg(args,int));
			break;
		case SYS_getsockopt: // 118
			// int getsockopt(int, int, int, void *, socklen_t *); <sys/socket.h>
			ret = getsockopt(va_arg(args,int), va_arg(args,int), va_arg(args,int), va_arg(args,void *), va_arg(args,socklen_t *));
			break;
		case SYS_thrkill: // 119
			// int thrkill(pid_t, int, void *); <signal.h>
			ret = thrkill(va_arg(args,pid_t), va_arg(args,int), va_arg(args,void *));
			break;
		case SYS_readv: // 120
			// ssize_t readv(int, const struct iovec *, int); <sys/uio.h>
			ret = readv(va_arg(args,int), va_arg(args,const struct iovec *), va_arg(args,int));
			break;
		case SYS_writev: // 121
			// ssize_t writev(int, const struct iovec *, int); <sys/uio.h>
			ret = writev(va_arg(args,int), va_arg(args,const struct iovec *), va_arg(args,int));
			break;
		case SYS_kill: // 122
			// int kill(int, int); <signal.h>
			ret = kill(va_arg(args,int), va_arg(args,int));
			break;
		case SYS_fchown: // 123
			// int fchown(int, uid_t, gid_t); <unistd.h>
			ret = fchown(va_arg(args,int), va_arg(args,uid_t), va_arg(args,gid_t));
			break;
		case SYS_fchmod: // 124
			// int fchmod(int, mode_t); <sys/stat.h>
			ret = fchmod(va_arg(args,int), va_arg(args,mode_t));
			break;
		case SYS_setreuid: // 126
			// int setreuid(uid_t, uid_t); <unistd.h>
			ret = setreuid(va_arg(args,uid_t), va_arg(args,uid_t));
			break;
		case SYS_setregid: // 127
			// int setregid(gid_t, gid_t); <unistd.h>
			ret = setregid(va_arg(args,gid_t), va_arg(args,gid_t));
			break;
		case SYS_rename: // 128
			// int rename(const char *, const char *); <stdio.h>
			ret = rename(va_arg(args,const char *), va_arg(args,const char *));
			break;
		case SYS_flock: // 131
			// int flock(int, int); <fcntl.h>
			ret = flock(va_arg(args,int), va_arg(args,int));
			break;
		case SYS_mkfifo: // 132
			// int mkfifo(const char *, mode_t); <sys/stat.h>
			ret = mkfifo(va_arg(args,const char *), va_arg(args,mode_t));
			break;
		case SYS_sendto: // 133
			// ssize_t sendto(int, const void *, size_t, int, const struct sockaddr *, socklen_t); <sys/socket.h>
			ret = sendto(va_arg(args,int), va_arg(args,const void *), va_arg(args,size_t), va_arg(args,int), va_arg(args,const struct sockaddr *), va_arg(args,socklen_t));
			break;
		case SYS_shutdown: // 134
			// int shutdown(int, int); <sys/socket.h>
			ret = shutdown(va_arg(args,int), va_arg(args,int));
			break;
		case SYS_socketpair: // 135
			// int socketpair(int, int, int, int *); <sys/socket.h>
			ret = socketpair(va_arg(args,int), va_arg(args,int), va_arg(args,int), va_arg(args,int *));
			break;
		case SYS_mkdir: // 136
			// int mkdir(const char *, mode_t); <sys/stat.h>
			ret = mkdir(va_arg(args,const char *), va_arg(args,mode_t));
			break;
		case SYS_rmdir: // 137
			// int rmdir(const char *); <unistd.h>
			ret = rmdir(va_arg(args,const char *));
			break;
		case SYS_adjtime: // 140
			// int adjtime(const struct timeval *, struct timeval *); <sys/time.h>
			ret = adjtime(va_arg(args,const struct timeval *), va_arg(args,struct timeval *));
			break;
		case SYS_getlogin_r: // 141
			// int getlogin_r(char *, u_int); <unistd.h>
			ret = getlogin_r(va_arg(args,char *), va_arg(args,u_int));
			break;
		case SYS_getthrname: // 142
			// int getthrname(pid_t, char *, size_t); <unistd.h>
			ret = getthrname(va_arg(args,pid_t), va_arg(args,char *), va_arg(args,size_t));
			break;
		case SYS_setthrname: // 143
			// int setthrname(pid_t, const char *); <unistd.h>
			ret = setthrname(va_arg(args,pid_t), va_arg(args,const char *));
			break;
		/* No signature found in headers
		case SYS_pinsyscall: // 146
			// int pinsyscall(int, void *, size_t);
			ret = pinsyscall(va_arg(args,int), va_arg(args,void *), va_arg(args,size_t));
			break;
		*/
		case SYS_setsid: // 147
			// int setsid(void); <unistd.h>
			ret = setsid();
			break;
		case SYS_quotactl: // 148
			// int quotactl(const char *, int, int, char *); <unistd.h>
			ret = quotactl(va_arg(args,const char *), va_arg(args,int), va_arg(args,int), va_arg(args,char *));
			break;
		/* No signature found in headers
		case SYS_ypconnect: // 150
			// int ypconnect(int);
			ret = ypconnect(va_arg(args,int));
			break;
		*/
		case SYS_nfssvc: // 155
			// int nfssvc(int, void *); <unistd.h>
			ret = nfssvc(va_arg(args,int), va_arg(args,void *));
			break;
		case SYS_mimmutable: // 159
			// int mimmutable(void *, size_t); <sys/mman.h>
			ret = mimmutable(va_arg(args,void *), va_arg(args,size_t));
			break;
		case SYS_waitid: // 160
			// int waitid(int, id_t, siginfo_t *, int); <sys/wait.h>
			ret = waitid(va_arg(args,int), va_arg(args,id_t), va_arg(args,siginfo_t *), va_arg(args,int));
			break;
		case SYS_getfh: // 161
			// int getfh(const char *, fhandle_t *); <sys/mount.h>
			ret = getfh(va_arg(args,const char *), va_arg(args,fhandle_t *));
			break;
		/* No signature found in headers
		case SYS___tmpfd: // 164
			// int __tmpfd(int);
			ret = __tmpfd(va_arg(args,int));
			break;
		*/
		/* No signature found in headers
		case SYS_sysarch: // 165
			// int sysarch(int, void *);
			ret = sysarch(va_arg(args,int), va_arg(args,void *));
			break;
		*/
		case SYS_lseek: // 166
			// off_t lseek(int, off_t, int); <unistd.h>
			ret = lseek(va_arg(args,int), va_arg(args,off_t), va_arg(args,int));
			break;
		case SYS_truncate: // 167
			// int truncate(const char *, off_t); <unistd.h>
			ret = truncate(va_arg(args,const char *), va_arg(args,off_t));
			break;
		case SYS_ftruncate: // 168
			// int ftruncate(int, off_t); <unistd.h>
			ret = ftruncate(va_arg(args,int), va_arg(args,off_t));
			break;
		case SYS_pread: // 169
			// ssize_t pread(int, void *, size_t, off_t); <unistd.h>
			ret = pread(va_arg(args,int), va_arg(args,void *), va_arg(args,size_t), va_arg(args,off_t));
			break;
		case SYS_pwrite: // 170
			// ssize_t pwrite(int, const void *, size_t, off_t); <unistd.h>
			ret = pwrite(va_arg(args,int), va_arg(args,const void *), va_arg(args,size_t), va_arg(args,off_t));
			break;
		case SYS_preadv: // 171
			// ssize_t preadv(int, const struct iovec *, int, off_t); <sys/uio.h>
			ret = preadv(va_arg(args,int), va_arg(args,const struct iovec *), va_arg(args,int), va_arg(args,off_t));
			break;
		case SYS_pwritev: // 172
			// ssize_t pwritev(int, const struct iovec *, int, off_t); <sys/uio.h>
			ret = pwritev(va_arg(args,int), va_arg(args,const struct iovec *), va_arg(args,int), va_arg(args,off_t));
			break;
		case SYS_setgid: // 181
			// int setgid(gid_t); <unistd.h>
			ret = setgid(va_arg(args,gid_t));
			break;
		case SYS_setegid: // 182
			// int setegid(gid_t); <unistd.h>
			ret = setegid(va_arg(args,gid_t));
			break;
		case SYS_seteuid: // 183
			// int seteuid(uid_t); <unistd.h>
			ret = seteuid(va_arg(args,uid_t));
			break;
		case SYS_pathconf: // 191
			// long pathconf(const char *, int); <unistd.h>
			ret = pathconf(va_arg(args,const char *), va_arg(args,int));
			break;
		case SYS_fpathconf: // 192
			// long fpathconf(int, int); <unistd.h>
			ret = fpathconf(va_arg(args,int), va_arg(args,int));
			break;
		case SYS_swapctl: // 193
			// int swapctl(int, const void *, int); <unistd.h>
			ret = swapctl(va_arg(args,int), va_arg(args,const void *), va_arg(args,int));
			break;
		case SYS_getrlimit: // 194
			// int getrlimit(int, struct rlimit *); <sys/resource.h>
			ret = getrlimit(va_arg(args,int), va_arg(args,struct rlimit *));
			break;
		case SYS_setrlimit: // 195
			// int setrlimit(int, const struct rlimit *); <sys/resource.h>
			ret = setrlimit(va_arg(args,int), va_arg(args,const struct rlimit *));
			break;
		case SYS_sysctl: // 202
			// int sysctl(const int *, u_int, void *, size_t *, void *, size_t); <sys/sysctl.h>
			ret = sysctl(va_arg(args,const int *), va_arg(args,u_int), va_arg(args,void *), va_arg(args,size_t *), va_arg(args,void *), va_arg(args,size_t));
			break;
		case SYS_mlock: // 203
			// int mlock(const void *, size_t); <sys/mman.h>
			ret = mlock(va_arg(args,const void *), va_arg(args,size_t));
			break;
		case SYS_munlock: // 204
			// int munlock(const void *, size_t); <sys/mman.h>
			ret = munlock(va_arg(args,const void *), va_arg(args,size_t));
			break;
		case SYS_getpgid: // 207
			// pid_t getpgid(pid_t); <unistd.h>
			ret = getpgid(va_arg(args,pid_t));
			break;
		case SYS_utrace: // 209
			// int utrace(const char *, const void *, size_t); <sys/ktrace.h>
			ret = utrace(va_arg(args,const char *), va_arg(args,const void *), va_arg(args,size_t));
			break;
		case SYS_semget: // 221
			// int semget(key_t, int, int); <sys/sem.h>
			ret = semget(va_arg(args,key_t), va_arg(args,int), va_arg(args,int));
			break;
		case SYS_msgget: // 225
			// int msgget(key_t, int); <sys/msg.h>
			ret = msgget(va_arg(args,key_t), va_arg(args,int));
			break;
		case SYS_msgsnd: // 226
			// int msgsnd(int, const void *, size_t, int); <sys/msg.h>
			ret = msgsnd(va_arg(args,int), va_arg(args,const void *), va_arg(args,size_t), va_arg(args,int));
			break;
		case SYS_msgrcv: // 227
			// int msgrcv(int, void *, size_t, long, int); <sys/msg.h>
			ret = msgrcv(va_arg(args,int), va_arg(args,void *), va_arg(args,size_t), va_arg(args,long), va_arg(args,int));
			break;
		case SYS_shmat: // 228
			// void * shmat(int, const void *, int); <sys/shm.h>
			ret = 0; shmat(va_arg(args,int), va_arg(args,const void *), va_arg(args,int));
			break;
		case SYS_shmdt: // 230
			// int shmdt(const void *); <sys/shm.h>
			ret = shmdt(va_arg(args,const void *));
			break;
		case SYS_minherit: // 250
			// int minherit(void *, size_t, int); <sys/mman.h>
			ret = minherit(va_arg(args,void *), va_arg(args,size_t), va_arg(args,int));
			break;
		case SYS_poll: // 252
			// int poll(struct pollfd *, u_int, int); <sys/poll.h>
			ret = poll(va_arg(args,struct pollfd *), va_arg(args,u_int), va_arg(args,int));
			break;
		case SYS_issetugid: // 253
			// int issetugid(void); <unistd.h>
			ret = issetugid();
			break;
		case SYS_lchown: // 254
			// int lchown(const char *, uid_t, gid_t); <unistd.h>
			ret = lchown(va_arg(args,const char *), va_arg(args,uid_t), va_arg(args,gid_t));
			break;
		case SYS_getsid: // 255
			// pid_t getsid(pid_t); <unistd.h>
			ret = getsid(va_arg(args,pid_t));
			break;
		case SYS_msync: // 256
			// int msync(void *, size_t, int); <sys/mman.h>
			ret = msync(va_arg(args,void *), va_arg(args,size_t), va_arg(args,int));
			break;
		case SYS_pipe: // 263
			// int pipe(int *); <unistd.h>
			ret = pipe(va_arg(args,int *));
			break;
		case SYS_fhopen: // 264
			// int fhopen(const fhandle_t *, int); <sys/mount.h>
			ret = fhopen(va_arg(args,const fhandle_t *), va_arg(args,int));
			break;
		case SYS_kqueue: // 269
			// int kqueue(void); <sys/event.h>
			ret = kqueue();
			break;
		case SYS_mlockall: // 271
			// int mlockall(int); <sys/mman.h>
			ret = mlockall(va_arg(args,int));
			break;
		case SYS_munlockall: // 272
			// int munlockall(void); <sys/mman.h>
			ret = munlockall();
			break;
		case SYS_getresuid: // 281
			// int getresuid(uid_t *, uid_t *, uid_t *); <unistd.h>
			ret = getresuid(va_arg(args,uid_t *), va_arg(args,uid_t *), va_arg(args,uid_t *));
			break;
		case SYS_setresuid: // 282
			// int setresuid(uid_t, uid_t, uid_t); <unistd.h>
			ret = setresuid(va_arg(args,uid_t), va_arg(args,uid_t), va_arg(args,uid_t));
			break;
		case SYS_getresgid: // 283
			// int getresgid(gid_t *, gid_t *, gid_t *); <unistd.h>
			ret = getresgid(va_arg(args,gid_t *), va_arg(args,gid_t *), va_arg(args,gid_t *));
			break;
		case SYS_setresgid: // 284
			// int setresgid(gid_t, gid_t, gid_t); <unistd.h>
			ret = setresgid(va_arg(args,gid_t), va_arg(args,gid_t), va_arg(args,gid_t));
			break;
		case SYS_closefrom: // 287
			// int closefrom(int); <unistd.h>
			ret = closefrom(va_arg(args,int));
			break;
		case SYS_sigaltstack: // 288
			// int sigaltstack(const struct sigaltstack *, struct sigaltstack *); <signal.h>
			ret = sigaltstack(va_arg(args,const struct sigaltstack *), va_arg(args,struct sigaltstack *));
			break;
		case SYS_shmget: // 289
			// int shmget(key_t, size_t, int); <sys/shm.h>
			ret = shmget(va_arg(args,key_t), va_arg(args,size_t), va_arg(args,int));
			break;
		case SYS_semop: // 290
			// int semop(int, struct sembuf *, size_t); <sys/sem.h>
			ret = semop(va_arg(args,int), va_arg(args,struct sembuf *), va_arg(args,size_t));
			break;
		case SYS_fhstat: // 294
			// int fhstat(const fhandle_t *, struct stat *); <sys/mount.h>
			ret = fhstat(va_arg(args,const fhandle_t *), va_arg(args,struct stat *));
			break;
		case SYS___semctl: // 295
			// int __semctl(int, int, int, union semun *); <sys/sem.h>
			ret = __semctl(va_arg(args,int), va_arg(args,int), va_arg(args,int), va_arg(args,union semun *));
			break;
		case SYS_shmctl: // 296
			// int shmctl(int, int, struct shmid_ds *); <sys/shm.h>
			ret = shmctl(va_arg(args,int), va_arg(args,int), va_arg(args,struct shmid_ds *));
			break;
		case SYS_msgctl: // 297
			// int msgctl(int, int, struct msqid_ds *); <sys/msg.h>
			ret = msgctl(va_arg(args,int), va_arg(args,int), va_arg(args,struct msqid_ds *));
			break;
		case SYS_sched_yield: // 298
			// int sched_yield(void); <sched.h>
			ret = sched_yield();
			break;
		case SYS_getthrid: // 299
			// pid_t getthrid(void); <unistd.h>
			ret = getthrid();
			break;
		/* No signature found in headers
		case SYS___thrwakeup: // 301
			// int __thrwakeup(const volatile void *, int);
			ret = __thrwakeup(va_arg(args,const volatile void *), va_arg(args,int));
			break;
		*/
		/* No signature found in headers
		case SYS___threxit: // 302
			// void __threxit(pid_t *);
			ret = 0; __threxit(va_arg(args,pid_t *));
			break;
		*/
		/* No signature found in headers
		case SYS___thrsigdivert: // 303
			// int __thrsigdivert(sigset_t, siginfo_t *, const struct timespec *);
			ret = __thrsigdivert(va_arg(args,sigset_t), va_arg(args,siginfo_t *), va_arg(args,const struct timespec *));
			break;
		*/
		/* No signature found in headers
		case SYS___getcwd: // 304
			// int __getcwd(char *, size_t);
			ret = __getcwd(va_arg(args,char *), va_arg(args,size_t));
			break;
		*/
		case SYS_adjfreq: // 305
			// int adjfreq(const int64_t *, int64_t *); <sys/time.h>
			ret = adjfreq(va_arg(args,const int64_t *), va_arg(args,int64_t *));
			break;
		case SYS_setrtable: // 310
			// int setrtable(int); <sys/socket.h>
			ret = setrtable(va_arg(args,int));
			break;
		case SYS_getrtable: // 311
			// int getrtable(void); <sys/socket.h>
			ret = getrtable();
			break;
		case SYS_faccessat: // 313
			// int faccessat(int, const char *, int, int); <unistd.h>
			ret = faccessat(va_arg(args,int), va_arg(args,const char *), va_arg(args,int), va_arg(args,int));
			break;
		case SYS_fchmodat: // 314
			// int fchmodat(int, const char *, mode_t, int); <sys/stat.h>
			ret = fchmodat(va_arg(args,int), va_arg(args,const char *), va_arg(args,mode_t), va_arg(args,int));
			break;
		case SYS_fchownat: // 315
			// int fchownat(int, const char *, uid_t, gid_t, int); <unistd.h>
			ret = fchownat(va_arg(args,int), va_arg(args,const char *), va_arg(args,uid_t), va_arg(args,gid_t), va_arg(args,int));
			break;
		case SYS_linkat: // 317
			// int linkat(int, const char *, int, const char *, int); <unistd.h>
			ret = linkat(va_arg(args,int), va_arg(args,const char *), va_arg(args,int), va_arg(args,const char *), va_arg(args,int));
			break;
		case SYS_mkdirat: // 318
			// int mkdirat(int, const char *, mode_t); <sys/stat.h>
			ret = mkdirat(va_arg(args,int), va_arg(args,const char *), va_arg(args,mode_t));
			break;
		case SYS_mkfifoat: // 319
			// int mkfifoat(int, const char *, mode_t); <sys/stat.h>
			ret = mkfifoat(va_arg(args,int), va_arg(args,const char *), va_arg(args,mode_t));
			break;
		case SYS_mknodat: // 320
			// int mknodat(int, const char *, mode_t, dev_t); <sys/stat.h>
			ret = mknodat(va_arg(args,int), va_arg(args,const char *), va_arg(args,mode_t), va_arg(args,dev_t));
			break;
		case SYS_openat: // 321
			// int openat(int, const char *, int, ...); <fcntl.h>
			ret = openat(va_arg(args,int), va_arg(args,const char *), va_arg(args,int), va_arg(args,mode_t));
			break;
		case SYS_readlinkat: // 322
			// ssize_t readlinkat(int, const char *, char *, size_t); <unistd.h>
			ret = readlinkat(va_arg(args,int), va_arg(args,const char *), va_arg(args,char *), va_arg(args,size_t));
			break;
		case SYS_renameat: // 323
			// int renameat(int, const char *, int, const char *); <stdio.h>
			ret = renameat(va_arg(args,int), va_arg(args,const char *), va_arg(args,int), va_arg(args,const char *));
			break;
		case SYS_symlinkat: // 324
			// int symlinkat(const char *, int, const char *); <unistd.h>
			ret = symlinkat(va_arg(args,const char *), va_arg(args,int), va_arg(args,const char *));
			break;
		case SYS_unlinkat: // 325
			// int unlinkat(int, const char *, int); <unistd.h>
			ret = unlinkat(va_arg(args,int), va_arg(args,const char *), va_arg(args,int));
			break;
		case SYS___set_tcb: // 329
			// void __set_tcb(void *); <tib.h>
			ret = 0; __set_tcb(va_arg(args,void *));
			break;
		case SYS___get_tcb: // 330
			// void * __get_tcb(void); <tib.h>
			ret = 0; __get_tcb();
			break;
	}
	va_end(args);

	return ret;
}
