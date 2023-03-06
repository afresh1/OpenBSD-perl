#include <sys/syscall.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/socket.h>
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
#include <dirent.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <tib.h>
#include <time.h>
#include <unistd.h>

long
syscall_emulator(int syscall, ...) {
	long ret = 0;
	va_list args;
	va_start(args, syscall);

	switch(syscall) {
	/* Indirect syscalls not supported
	 *case SYS_syscall:
	 *	ret = syscall(int, ...);
	 *	break;
	 */
	case SYS_exit:
		exit(va_arg(args, int)); // rval
		break;
	case SYS_fork:
		ret = fork();
		break;
	case SYS_read:
		{
		int fd = va_arg(args, int);
		void * buf = va_arg(args, void *);
		size_t nbyte = va_arg(args, size_t);
		ret = read(fd, buf, nbyte);
		}
		break;
	case SYS_write:
		{
		int fd = va_arg(args, int);
		const void * buf = va_arg(args, const void *);
		size_t nbyte = va_arg(args, size_t);
		ret = write(fd, buf, nbyte);
		}
		break;
	case SYS_open:
		{
		const char * path = va_arg(args, const char *);
		int flags = va_arg(args, int);
		mode_t mode = va_arg(args, mode_t);
		ret = open(path, flags, mode);
		}
		break;
	case SYS_close:
		ret = close(va_arg(args, int)); // fd
		break;
	case SYS_getentropy:
		{
		void * buf = va_arg(args, void *);
		size_t nbyte = va_arg(args, size_t);
		ret = getentropy(buf, nbyte);
		}
		break;
	/* No signature found in headers
	 *case SYS___tfork:
	 *	{
	 *	const struct __tfork * param = va_arg(args, const struct __tfork *);
	 *	size_t psize = va_arg(args, size_t);
	 *	ret = __tfork(param, psize);
	 *	}
	 *	break;
	 */
	case SYS_link:
		{
		const char * path = va_arg(args, const char *);
		const char * _link = va_arg(args, const char *);
		ret = link(path, _link);
		}
		break;
	case SYS_unlink:
		ret = unlink(va_arg(args, const char *)); // path
		break;
	case SYS_wait4:
		{
		pid_t pid = va_arg(args, pid_t);
		int * status = va_arg(args, int *);
		int options = va_arg(args, int);
		struct rusage * rusage = va_arg(args, struct rusage *);
		ret = wait4(pid, status, options, rusage);
		}
		break;
	case SYS_chdir:
		ret = chdir(va_arg(args, const char *)); // path
		break;
	case SYS_fchdir:
		ret = fchdir(va_arg(args, int)); // fd
		break;
	case SYS_mknod:
		{
		const char * path = va_arg(args, const char *);
		mode_t mode = va_arg(args, mode_t);
		dev_t dev = va_arg(args, dev_t);
		ret = mknod(path, mode, dev);
		}
		break;
	case SYS_chmod:
		{
		const char * path = va_arg(args, const char *);
		mode_t mode = va_arg(args, mode_t);
		ret = chmod(path, mode);
		}
		break;
	case SYS_chown:
		{
		const char * path = va_arg(args, const char *);
		uid_t uid = va_arg(args, uid_t);
		gid_t gid = va_arg(args, gid_t);
		ret = chown(path, uid, gid);
		}
		break;
	/* No signature found in headers
	 *case SYS_break:
	 *	ret = break(char *);
	 *	break;
	 */
	case SYS_getdtablecount:
		ret = getdtablecount();
		break;
	case SYS_getrusage:
		{
		int who = va_arg(args, int);
		struct rusage * rusage = va_arg(args, struct rusage *);
		ret = getrusage(who, rusage);
		}
		break;
	case SYS_getpid:
		ret = getpid();
		break;
	case SYS_mount:
		{
		const char * type = va_arg(args, const char *);
		const char * path = va_arg(args, const char *);
		int flags = va_arg(args, int);
		void * data = va_arg(args, void *);
		ret = mount(type, path, flags, data);
		}
		break;
	case SYS_unmount:
		{
		const char * path = va_arg(args, const char *);
		int flags = va_arg(args, int);
		ret = unmount(path, flags);
		}
		break;
	case SYS_setuid:
		ret = setuid(va_arg(args, uid_t)); // uid
		break;
	case SYS_getuid:
		ret = getuid();
		break;
	case SYS_geteuid:
		ret = geteuid();
		break;
	case SYS_ptrace:
		{
		int req = va_arg(args, int);
		pid_t pid = va_arg(args, pid_t);
		caddr_t addr = va_arg(args, caddr_t);
		int data = va_arg(args, int);
		ret = ptrace(req, pid, addr, data);
		}
		break;
	case SYS_recvmsg:
		{
		int s = va_arg(args, int);
		struct msghdr * msg = va_arg(args, struct msghdr *);
		int flags = va_arg(args, int);
		ret = recvmsg(s, msg, flags);
		}
		break;
	case SYS_sendmsg:
		{
		int s = va_arg(args, int);
		const struct msghdr * msg = va_arg(args, const struct msghdr *);
		int flags = va_arg(args, int);
		ret = sendmsg(s, msg, flags);
		}
		break;
	case SYS_recvfrom:
		{
		int s = va_arg(args, int);
		void * buf = va_arg(args, void *);
		size_t len = va_arg(args, size_t);
		int flags = va_arg(args, int);
		struct sockaddr * from = va_arg(args, struct sockaddr *);
		socklen_t * fromlenaddr = va_arg(args, socklen_t *);
		ret = recvfrom(s, buf, len, flags, from, fromlenaddr);
		}
		break;
	case SYS_accept:
		{
		int s = va_arg(args, int);
		struct sockaddr * name = va_arg(args, struct sockaddr *);
		socklen_t * anamelen = va_arg(args, socklen_t *);
		ret = accept(s, name, anamelen);
		}
		break;
	case SYS_getpeername:
		{
		int fdes = va_arg(args, int);
		struct sockaddr * asa = va_arg(args, struct sockaddr *);
		socklen_t * alen = va_arg(args, socklen_t *);
		ret = getpeername(fdes, asa, alen);
		}
		break;
	case SYS_getsockname:
		{
		int fdes = va_arg(args, int);
		struct sockaddr * asa = va_arg(args, struct sockaddr *);
		socklen_t * alen = va_arg(args, socklen_t *);
		ret = getsockname(fdes, asa, alen);
		}
		break;
	case SYS_access:
		{
		const char * path = va_arg(args, const char *);
		int amode = va_arg(args, int);
		ret = access(path, amode);
		}
		break;
	case SYS_chflags:
		{
		const char * path = va_arg(args, const char *);
		u_int flags = va_arg(args, u_int);
		ret = chflags(path, flags);
		}
		break;
	case SYS_fchflags:
		{
		int fd = va_arg(args, int);
		u_int flags = va_arg(args, u_int);
		ret = fchflags(fd, flags);
		}
		break;
	case SYS_sync:
		sync();
		break;
	/* No signature found in headers
	 *case SYS_msyscall:
	 *	{
	 *	void * addr = va_arg(args, void *);
	 *	size_t len = va_arg(args, size_t);
	 *	ret = msyscall(addr, len);
	 *	}
	 *	break;
	 */
	case SYS_stat:
		{
		const char * path = va_arg(args, const char *);
		struct stat * ub = va_arg(args, struct stat *);
		ret = stat(path, ub);
		}
		break;
	case SYS_getppid:
		ret = getppid();
		break;
	case SYS_lstat:
		{
		const char * path = va_arg(args, const char *);
		struct stat * ub = va_arg(args, struct stat *);
		ret = lstat(path, ub);
		}
		break;
	case SYS_dup:
		ret = dup(va_arg(args, int)); // fd
		break;
	case SYS_fstatat:
		{
		int fd = va_arg(args, int);
		const char * path = va_arg(args, const char *);
		struct stat * buf = va_arg(args, struct stat *);
		int flag = va_arg(args, int);
		ret = fstatat(fd, path, buf, flag);
		}
		break;
	case SYS_getegid:
		ret = getegid();
		break;
	case SYS_profil:
		{
		caddr_t samples = va_arg(args, caddr_t);
		size_t size = va_arg(args, size_t);
		u_long offset = va_arg(args, u_long);
		u_int scale = va_arg(args, u_int);
		ret = profil(samples, size, offset, scale);
		}
		break;
	case SYS_ktrace:
		{
		const char * fname = va_arg(args, const char *);
		int ops = va_arg(args, int);
		int facs = va_arg(args, int);
		pid_t pid = va_arg(args, pid_t);
		ret = ktrace(fname, ops, facs, pid);
		}
		break;
	case SYS_sigaction:
		{
		int signum = va_arg(args, int);
		const struct sigaction * nsa = va_arg(args, const struct sigaction *);
		struct sigaction * osa = va_arg(args, struct sigaction *);
		ret = sigaction(signum, nsa, osa);
		}
		break;
	case SYS_getgid:
		ret = getgid();
		break;
	/* Mismatched func: int sigprocmask(int, const sigset_t *, sigset_t *); <signal.h>
	 *                  int sigprocmask(int, sigset_t); <sys/syscall.h>
	 *case SYS_sigprocmask:
	 *	{
	 *	int how = va_arg(args, int);
	 *	sigset_t mask = va_arg(args, sigset_t);
	 *	ret = sigprocmask(how, mask);
	 *	}
	 *	break;
	 */
	case SYS_mmap:
		{
		void * addr = va_arg(args, void *);
		size_t len = va_arg(args, size_t);
		int prot = va_arg(args, int);
		int flags = va_arg(args, int);
		int fd = va_arg(args, int);
		off_t pos = va_arg(args, off_t);
		ret = (long)mmap(addr, len, prot, flags, fd, pos);
		}
		break;
	case SYS_setlogin:
		ret = setlogin(va_arg(args, const char *)); // namebuf
		break;
	case SYS_acct:
		ret = acct(va_arg(args, const char *)); // path
		break;
	/* Mismatched func: int sigpending(sigset_t *); <signal.h>
	 *                  int sigpending(void); <sys/syscall.h>
	 *case SYS_sigpending:
	 *	ret = sigpending();
	 *	break;
	 */
	case SYS_fstat:
		{
		int fd = va_arg(args, int);
		struct stat * sb = va_arg(args, struct stat *);
		ret = fstat(fd, sb);
		}
		break;
	case SYS_ioctl:
		{
		int fd = va_arg(args, int);
		u_long com = va_arg(args, u_long);
		void * data = va_arg(args, void *);
		ret = ioctl(fd, com, data);
		}
		break;
	case SYS_reboot:
		ret = reboot(va_arg(args, int)); // opt
		break;
	case SYS_revoke:
		ret = revoke(va_arg(args, const char *)); // path
		break;
	case SYS_symlink:
		{
		const char * path = va_arg(args, const char *);
		const char * link = va_arg(args, const char *);
		ret = symlink(path, link);
		}
		break;
	case SYS_readlink:
		{
		const char * path = va_arg(args, const char *);
		char * buf = va_arg(args, char *);
		size_t count = va_arg(args, size_t);
		ret = readlink(path, buf, count);
		}
		break;
	case SYS_execve:
		{
		const char * path = va_arg(args, const char *);
		char *const * argp = va_arg(args, char *const *);
		char *const * envp = va_arg(args, char *const *);
		ret = execve(path, argp, envp);
		}
		break;
	case SYS_umask:
		ret = umask(va_arg(args, mode_t)); // newmask
		break;
	case SYS_chroot:
		ret = chroot(va_arg(args, const char *)); // path
		break;
	case SYS_getfsstat:
		{
		struct statfs * buf = va_arg(args, struct statfs *);
		size_t bufsize = va_arg(args, size_t);
		int flags = va_arg(args, int);
		ret = getfsstat(buf, bufsize, flags);
		}
		break;
	case SYS_statfs:
		{
		const char * path = va_arg(args, const char *);
		struct statfs * buf = va_arg(args, struct statfs *);
		ret = statfs(path, buf);
		}
		break;
	case SYS_fstatfs:
		{
		int fd = va_arg(args, int);
		struct statfs * buf = va_arg(args, struct statfs *);
		ret = fstatfs(fd, buf);
		}
		break;
	case SYS_fhstatfs:
		{
		const fhandle_t * fhp = va_arg(args, const fhandle_t *);
		struct statfs * buf = va_arg(args, struct statfs *);
		ret = fhstatfs(fhp, buf);
		}
		break;
	case SYS_vfork:
		ret = vfork();
		break;
	case SYS_gettimeofday:
		{
		struct timeval * tp = va_arg(args, struct timeval *);
		struct timezone * tzp = va_arg(args, struct timezone *);
		ret = gettimeofday(tp, tzp);
		}
		break;
	case SYS_settimeofday:
		{
		const struct timeval * tv = va_arg(args, const struct timeval *);
		const struct timezone * tzp = va_arg(args, const struct timezone *);
		ret = settimeofday(tv, tzp);
		}
		break;
	case SYS_setitimer:
		{
		int which = va_arg(args, int);
		const struct itimerval * itv = va_arg(args, const struct itimerval *);
		struct itimerval * oitv = va_arg(args, struct itimerval *);
		ret = setitimer(which, itv, oitv);
		}
		break;
	case SYS_getitimer:
		{
		int which = va_arg(args, int);
		struct itimerval * itv = va_arg(args, struct itimerval *);
		ret = getitimer(which, itv);
		}
		break;
	case SYS_select:
		{
		int nd = va_arg(args, int);
		fd_set * in = va_arg(args, fd_set *);
		fd_set * ou = va_arg(args, fd_set *);
		fd_set * ex = va_arg(args, fd_set *);
		struct timeval * tv = va_arg(args, struct timeval *);
		ret = select(nd, in, ou, ex, tv);
		}
		break;
	case SYS_kevent:
		{
		int fd = va_arg(args, int);
		const struct kevent * changelist = va_arg(args, const struct kevent *);
		int nchanges = va_arg(args, int);
		struct kevent * eventlist = va_arg(args, struct kevent *);
		int nevents = va_arg(args, int);
		const struct timespec * timeout = va_arg(args, const struct timespec *);
		ret = kevent(fd, changelist, nchanges, eventlist, nevents, timeout);
		}
		break;
	case SYS_munmap:
		{
		void * addr = va_arg(args, void *);
		size_t len = va_arg(args, size_t);
		ret = munmap(addr, len);
		}
		break;
	case SYS_mprotect:
		{
		void * addr = va_arg(args, void *);
		size_t len = va_arg(args, size_t);
		int prot = va_arg(args, int);
		ret = mprotect(addr, len, prot);
		}
		break;
	case SYS_madvise:
		{
		void * addr = va_arg(args, void *);
		size_t len = va_arg(args, size_t);
		int behav = va_arg(args, int);
		ret = madvise(addr, len, behav);
		}
		break;
	case SYS_utimes:
		{
		const char * path = va_arg(args, const char *);
		const struct timeval * tptr = va_arg(args, const struct timeval *);
		ret = utimes(path, tptr);
		}
		break;
	case SYS_futimes:
		{
		int fd = va_arg(args, int);
		const struct timeval * tptr = va_arg(args, const struct timeval *);
		ret = futimes(fd, tptr);
		}
		break;
	case SYS_mquery:
		{
		void * addr = va_arg(args, void *);
		size_t len = va_arg(args, size_t);
		int prot = va_arg(args, int);
		int flags = va_arg(args, int);
		int fd = va_arg(args, int);
		off_t pos = va_arg(args, off_t);
		ret = (long)mquery(addr, len, prot, flags, fd, pos);
		}
		break;
	case SYS_getgroups:
		{
		int gidsetsize = va_arg(args, int);
		gid_t * gidset = va_arg(args, gid_t *);
		ret = getgroups(gidsetsize, gidset);
		}
		break;
	case SYS_setgroups:
		{
		int gidsetsize = va_arg(args, int);
		const gid_t * gidset = va_arg(args, const gid_t *);
		ret = setgroups(gidsetsize, gidset);
		}
		break;
	case SYS_getpgrp:
		ret = getpgrp();
		break;
	case SYS_setpgid:
		{
		pid_t pid = va_arg(args, pid_t);
		pid_t pgid = va_arg(args, pid_t);
		ret = setpgid(pid, pgid);
		}
		break;
	case SYS_futex:
		{
		uint32_t * f = va_arg(args, uint32_t *);
		int op = va_arg(args, int);
		int val = va_arg(args, int);
		const struct timespec * timeout = va_arg(args, const struct timespec *);
		uint32_t * g = va_arg(args, uint32_t *);
		ret = futex(f, op, val, timeout, g);
		}
		break;
	case SYS_utimensat:
		{
		int fd = va_arg(args, int);
		const char * path = va_arg(args, const char *);
		const struct timespec * times = va_arg(args, const struct timespec *);
		int flag = va_arg(args, int);
		ret = utimensat(fd, path, times, flag);
		}
		break;
	case SYS_futimens:
		{
		int fd = va_arg(args, int);
		const struct timespec * times = va_arg(args, const struct timespec *);
		ret = futimens(fd, times);
		}
		break;
	/* No signature found in headers
	 *case SYS_kbind:
	 *	{
	 *	const struct __kbind * param = va_arg(args, const struct __kbind *);
	 *	size_t psize = va_arg(args, size_t);
	 *	int64_t proc_cookie = va_arg(args, int64_t);
	 *	ret = kbind(param, psize, proc_cookie);
	 *	}
	 *	break;
	 */
	case SYS_clock_gettime:
		{
		clockid_t clock_id = va_arg(args, clockid_t);
		struct timespec * tp = va_arg(args, struct timespec *);
		ret = clock_gettime(clock_id, tp);
		}
		break;
	case SYS_clock_settime:
		{
		clockid_t clock_id = va_arg(args, clockid_t);
		const struct timespec * tp = va_arg(args, const struct timespec *);
		ret = clock_settime(clock_id, tp);
		}
		break;
	case SYS_clock_getres:
		{
		clockid_t clock_id = va_arg(args, clockid_t);
		struct timespec * tp = va_arg(args, struct timespec *);
		ret = clock_getres(clock_id, tp);
		}
		break;
	case SYS_dup2:
		{
		int from = va_arg(args, int);
		int to = va_arg(args, int);
		ret = dup2(from, to);
		}
		break;
	case SYS_nanosleep:
		{
		const struct timespec * rqtp = va_arg(args, const struct timespec *);
		struct timespec * rmtp = va_arg(args, struct timespec *);
		ret = nanosleep(rqtp, rmtp);
		}
		break;
	case SYS_fcntl:
		{
		int fd = va_arg(args, int);
		int cmd = va_arg(args, int);
		void * arg = va_arg(args, void *);
		ret = fcntl(fd, cmd, arg);
		}
		break;
	case SYS_accept4:
		{
		int s = va_arg(args, int);
		struct sockaddr * name = va_arg(args, struct sockaddr *);
		socklen_t * anamelen = va_arg(args, socklen_t *);
		int flags = va_arg(args, int);
		ret = accept4(s, name, anamelen, flags);
		}
		break;
	/* No signature found in headers
	 *case SYS___thrsleep:
	 *	{
	 *	const volatile void * ident = va_arg(args, const volatile void *);
	 *	clockid_t clock_id = va_arg(args, clockid_t);
	 *	const struct timespec * tp = va_arg(args, const struct timespec *);
	 *	void * lock = va_arg(args, void *);
	 *	const int * abort = va_arg(args, const int *);
	 *	ret = __thrsleep(ident, clock_id, tp, lock, abort);
	 *	}
	 *	break;
	 */
	case SYS_fsync:
		ret = fsync(va_arg(args, int)); // fd
		break;
	case SYS_setpriority:
		{
		int which = va_arg(args, int);
		id_t who = va_arg(args, id_t);
		int prio = va_arg(args, int);
		ret = setpriority(which, who, prio);
		}
		break;
	case SYS_socket:
		{
		int domain = va_arg(args, int);
		int type = va_arg(args, int);
		int protocol = va_arg(args, int);
		ret = socket(domain, type, protocol);
		}
		break;
	case SYS_connect:
		{
		int s = va_arg(args, int);
		const struct sockaddr * name = va_arg(args, const struct sockaddr *);
		socklen_t namelen = va_arg(args, socklen_t);
		ret = connect(s, name, namelen);
		}
		break;
	case SYS_getdents:
		{
		int fd = va_arg(args, int);
		void * buf = va_arg(args, void *);
		size_t buflen = va_arg(args, size_t);
		ret = getdents(fd, buf, buflen);
		}
		break;
	case SYS_getpriority:
		{
		int which = va_arg(args, int);
		id_t who = va_arg(args, id_t);
		ret = getpriority(which, who);
		}
		break;
	case SYS_pipe2:
		{
		int * fdp = va_arg(args, int *);
		int flags = va_arg(args, int);
		ret = pipe2(fdp, flags);
		}
		break;
	case SYS_dup3:
		{
		int from = va_arg(args, int);
		int to = va_arg(args, int);
		int flags = va_arg(args, int);
		ret = dup3(from, to, flags);
		}
		break;
	/* No signature found in headers
	 *case SYS_sigreturn:
	 *	ret = sigreturn(va_arg(args, struct sigcontext *)); // sigcntxp
	 *	break;
	 */
	case SYS_bind:
		{
		int s = va_arg(args, int);
		const struct sockaddr * name = va_arg(args, const struct sockaddr *);
		socklen_t namelen = va_arg(args, socklen_t);
		ret = bind(s, name, namelen);
		}
		break;
	case SYS_setsockopt:
		{
		int s = va_arg(args, int);
		int level = va_arg(args, int);
		int name = va_arg(args, int);
		const void * val = va_arg(args, const void *);
		socklen_t valsize = va_arg(args, socklen_t);
		ret = setsockopt(s, level, name, val, valsize);
		}
		break;
	case SYS_listen:
		{
		int s = va_arg(args, int);
		int backlog = va_arg(args, int);
		ret = listen(s, backlog);
		}
		break;
	case SYS_chflagsat:
		{
		int fd = va_arg(args, int);
		const char * path = va_arg(args, const char *);
		u_int flags = va_arg(args, u_int);
		int atflags = va_arg(args, int);
		ret = chflagsat(fd, path, flags, atflags);
		}
		break;
	case SYS_pledge:
		{
		const char * promises = va_arg(args, const char *);
		const char * execpromises = va_arg(args, const char *);
		ret = pledge(promises, execpromises);
		}
		break;
	case SYS_ppoll:
		{
		struct pollfd * fds = va_arg(args, struct pollfd *);
		u_int nfds = va_arg(args, u_int);
		const struct timespec * ts = va_arg(args, const struct timespec *);
		const sigset_t * mask = va_arg(args, const sigset_t *);
		ret = ppoll(fds, nfds, ts, mask);
		}
		break;
	case SYS_pselect:
		{
		int nd = va_arg(args, int);
		fd_set * in = va_arg(args, fd_set *);
		fd_set * ou = va_arg(args, fd_set *);
		fd_set * ex = va_arg(args, fd_set *);
		const struct timespec * ts = va_arg(args, const struct timespec *);
		const sigset_t * mask = va_arg(args, const sigset_t *);
		ret = pselect(nd, in, ou, ex, ts, mask);
		}
		break;
	/* Mismatched func: int sigsuspend(const sigset_t *); <signal.h>
	 *                  int sigsuspend(int); <sys/syscall.h>
	 *case SYS_sigsuspend:
	 *	ret = sigsuspend(va_arg(args, int)); // mask
	 *	break;
	 */
	/* No signature found in headers
	 *case SYS_sendsyslog:
	 *	{
	 *	const char * buf = va_arg(args, const char *);
	 *	size_t nbyte = va_arg(args, size_t);
	 *	int flags = va_arg(args, int);
	 *	ret = sendsyslog(buf, nbyte, flags);
	 *	}
	 *	break;
	 */
	case SYS_unveil:
		{
		const char * path = va_arg(args, const char *);
		const char * permissions = va_arg(args, const char *);
		ret = unveil(path, permissions);
		}
		break;
	/* No signature found in headers
	 *case SYS___realpath:
	 *	{
	 *	const char * pathname = va_arg(args, const char *);
	 *	char * resolved = va_arg(args, char *);
	 *	ret = __realpath(pathname, resolved);
	 *	}
	 *	break;
	 */
	case SYS_recvmmsg:
		{
		int s = va_arg(args, int);
		struct mmsghdr * mmsg = va_arg(args, struct mmsghdr *);
		unsigned int vlen = va_arg(args, unsigned int);
		int flags = va_arg(args, int);
		struct timespec * timeout = va_arg(args, struct timespec *);
		ret = recvmmsg(s, mmsg, vlen, flags, timeout);
		}
		break;
	case SYS_sendmmsg:
		{
		int s = va_arg(args, int);
		struct mmsghdr * mmsg = va_arg(args, struct mmsghdr *);
		unsigned int vlen = va_arg(args, unsigned int);
		int flags = va_arg(args, int);
		ret = sendmmsg(s, mmsg, vlen, flags);
		}
		break;
	case SYS_getsockopt:
		{
		int s = va_arg(args, int);
		int level = va_arg(args, int);
		int name = va_arg(args, int);
		void * val = va_arg(args, void *);
		socklen_t * avalsize = va_arg(args, socklen_t *);
		ret = getsockopt(s, level, name, val, avalsize);
		}
		break;
	case SYS_thrkill:
		{
		pid_t tid = va_arg(args, pid_t);
		int signum = va_arg(args, int);
		void * tcb = va_arg(args, void *);
		ret = thrkill(tid, signum, tcb);
		}
		break;
	case SYS_readv:
		{
		int fd = va_arg(args, int);
		const struct iovec * iovp = va_arg(args, const struct iovec *);
		int iovcnt = va_arg(args, int);
		ret = readv(fd, iovp, iovcnt);
		}
		break;
	case SYS_writev:
		{
		int fd = va_arg(args, int);
		const struct iovec * iovp = va_arg(args, const struct iovec *);
		int iovcnt = va_arg(args, int);
		ret = writev(fd, iovp, iovcnt);
		}
		break;
	case SYS_kill:
		{
		int pid = va_arg(args, int);
		int signum = va_arg(args, int);
		ret = kill(pid, signum);
		}
		break;
	case SYS_fchown:
		{
		int fd = va_arg(args, int);
		uid_t uid = va_arg(args, uid_t);
		gid_t gid = va_arg(args, gid_t);
		ret = fchown(fd, uid, gid);
		}
		break;
	case SYS_fchmod:
		{
		int fd = va_arg(args, int);
		mode_t mode = va_arg(args, mode_t);
		ret = fchmod(fd, mode);
		}
		break;
	case SYS_setreuid:
		{
		uid_t ruid = va_arg(args, uid_t);
		uid_t euid = va_arg(args, uid_t);
		ret = setreuid(ruid, euid);
		}
		break;
	case SYS_setregid:
		{
		gid_t rgid = va_arg(args, gid_t);
		gid_t egid = va_arg(args, gid_t);
		ret = setregid(rgid, egid);
		}
		break;
	case SYS_rename:
		{
		const char * from = va_arg(args, const char *);
		const char * to = va_arg(args, const char *);
		ret = rename(from, to);
		}
		break;
	case SYS_flock:
		{
		int fd = va_arg(args, int);
		int how = va_arg(args, int);
		ret = flock(fd, how);
		}
		break;
	case SYS_mkfifo:
		{
		const char * path = va_arg(args, const char *);
		mode_t mode = va_arg(args, mode_t);
		ret = mkfifo(path, mode);
		}
		break;
	case SYS_sendto:
		{
		int s = va_arg(args, int);
		const void * buf = va_arg(args, const void *);
		size_t len = va_arg(args, size_t);
		int flags = va_arg(args, int);
		const struct sockaddr * to = va_arg(args, const struct sockaddr *);
		socklen_t tolen = va_arg(args, socklen_t);
		ret = sendto(s, buf, len, flags, to, tolen);
		}
		break;
	case SYS_shutdown:
		{
		int s = va_arg(args, int);
		int how = va_arg(args, int);
		ret = shutdown(s, how);
		}
		break;
	case SYS_socketpair:
		{
		int domain = va_arg(args, int);
		int type = va_arg(args, int);
		int protocol = va_arg(args, int);
		int * rsv = va_arg(args, int *);
		ret = socketpair(domain, type, protocol, rsv);
		}
		break;
	case SYS_mkdir:
		{
		const char * path = va_arg(args, const char *);
		mode_t mode = va_arg(args, mode_t);
		ret = mkdir(path, mode);
		}
		break;
	case SYS_rmdir:
		ret = rmdir(va_arg(args, const char *)); // path
		break;
	case SYS_adjtime:
		{
		const struct timeval * delta = va_arg(args, const struct timeval *);
		struct timeval * olddelta = va_arg(args, struct timeval *);
		ret = adjtime(delta, olddelta);
		}
		break;
	case SYS_getlogin_r:
		{
		char * namebuf = va_arg(args, char *);
		u_int namelen = va_arg(args, u_int);
		ret = getlogin_r(namebuf, namelen);
		}
		break;
	case SYS_getthrname:
		{
		pid_t tid = va_arg(args, pid_t);
		char * name = va_arg(args, char *);
		size_t len = va_arg(args, size_t);
		ret = getthrname(tid, name, len);
		}
		break;
	case SYS_setthrname:
		{
		pid_t tid = va_arg(args, pid_t);
		const char * name = va_arg(args, const char *);
		ret = setthrname(tid, name);
		}
		break;
	/* No signature found in headers
	 *case SYS_pinsyscall:
	 *	{
	 *	int syscall = va_arg(args, int);
	 *	void * addr = va_arg(args, void *);
	 *	size_t len = va_arg(args, size_t);
	 *	ret = pinsyscall(syscall, addr, len);
	 *	}
	 *	break;
	 */
	case SYS_setsid:
		ret = setsid();
		break;
	case SYS_quotactl:
		{
		const char * path = va_arg(args, const char *);
		int cmd = va_arg(args, int);
		int uid = va_arg(args, int);
		char * arg = va_arg(args, char *);
		ret = quotactl(path, cmd, uid, arg);
		}
		break;
	/* No signature found in headers
	 *case SYS_ypconnect:
	 *	ret = ypconnect(va_arg(args, int)); // type
	 *	break;
	 */
	case SYS_nfssvc:
		{
		int flag = va_arg(args, int);
		void * argp = va_arg(args, void *);
		ret = nfssvc(flag, argp);
		}
		break;
	case SYS_mimmutable:
		{
		void * addr = va_arg(args, void *);
		size_t len = va_arg(args, size_t);
		ret = mimmutable(addr, len);
		}
		break;
	case SYS_waitid:
		{
		int idtype = va_arg(args, int);
		id_t id = va_arg(args, id_t);
		siginfo_t * info = va_arg(args, siginfo_t *);
		int options = va_arg(args, int);
		ret = waitid(idtype, id, info, options);
		}
		break;
	case SYS_getfh:
		{
		const char * fname = va_arg(args, const char *);
		fhandle_t * fhp = va_arg(args, fhandle_t *);
		ret = getfh(fname, fhp);
		}
		break;
	/* No signature found in headers
	 *case SYS___tmpfd:
	 *	ret = __tmpfd(va_arg(args, int)); // flags
	 *	break;
	 */
	/* No signature found in headers
	 *case SYS_sysarch:
	 *	{
	 *	int op = va_arg(args, int);
	 *	void * parms = va_arg(args, void *);
	 *	ret = sysarch(op, parms);
	 *	}
	 *	break;
	 */
	case SYS_lseek:
		{
		int fd = va_arg(args, int);
		off_t offset = va_arg(args, off_t);
		int whence = va_arg(args, int);
		ret = lseek(fd, offset, whence);
		}
		break;
	case SYS_truncate:
		{
		const char * path = va_arg(args, const char *);
		off_t length = va_arg(args, off_t);
		ret = truncate(path, length);
		}
		break;
	case SYS_ftruncate:
		{
		int fd = va_arg(args, int);
		off_t length = va_arg(args, off_t);
		ret = ftruncate(fd, length);
		}
		break;
	case SYS_pread:
		{
		int fd = va_arg(args, int);
		void * buf = va_arg(args, void *);
		size_t nbyte = va_arg(args, size_t);
		off_t offset = va_arg(args, off_t);
		ret = pread(fd, buf, nbyte, offset);
		}
		break;
	case SYS_pwrite:
		{
		int fd = va_arg(args, int);
		const void * buf = va_arg(args, const void *);
		size_t nbyte = va_arg(args, size_t);
		off_t offset = va_arg(args, off_t);
		ret = pwrite(fd, buf, nbyte, offset);
		}
		break;
	case SYS_preadv:
		{
		int fd = va_arg(args, int);
		const struct iovec * iovp = va_arg(args, const struct iovec *);
		int iovcnt = va_arg(args, int);
		off_t offset = va_arg(args, off_t);
		ret = preadv(fd, iovp, iovcnt, offset);
		}
		break;
	case SYS_pwritev:
		{
		int fd = va_arg(args, int);
		const struct iovec * iovp = va_arg(args, const struct iovec *);
		int iovcnt = va_arg(args, int);
		off_t offset = va_arg(args, off_t);
		ret = pwritev(fd, iovp, iovcnt, offset);
		}
		break;
	case SYS_setgid:
		ret = setgid(va_arg(args, gid_t)); // gid
		break;
	case SYS_setegid:
		ret = setegid(va_arg(args, gid_t)); // egid
		break;
	case SYS_seteuid:
		ret = seteuid(va_arg(args, uid_t)); // euid
		break;
	case SYS_pathconf:
		{
		const char * path = va_arg(args, const char *);
		int name = va_arg(args, int);
		ret = pathconf(path, name);
		}
		break;
	case SYS_fpathconf:
		{
		int fd = va_arg(args, int);
		int name = va_arg(args, int);
		ret = fpathconf(fd, name);
		}
		break;
	case SYS_swapctl:
		{
		int cmd = va_arg(args, int);
		const void * arg = va_arg(args, const void *);
		int misc = va_arg(args, int);
		ret = swapctl(cmd, arg, misc);
		}
		break;
	case SYS_getrlimit:
		{
		int which = va_arg(args, int);
		struct rlimit * rlp = va_arg(args, struct rlimit *);
		ret = getrlimit(which, rlp);
		}
		break;
	case SYS_setrlimit:
		{
		int which = va_arg(args, int);
		const struct rlimit * rlp = va_arg(args, const struct rlimit *);
		ret = setrlimit(which, rlp);
		}
		break;
	case SYS_sysctl:
		{
		const int * name = va_arg(args, const int *);
		u_int namelen = va_arg(args, u_int);
		void * old = va_arg(args, void *);
		size_t * oldlenp = va_arg(args, size_t *);
		void * new = va_arg(args, void *);
		size_t newlen = va_arg(args, size_t);
		ret = sysctl(name, namelen, old, oldlenp, new, newlen);
		}
		break;
	case SYS_mlock:
		{
		const void * addr = va_arg(args, const void *);
		size_t len = va_arg(args, size_t);
		ret = mlock(addr, len);
		}
		break;
	case SYS_munlock:
		{
		const void * addr = va_arg(args, const void *);
		size_t len = va_arg(args, size_t);
		ret = munlock(addr, len);
		}
		break;
	case SYS_getpgid:
		ret = getpgid(va_arg(args, pid_t)); // pid
		break;
	case SYS_utrace:
		{
		const char * label = va_arg(args, const char *);
		const void * addr = va_arg(args, const void *);
		size_t len = va_arg(args, size_t);
		ret = utrace(label, addr, len);
		}
		break;
	case SYS_semget:
		{
		key_t key = va_arg(args, key_t);
		int nsems = va_arg(args, int);
		int semflg = va_arg(args, int);
		ret = semget(key, nsems, semflg);
		}
		break;
	case SYS_msgget:
		{
		key_t key = va_arg(args, key_t);
		int msgflg = va_arg(args, int);
		ret = msgget(key, msgflg);
		}
		break;
	case SYS_msgsnd:
		{
		int msqid = va_arg(args, int);
		const void * msgp = va_arg(args, const void *);
		size_t msgsz = va_arg(args, size_t);
		int msgflg = va_arg(args, int);
		ret = msgsnd(msqid, msgp, msgsz, msgflg);
		}
		break;
	case SYS_msgrcv:
		{
		int msqid = va_arg(args, int);
		void * msgp = va_arg(args, void *);
		size_t msgsz = va_arg(args, size_t);
		long msgtyp = va_arg(args, long);
		int msgflg = va_arg(args, int);
		ret = msgrcv(msqid, msgp, msgsz, msgtyp, msgflg);
		}
		break;
	case SYS_shmat:
		{
		int shmid = va_arg(args, int);
		const void * shmaddr = va_arg(args, const void *);
		int shmflg = va_arg(args, int);
		ret = (long)shmat(shmid, shmaddr, shmflg);
		}
		break;
	case SYS_shmdt:
		ret = shmdt(va_arg(args, const void *)); // shmaddr
		break;
	case SYS_minherit:
		{
		void * addr = va_arg(args, void *);
		size_t len = va_arg(args, size_t);
		int inherit = va_arg(args, int);
		ret = minherit(addr, len, inherit);
		}
		break;
	case SYS_poll:
		{
		struct pollfd * fds = va_arg(args, struct pollfd *);
		u_int nfds = va_arg(args, u_int);
		int timeout = va_arg(args, int);
		ret = poll(fds, nfds, timeout);
		}
		break;
	case SYS_issetugid:
		ret = issetugid();
		break;
	case SYS_lchown:
		{
		const char * path = va_arg(args, const char *);
		uid_t uid = va_arg(args, uid_t);
		gid_t gid = va_arg(args, gid_t);
		ret = lchown(path, uid, gid);
		}
		break;
	case SYS_getsid:
		ret = getsid(va_arg(args, pid_t)); // pid
		break;
	case SYS_msync:
		{
		void * addr = va_arg(args, void *);
		size_t len = va_arg(args, size_t);
		int flags = va_arg(args, int);
		ret = msync(addr, len, flags);
		}
		break;
	case SYS_pipe:
		ret = pipe(va_arg(args, int *)); // fdp
		break;
	case SYS_fhopen:
		{
		const fhandle_t * fhp = va_arg(args, const fhandle_t *);
		int flags = va_arg(args, int);
		ret = fhopen(fhp, flags);
		}
		break;
	case SYS_kqueue:
		ret = kqueue();
		break;
	case SYS_mlockall:
		ret = mlockall(va_arg(args, int)); // flags
		break;
	case SYS_munlockall:
		ret = munlockall();
		break;
	case SYS_getresuid:
		{
		uid_t * ruid = va_arg(args, uid_t *);
		uid_t * euid = va_arg(args, uid_t *);
		uid_t * suid = va_arg(args, uid_t *);
		ret = getresuid(ruid, euid, suid);
		}
		break;
	case SYS_setresuid:
		{
		uid_t ruid = va_arg(args, uid_t);
		uid_t euid = va_arg(args, uid_t);
		uid_t suid = va_arg(args, uid_t);
		ret = setresuid(ruid, euid, suid);
		}
		break;
	case SYS_getresgid:
		{
		gid_t * rgid = va_arg(args, gid_t *);
		gid_t * egid = va_arg(args, gid_t *);
		gid_t * sgid = va_arg(args, gid_t *);
		ret = getresgid(rgid, egid, sgid);
		}
		break;
	case SYS_setresgid:
		{
		gid_t rgid = va_arg(args, gid_t);
		gid_t egid = va_arg(args, gid_t);
		gid_t sgid = va_arg(args, gid_t);
		ret = setresgid(rgid, egid, sgid);
		}
		break;
	case SYS_closefrom:
		ret = closefrom(va_arg(args, int)); // fd
		break;
	case SYS_sigaltstack:
		{
		const struct sigaltstack * nss = va_arg(args, const struct sigaltstack *);
		struct sigaltstack * oss = va_arg(args, struct sigaltstack *);
		ret = sigaltstack(nss, oss);
		}
		break;
	case SYS_shmget:
		{
		key_t key = va_arg(args, key_t);
		size_t size = va_arg(args, size_t);
		int shmflg = va_arg(args, int);
		ret = shmget(key, size, shmflg);
		}
		break;
	case SYS_semop:
		{
		int semid = va_arg(args, int);
		struct sembuf * sops = va_arg(args, struct sembuf *);
		size_t nsops = va_arg(args, size_t);
		ret = semop(semid, sops, nsops);
		}
		break;
	case SYS_fhstat:
		{
		const fhandle_t * fhp = va_arg(args, const fhandle_t *);
		struct stat * sb = va_arg(args, struct stat *);
		ret = fhstat(fhp, sb);
		}
		break;
	case SYS___semctl:
		{
		int semid = va_arg(args, int);
		int semnum = va_arg(args, int);
		int cmd = va_arg(args, int);
		union semun * arg = va_arg(args, union semun *);
		ret = __semctl(semid, semnum, cmd, arg);
		}
		break;
	case SYS_shmctl:
		{
		int shmid = va_arg(args, int);
		int cmd = va_arg(args, int);
		struct shmid_ds * buf = va_arg(args, struct shmid_ds *);
		ret = shmctl(shmid, cmd, buf);
		}
		break;
	case SYS_msgctl:
		{
		int msqid = va_arg(args, int);
		int cmd = va_arg(args, int);
		struct msqid_ds * buf = va_arg(args, struct msqid_ds *);
		ret = msgctl(msqid, cmd, buf);
		}
		break;
	case SYS_sched_yield:
		ret = sched_yield();
		break;
	case SYS_getthrid:
		ret = getthrid();
		break;
	/* No signature found in headers
	 *case SYS___thrwakeup:
	 *	{
	 *	const volatile void * ident = va_arg(args, const volatile void *);
	 *	int n = va_arg(args, int);
	 *	ret = __thrwakeup(ident, n);
	 *	}
	 *	break;
	 */
	/* No signature found in headers
	 *case SYS___threxit:
	 *	__threxit(va_arg(args, pid_t *)); // notdead
	 *	break;
	 */
	/* No signature found in headers
	 *case SYS___thrsigdivert:
	 *	{
	 *	sigset_t sigmask = va_arg(args, sigset_t);
	 *	siginfo_t * info = va_arg(args, siginfo_t *);
	 *	const struct timespec * timeout = va_arg(args, const struct timespec *);
	 *	ret = __thrsigdivert(sigmask, info, timeout);
	 *	}
	 *	break;
	 */
	/* No signature found in headers
	 *case SYS___getcwd:
	 *	{
	 *	char * buf = va_arg(args, char *);
	 *	size_t len = va_arg(args, size_t);
	 *	ret = __getcwd(buf, len);
	 *	}
	 *	break;
	 */
	case SYS_adjfreq:
		{
		const int64_t * freq = va_arg(args, const int64_t *);
		int64_t * oldfreq = va_arg(args, int64_t *);
		ret = adjfreq(freq, oldfreq);
		}
		break;
	case SYS_setrtable:
		ret = setrtable(va_arg(args, int)); // rtableid
		break;
	case SYS_getrtable:
		ret = getrtable();
		break;
	case SYS_faccessat:
		{
		int fd = va_arg(args, int);
		const char * path = va_arg(args, const char *);
		int amode = va_arg(args, int);
		int flag = va_arg(args, int);
		ret = faccessat(fd, path, amode, flag);
		}
		break;
	case SYS_fchmodat:
		{
		int fd = va_arg(args, int);
		const char * path = va_arg(args, const char *);
		mode_t mode = va_arg(args, mode_t);
		int flag = va_arg(args, int);
		ret = fchmodat(fd, path, mode, flag);
		}
		break;
	case SYS_fchownat:
		{
		int fd = va_arg(args, int);
		const char * path = va_arg(args, const char *);
		uid_t uid = va_arg(args, uid_t);
		gid_t gid = va_arg(args, gid_t);
		int flag = va_arg(args, int);
		ret = fchownat(fd, path, uid, gid, flag);
		}
		break;
	case SYS_linkat:
		{
		int fd1 = va_arg(args, int);
		const char * path1 = va_arg(args, const char *);
		int fd2 = va_arg(args, int);
		const char * path2 = va_arg(args, const char *);
		int flag = va_arg(args, int);
		ret = linkat(fd1, path1, fd2, path2, flag);
		}
		break;
	case SYS_mkdirat:
		{
		int fd = va_arg(args, int);
		const char * path = va_arg(args, const char *);
		mode_t mode = va_arg(args, mode_t);
		ret = mkdirat(fd, path, mode);
		}
		break;
	case SYS_mkfifoat:
		{
		int fd = va_arg(args, int);
		const char * path = va_arg(args, const char *);
		mode_t mode = va_arg(args, mode_t);
		ret = mkfifoat(fd, path, mode);
		}
		break;
	case SYS_mknodat:
		{
		int fd = va_arg(args, int);
		const char * path = va_arg(args, const char *);
		mode_t mode = va_arg(args, mode_t);
		dev_t dev = va_arg(args, dev_t);
		ret = mknodat(fd, path, mode, dev);
		}
		break;
	case SYS_openat:
		{
		int fd = va_arg(args, int);
		const char * path = va_arg(args, const char *);
		int flags = va_arg(args, int);
		mode_t mode = va_arg(args, mode_t);
		ret = openat(fd, path, flags, mode);
		}
		break;
	case SYS_readlinkat:
		{
		int fd = va_arg(args, int);
		const char * path = va_arg(args, const char *);
		char * buf = va_arg(args, char *);
		size_t count = va_arg(args, size_t);
		ret = readlinkat(fd, path, buf, count);
		}
		break;
	case SYS_renameat:
		{
		int fromfd = va_arg(args, int);
		const char * from = va_arg(args, const char *);
		int tofd = va_arg(args, int);
		const char * to = va_arg(args, const char *);
		ret = renameat(fromfd, from, tofd, to);
		}
		break;
	case SYS_symlinkat:
		{
		const char * path = va_arg(args, const char *);
		int fd = va_arg(args, int);
		const char * link = va_arg(args, const char *);
		ret = symlinkat(path, fd, link);
		}
		break;
	case SYS_unlinkat:
		{
		int fd = va_arg(args, int);
		const char * path = va_arg(args, const char *);
		int flag = va_arg(args, int);
		ret = unlinkat(fd, path, flag);
		}
		break;
	case SYS___set_tcb:
		__set_tcb(va_arg(args, void *)); // tcb
		break;
	case SYS___get_tcb:
		ret = (long)__get_tcb();
		break;
	default:
		ret = -1;
		errno = ENOSYS;
	}
	va_end(args);

	return ret;
}
