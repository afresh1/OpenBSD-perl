#include <sys/syscall.h>
#include "syscall_emulator.h"

#include <sys/mman.h>
#include <sys/stat.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(void) {
	int fd;
	char file[] = "./test.out";
	char out[] = "Hello World\n";
	char in[32];
	char *in_p;
	mode_t perms = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;
	struct stat *sb;

	sb = malloc(sizeof(struct stat));

	printf("%s\n", "1..13");

	if ((fd = syscall_emulator(SYS_open, file, O_CREAT|O_WRONLY, perms)) < 0)
		err(1, "Failed to open test.out for write/create");
	printf("ok 1 Opened %s for write/create\n", file);

	if ((syscall_emulator(SYS_write, fd, &out, sizeof(out)-1)) <= 0)
		err(1, "Failed to write");
	printf("ok 2 Wrote out to %s\n", file);

	if (syscall_emulator(SYS_close, fd) != 0)
		err(1, "Failed to close");
	printf("ok 3 closed %s\n", file);


	if (syscall_emulator(SYS_stat, file, sb) != 0)
		err(1, "Failed to stat");
	printf("ok 4 stat %s\n", file);

	if ((sb->st_mode & 0777) == (perms & 0777))
		printf("ok 5 new file %s has correct permissions (%o)\n",
		    file, sb->st_mode & 0777);
	else
		printf("not ok 5 new file %s has correct permissions (%o)\n",
		    file, sb->st_mode & 0777);

	if ((fd = syscall_emulator(SYS_open, file, O_RDONLY)) < 0)
		err(1, "Failed to open test.out for reading");
	printf("ok 6 Opened %s for read\n", file);

	if ((syscall_emulator(SYS_read, fd, &in, sizeof(in)-1)) <= 0)
		err(1, "Failed to read");
	printf("ok 7 read %lu bytes from %s\n", strlen(in), file);

	if (strlen(in) == strlen(out)
	 && strncmp(in, out, sizeof(out)) == 0)
		printf("ok 8 Read written content from %s\n", file);
	else
		printf("not ok 8 Read written content from %s\n", file);

	if (syscall_emulator(SYS_lseek, fd, 0, SEEK_SET) < 0)
		err(1, "Failed to lseek");
	printf("ok 9 lseek on fd\n");

	if ((in_p = (void *)syscall_emulator(SYS_mmap,
	    NULL, sizeof(out), PROT_READ, MAP_PRIVATE,
	    fd, 0)) == MAP_FAILED)
		err(1, "mmap failed");
	printf("ok 10 mmap fd\n");

	if (strncmp(in_p, out, sizeof(out)) == 0)
		printf("ok 11 Read written content from %s via mmap\n", file);
	else
		printf("not ok 11 Read written content from %s via mmap\n", file);
	if (syscall_emulator(SYS_munmap, in_p, sizeof(out)) != 0)
	    err(1, "munmap failed");
	printf("ok 12 munmap fd\n");

	if (syscall_emulator(SYS_close, fd) != 0)
		err(1, "Failed to close");
	printf("ok 13 closed %s\n", file);

	free(sb);

	return 0;
}
