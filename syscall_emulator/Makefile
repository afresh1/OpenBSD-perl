OUT=a.out

build: $(OUT)

$(OUT): syscall_user.c syscall_emulator.c
	$(CC) -o $@ $>

syscall_emulator.c: ../files/gen_syscall_emulator.pl syscall_emulator.h /usr/include/sys/syscall.h /usr/include/sys/syscallargs.h
	/usr/bin/perl $(.CURDIR)/../files/gen_syscall_emulator.pl > $@

syscall_emulator.h: ../files/syscall_emulator.h
	cp $> $@
	
test: build
	prove -v -e '' $(.CURDIR)/$(OUT)

clean:
	rm -f $(OUT) test.out test.txt syscall_emulator.c syscall_emulator.h
