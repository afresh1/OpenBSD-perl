#!/usr/bin/perl
use v5.36;

use Test::More;
use File::Temp;
use POSIX qw< S_IRUSR S_IWUSR S_IRGRP S_IROTH O_CREAT O_WRONLY O_RDONLY >;

use constant {
    PROT_READ   => 0x01,
    MAP_PRIVATE => 0x0002,
    MAP_FAILED  => -1,
};

my $dir = File::Temp->newdir("syscall_emulator-XXXXXXXXX");
{
	system("h2ph", '-d', $dir,
	    "/usr/include/sys/syscall.h");
	local @INC = ("$dir/usr/include", "$dir");
	require 'sys/syscall.ph';
}

my $filename = "test.txt";
my $file = "$dir/$filename";
my $fd;
my $out = "Hello World\n";
my $in = "\0" x 32;
my $in_p;
my $sb = "\0\0\0\0";
my $st_mode;

my $perms = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;

plan tests => 14;

ok(!
    (($fd = syscall(SYS_open(), $file, O_CREAT|O_WRONLY, $perms)) < 0),
    "Opened $filename for write/create"
);
ok(!
    (syscall(SYS_write(), $fd, $out, length $out) <= 0),
    "Wrote out to $filename"
);
ok(!
    (syscall(SYS_close(), $fd) != 0),
    "closed $filename"
);


ok(!
    (syscall(SYS_stat(), $file, $sb) != 0),
    "stat $filename"
);

# fortunately st_mode is the first unsigned long in stat struct
$st_mode = unpack "L", $sb;

ok( ($st_mode & 0777) == ($perms & 0777),
    sprintf "new file %s has correct permissions (%o)",
        $filename, $st_mode & 0777
);

ok(!
    (($fd = syscall(SYS_open(), $file, O_RDONLY)) < 0),
    "Opened $filename for read"
);
ok(!
    (syscall(SYS_read(), $fd, $in, length $in) <= 0),
    "read from $filename"
);

$in = unpack 'Z*', $in;

ok( length($in) == length($out) && ($in eq $out),
    "Read written content from $filename"
);

ok(!
    (syscall(SYS_lseek(), $fd, 0, SEEK_SET) < 0),
    "lseek on fd"
);


ok(!
    (($in_p = syscall(SYS_mmap(), undef, length($out), PROT_READ, MAP_PRIVATE,
        $fd, 0)) == MAP_FAILED),
    "mmap fd"
);

ok $in_p =~ /^-?\d+$/, "The mmapped value ($in_p) looks like an integer";

SKIP: { skip "No idea how to get dereference the pointer", 2;
ok( length($in_p) == length($out) && ($in_p eq $out),
    "Read written content from $filename"
);

ok(!
    (syscall(SYS_munmap(), $in_p, length($out)) != 0),
    "munmap fd"
);
}

ok(!
    (syscall(SYS_close(), $fd) != 0),
    "closed $filename"
);
