#!/usr/bin/perl
#	$OpenBSD$	#
use v5.36;
use warnings;

# Copyright (c) 2023 Andrew Hewus Fresh <afresh1@openbsd.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

my $includes = '/usr/include';

# See also /usr/src/sys/kern/syscalls.master
my %syscalls = parse_syscalls(
    "$includes/sys/syscall.h",
    "$includes/sys/syscallargs.h",
);
delete $syscalls{MAXSYSCALL}; # not an actual function

# The ordered list of all the headers we need
my @headers = qw<
	sys/syscall.h
	stdarg.h
	errno.h

	sys/socket.h
	sys/event.h
	sys/futex.h
	sys/ioctl.h
	sys/ktrace.h
	sys/mman.h
	sys/mount.h
	sys/msg.h
	sys/poll.h
	sys/ptrace.h
	sys/resource.h
	sys/select.h
	sys/sem.h
	sys/shm.h
	sys/stat.h
	sys/sysctl.h
	sys/time.h
	sys/uio.h
	sys/wait.h

	dirent.h
	fcntl.h
	sched.h
	signal.h
	stdlib.h
	stdio.h
	syslog.h
	tib.h
	time.h
	unistd.h
>;

foreach my $header (@headers) {
	my $file = "$includes/$header";
	open my $fh, '<', $file or die "Unable to open $file: $!";
	my $content = do { local $/; readline $fh };
	close $fh;

	# Look for matching syscalls in this header
	foreach my $name (sort keys %syscalls) {
		my $s = $syscalls{$name};
		my $func_sig = find_func_sig($content, $name, $s);

		if (ref $func_sig) {
			die "Multiple defs for $name <$header> <$s->{header}>"
			    if $s->{header};
			$s->{func} = $func_sig;
			$s->{header} = $header;
		} elsif ($func_sig) {
			$s->{mismatched_sig} = "$func_sig <$header>";
		}
	}
}

say "/*\n * Generated from gen_syscall_emulator.pl\n */";
say "#include <$_>" for @headers;
print <<"EOL";

long
syscall_emulator(int syscall, ...) {
	long ret = 0;
	va_list args;
	va_start(args, syscall);

	switch(syscall) {
EOL

foreach my $name (
	sort { $syscalls{$a}{id} <=> $syscalls{$b}{id} } keys %syscalls
    ) {
	my %s = %{ $syscalls{$name} };

	# Some syscalls we can't emulate, so we comment those out.
	$s{skip} //= "Indirect syscalls not supported"
	    if !$s{argtypes} && ($s{args}[-1] || '') eq '...';
	$s{skip} //= "Mismatched func: $s{mismatched_sig}"
	    if $s{mismatched_sig} and not $s{func};
	$s{skip} //= "No signature found in headers"
	    unless $s{header};

	my $ret = $s{ret} eq 'void' ? '' : 'ret = ';
	$ret .= '(long)' if $s{ret} eq 'void *';

	my (@args, @defines);
	my $argname = '';
	if ($s{argtypes}) {
		if (@{ $s{argtypes} } > 1) {
			@defines = map {
			    my $t = $_->{type};
			    my $n = $_->{name};
			    $n = "_$n" if $n eq $name; # link :-/
			    push @args, $n;
			    "$t $n = va_arg(args, $t);"
			} @{ $s{argtypes} };
		} else {
			if (@{ $s{argtypes} }) {
				$argname = " // " . join ', ',
				    map { $_->{name} }
				    @{ $s{argtypes} };
			}
			@args = map { "va_arg(args, $_->{type})" }
			    @{ $s{argtypes} };
		}
	} else {
		@args = @{ $s{args} };

		# If we didn't find args in syscallargs.h but have args
		# we don't know how to write our function.
		$s{skip} //= "Not found in sys/syscallargs.h"
		    if @args;
	}

	#my $header = $s{header} ? " <$s{header}>" : '';

	my $indent = "\t";
	say "$indent/* $s{skip}" if $s{skip};

	$indent .= ' *' if $s{skip};
	say "${indent}                  $s{signature} <sys/syscall.h>"
	    if $s{skip} && $s{skip} =~ /Mismatch/;

	say "${indent}case $s{define}:"; # // $s{id}";
	say "${indent}\t{" if @defines;
	say "${indent}\t$_" for @defines;
	#say "${indent}\t// $s{signature}$header";
	say "${indent}\t$ret$name(" . join(', ', @args) . ");$argname";
	say "${indent}\t}" if @defines;
	say "${indent}\tbreak;";

	say "\t */" if $s{skip};
}

print <<"EOL";
	default:
		ret = -1;
		errno = ENOSYS;
	}
	va_end(args);

	return ret;
}
EOL


sub parse_syscalls ($syscall, $args) {
	my %s = parse_syscall_h($syscall);

	my %a = parse_syscallargs_h($args);
	$s{$_}{argtypes} = $a{$_} for grep { $a{$_} } keys %s;

	return %s;
}

sub parse_syscall_h ($file) {
	my %s;
	open my $fh, '<', $file or die "Unable to open $file: $!";
	while ($_ = $fh->getline) {
		if (m{^/\*
		    \s+ syscall: \s+ "(?<name>[^"]+)"
		    \s+	 ret: \s+ "(?<ret> [^"]+)"
		    \s+	args: \s+  (?<args>.*?)
		    \s* \*/
		  |
		    ^\#define \s+ (?<define>SYS_(?<name>\S+)) \s+ (?<id>\d+)
		}x) {
			my $name        = $+{name};
			$s{$name}{$_}   = $+{$_} for keys %+;
			$s{$name}{args} = [ $+{args} =~ /"(.*?)"/g ]
			    if exists $+{args};
		}
	}
	close $fh or die "Unable to close $file: $!";

	foreach my $name (keys %s) {
		my %d = %{ $s{$name} };
		next unless $d{ret}; # the MAXSYSCALL

		my $ret = $d{ret};
		my @args = @{ $d{args} || [] };
		@args = 'void' unless @args;

		if ($args[-1] ne '...') {
			my @a;
			for (@args) {
				push @a, $_;
				last if $_ eq '...';
			}
			@args = @a;
		}

		my $args = join ", ", @args;
		$s{$name}{signature} = "$ret\t$name($args);" =~ s/\s+/ /gr;
		#print "    $s{$name}{signature}\n";
	}

	return %s;
}

sub _parse_syscallarg ($fh) {
	my @a;
	while ($_ = $fh->getline) {
		last if /^\s*\};\s*$/;
		if (/syscallarg\( ( [^)]+  ) \) \s+ (\w+) \s* ;/x) {
			push @a, { type => $1, name => $2 };
		}
	}
	return \@a;
}

sub parse_syscallargs_h ($file) {
	my %a;
	open my $fh, '<', $file or die "Unable to open $file; $!";
	while ($_ = $fh->getline) {
		if (/^struct sys_(\w+)_args \{/) {
			my $name = $1;
			$a{$name} = _parse_syscallarg($fh);
		}
	}
	close $fh;
	return %a;
}

sub find_func_sig ($content, $name, $s) {
	my $re = $s->{re} //= qr{^
	    (?<ret> \S+ (?: [^\S\n]+ \S+)? ) [^\S\n]* \n?
	    \b \Q$name\E \( (?<args> [^)]* ) \)
	[^;]*;}xms;

	$content =~ /$re/ || return;
	my $ret  = $+{ret};
	my $args = $+{args};

	for ($ret, $args) {
		s/^\s+//;
		s/\s+$//;
		s/\s+/ /g;
	}

	# The actual functions may have this extra annotation
	$args =~ s/\*\s*__restrict/*/g;

	my %func_sig = ( ret => $ret, args => [ split /\s*,\s*/, $args ] );

	return "$ret $name($args);" =~ s/\s+/ /gr
	    unless sigs_match( $s, \%func_sig );

	return \%func_sig;
}

# Tests whether two types are equivalent.
# Sometimes there are two ways to represent the same thing
# and it seems the functions and the syscalls
# differ a fair amount.
{
my %m; BEGIN { %m = (
    'unsigned long' => 'u_long',
    'unsigned int'  => 'u_int',
    __off_t         => 'off_t',
    caddr_t         => 'char *',
    pid_t           => 'int',
    nfds_t          => 'u_int',
    idtype_t        => 'int',
    size_t          => 'u_int',
    __size_t        => 'u_int',
) }
sub types_match ($l, $r) {
	$l //= '__undef__';
	$r //= '__undef__';

	s/^volatile //     for $l, $r;
	s/^const //        for $l, $r;
	s/\s*\[\d*\]$/ \*/ for $l, $r;

	my ($f, $s) = sort { length($a) <=> length($b) } $l, $r;
	if (index($s,$f) == 0) {
		$s =~ s/^\Q$f\E\s*//;
		if ( $s && $s =~ /^\w+$/ ) {
			#warn "prefix ['$f', '$s']\n";
			s/\s*\Q$s\E$// for $l, $r;
		}
	}

	# my ($p_l, $p_r) = ($l, $r);
	$l = $m{$l} //= $l;
	$r = $m{$r} //= $r;

	#warn "    $p_l [$l] $p_r [$r] <'$f' '$s'>\n";
	# return and use the original "right" value
	# as it's from the function header and closer to what we need.
	return $l eq $r;
}
}


# Tests whether two funciton signatures match,
# expected to be left from syscall.h, right from the appopriate header.
sub sigs_match ($l, $r) {
	return unless types_match( $l->{ret}, $l->{ret} );

	my @l_args = @{ $l->{args} || [] };
	my @r_args = @{ $r->{args} || [] };

	for (\@l_args, \@r_args) {
		@{$_} = 'void' unless @{$_};
	}

	for my $i ( 0 .. $#l_args ) {
		return unless types_match( $l_args[$i], $r_args[$i] );
		last if $l_args[$i] eq '...';
	}

	return 1;
}
