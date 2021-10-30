#	$OpenBSD: Pledge.pm,v 1.6 2021/06/09 23:21:34 afresh1 Exp $	#
package OpenBSD::Pledge;

use 5.020002;
use strict;
use warnings;

use parent 'Exporter';
our @EXPORT = qw( pledge );    ## no critic 'export'

our $VERSION = '0.03';

require XSLoader;
XSLoader::load( 'OpenBSD::Pledge', $VERSION );

sub pledge
{
	my (@promises) = @_;

	my %seen;
	my $promises = join q{ },
	    sort grep { !$seen{$_}++ } ( 'stdio', @promises );

	return _pledge( $promises );
}

1;

## no critic 'pod sections'
__END__

=head1 NAME

OpenBSD::Pledge - Perl interface to OpenBSD pledge(2)

=head1 SYNOPSIS

  use OpenBSD::Pledge;

  my $file = "/usr/share/dict/words";
  pledge( qw( rpath ) ) || die "Unable to pledge: $!";
  open my $fh, '<', $file or die "Unable to open $file: $!";

  pledge() || die "Unable to pledge again: $!";
  print grep { /pledge/i } readline($fh);
  close $fh;


=head1 DESCRIPTION

This module provides a perl interface to OpenBSD's L<pledge(2)> L<syscall(2)>.

Once you promise that your program will only use certain syscalls
the kernel will kill the program if it attempts to call any other
interfaces.

=head1 EXPORT

Exports L</pledge> by default.

=head1 FUNCTIONS

=head2 pledge

Perl interface to L<pledge(2)>.

	pledge(@promises)

The "stdio" promise is always implied,
as L<perl(1)> itself is useless without it.

Returns true on success, returns false and sets $! on failure

=head1 BUGS AND LIMITATIONS

Perl is particularly fond of C<stdio> so that promise is always added by
L</pledge>.

=head1 SEE ALSO

L<pledge(2)>

L<http://man.openbsd.org/pledge.2>

=head1 AUTHOR

Andrew Hewus Fresh, E<lt>afresh1@OpenBSD.orgE<gt>

=head1 LICENSE AND COPYRIGHT

Copyright (C) 2015,2021 by Andrew Hewus Fresh E<lt>afresh1@OpenBSD.orgE<gt>

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

=cut
