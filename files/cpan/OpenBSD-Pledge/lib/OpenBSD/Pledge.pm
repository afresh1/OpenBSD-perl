package OpenBSD::Pledge;

use 5.020002;
use strict;
use warnings;

use parent 'Exporter';
our %EXPORT_TAGS = ( 'all' => [ qw( pledge pledgenames ) ] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw( pledge ); ## no critic 'export'

our $VERSION = '0.01';

require XSLoader;
XSLoader::load('OpenBSD::Pledge', $VERSION);

sub pledge {
    my (@flags) = @_;

    my $paths;
    $paths = pop @flags if @flags and ref $flags[-1] eq 'ARRAY';

    my %seen;
    my $flags = join q{ }, sort grep { !$seen{$_}++ } @flags;

    return _pledge( $flags, $paths );
}

1;

## no critic 'pod sections'
__END__

=head1 NAME

OpenBSD::Pledge - Perl interface to OpenBSD pledge(2)

=head1 SYNOPSIS

  use OpenBSD::Pledge;
  my $file = "/usr/share/dict/words";
  pledge(qw( stdio rpath ), [$file]) || die "Unable to pledge: $!";

  open my $fh, '<', $file or die "Unable to open $file: $!\n";
  while (<$fh>) {
    print if /pledge/i;
  }
  close $fh;

=head1 DESCRIPTION

This module provides a perl interface to OpenBSD's pledge(2) syscall.
This is used to limit what your program can do.

Once you pledge that your program will only make certain syscalls
the kernel will kill the program if it attempts to call any other
interfaces.

=head2 EXPORT

Exports L</pledge> by default.

C<:all> will also export L</pledgenames>

=head1 METHODS

=head2 pledge(@flags, [\@paths])

This is the primary interface to pledge.

See the man page for more details.

Returns true on success, returns false and sets C<$!> on failure.

=head2 pledgenames

Returns a list of the possible flags you can pass to L</pledge>.

=head1 BUGS AND LIMITATIONS

Perl is particularly fond of C<stdio> so you usually need to include
at least that flag.

=head1 SEE ALSO

L<man 2 pledge|http://www.openbsd.org/cgi-bin/man.cgi/OpenBSD-current/man2/pledge.2>

=head1 AUTHOR

Andrew Fresh, E<lt>afresh1@OpenBSD.orgE<gt>

=head1 LICENSE AND COPYRIGHT

Copyright (C) 2015 by Andrew Fresh E<lt>afresh1@OpenBSD.orgE<gt>

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
