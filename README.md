OpenBSD-perl
============

# At the moment this isn't working.

### Something is screwed up causing perl to core dump when trying to build.
### I got the patches we should need applied and everything so next should just be solving the problem.
### No idea how to do that yet.  But, it is also bedtime.

Patches and scripts with the goal of a current perl in OpenBSD base

Now available from https://github.com/afresh1/OpenBSD-perl

It's easy!

* [download the patches and scripts](https://github.com/afresh1/OpenBSD-perl/downloads)
* extract someplace
* download perl-5.16.2.tar.gz into the same directory
    * http://cpan.metacpan.org/authors/id/R/RJ/RJBS/perl-5.16.2.tar.gz
    * http://cvs.afresh1.com/~andrew/perl-update/perl-5.16.2.tar.gz
* cd to someplace you have room
* run /path/to/OpenBSD-perl/build_local_perl
* wait
* send me the log file(s) it generates
