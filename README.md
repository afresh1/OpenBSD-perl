OpenBSD-perl
============

Patches and scripts with the goal of a current perl in OpenBSD base

Now available from https://github.com/afresh1/OpenBSD-perl

It's easy!

* [download the patches and scripts](https://github.com/afresh1/OpenBSD-perl/archive/master.tar.gz)
* extract someplace
* download perl-5.20.3.tar.gz into the same directory
    * https://cpan.metacpan.org/authors/id/S/SH/SHAY/perl-5.20.3.tar.gz
* cd to someplace you have room
* run /path/to/OpenBSD-perl/build_perl
* wait
* send me the log file(s) it generates


There are some environment variables you can set to control the build.
Unless otherwise specified, just need to be set.

## build_local_perl

### NO_LOCAL_PATCHES

Disables applying the local patches to the build.

Automatically gets re-run if the build with the patches fails.
Unless you set NO_RETRY_WITHOUT_PATCHES

### NO_RETRY_WITHOUT_PATCHES

Disables cleanup and retry without patches.
Useful for figuring out why failures are happening with the patches.

## test_patches

### REGEN_PATCHES

Just regenerates the patches, doesn't attempt to build.


## Misc in utils.sub

### NO_BSD_WRAPPER

Disables using `make -f Makefile.bsd-wrapper` and instead
uses the standard `./Configure && make` to build perl.

### SKIP_UNICORE_PATCH

Ignores files in lib/unicore/{lib,To} when doing cvs rm and add

In make_src_patch, setting this doesn't apply pre_built_unicore.patch and
so makes the patch slightly smaller.  Not really useful.

Mostly used internally by import_perl to apply the unicore changes in a
separate commit.
