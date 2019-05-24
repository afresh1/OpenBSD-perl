# They release a new perl, now what?

### Updating OpenBSD patches for a new version of perl

This is still an art, not as yet a complete doc, but a start.

* Pick a new version of perl and download the tar.gz
* Update the different scripts, primarily test_patches, with the new version
* Update files/shlib_version
* git rm -rf build_logs/$old_perl_version
* mv patches/GOOD patches/GOOD.orig and run `bin/cp_good_research`
* Change to a temporary directory and run `NO_LOCAL_PATCHES=1 build_local_perl`
  * See if it runs successfully, it generally should
  * If not, you can add patches to patches/REQUIRED to get it building
* Run `test_patches` to update and test all patches
  * Updating patches in `patches/RESEARCH` as necessary to get them to apply
    or removing patches that are no longer needed.
  * You probably need to move files/cpan out of the way until you get to
    the patches that put them in the Makefile.
  * From time-to time you may need to start over with `cp_good_research`
  * First with `NO_LOCAL_PATCHES=1` until they all apply
  * Then with `NO_BSD_WRAPPER=1` to get patches that rely on each othe
  * Finally run without any environment variables either variable set
  * You may want to adjust `test_patches` to exit after the first
    failed build to make it go faster.
* After you do get to use Makefile.bsdwrapper, you probably will need
    * NO_LOCALE_test_fixes.patch will need to be applied
    * While doing this, won't pass without put_OpenBSD-MkTemp_in_MANIFEST.patch
    * Similarly with the put_OpenBSD_Pledge_in_MANIFEST.patch
    * unless you mv files/cpan out of the way, so need to do that.
    * as well as dont_rebuild_libperl.patch
* At some point you won't get any better results and you will actually have to
  look at the logs and update patches.
* When adding new modules to the dist, You need to regenerate some files
  * use the "bin/make_patched_perl" script
  * find . -name '*.orig' -exec rm -f {} +
  * cp -a perl-* orig
  * cd perl-*
  * Add your new files to the MANIFEST
  * if Porting/manicheck says it's not sorted properly
  * run Porting/manisort --output MANIFEST.new && mv MANIFEST.new MANIFEST
  * regen/lib_cleanup.pl -v with the system perl
  * diff -ru ../orig . > .../OpenBSD-perl/patches/RESEARCH/put_My-Module_in_MANIFEST.patch
  * cd .. && rm -rf -- ./*
  * use bin/test_patches to make sure it works
* Once all the patches have been regenerated run the `update_unicore` script
* Eventually everything will build and tests will pass.
* Check to see if a build or test run causes any new /var/log/messages
* After this, use `make_patched_perl` to build a patched perl directory
* Change into the perl build directory and run `regen_manpage_list`
* Copy the new Makefile.bsdwrapper1 to the git repo
* Check out corelist --diff $last_version $current_version | grep absent
* Then you can commit the patch changes!
* Now have people test on additional architectures.
* Try building a release with it
    * and installing it
    * and building packages
    * and using dpb
* Double check that we got results from all archs, or at least enough
* Run bin/find_base_perl_ports to see what can be removed

### Updating in CVS
See bin/import_perl for most of the notes related to importing. That script
works to test importing into a local copy of a repo.

The one note I am sure of is to remind someone that they should use "-k o"
when importing into cvs so that keywords don't get expanded.
