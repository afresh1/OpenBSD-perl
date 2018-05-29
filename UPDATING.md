# They release a new perl, now what?

### Updating OpenBSD patches for a new version of perl

This is still an art, not as yet a complete doc, but a start.

* Pick a new version of perl and download the tar.gz
* Update the different scripts, primarily test_patches, with the new version
* Update files/shlib_version
* mv patches/GOOD patches/GOOD.orig and run `bin/cp_good_research`
* Change to a temporary directory and run `NO_LOCAL_PATCHES=1 build_local_perl`
* See if it runs successfully, it generally should
* Run `test_patches` to update and test all patches
* You may need to rerun `bin/cp_good_research` and re-run
  `test_patches` a few times as some patches depend on other patches
* Likely you will need to set NO_BSD_WRAPPER for the first few rounds
* After you do get to use Makefile.bsdwrapper, you probably will need
    * NO_LOCALE_test_fixes.patch will need to be applied
    * While doing this, won't pass without put_OpenBSD-MkTemp_in_MANIFEST.patch
    * Similarly with the put_OpenBSD_Pledge_in_MANIFEST.patch
    * unless you mv files/cpan out of the way, so need to do that.
    * as well as dont_rebuild_libperl.patch
* At some point you won't get any better results and you will actually have to
  look at the logs and update patches.
* Once all the patches have been regenerated run the `update_unicore` script
* Eventually everything will build and tests will pass.
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
