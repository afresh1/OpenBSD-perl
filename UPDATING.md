# They release a new perl, now what?

### Updating OpenBSD patches for a new version of perl

This is still an art, not as yet a complete doc, but a start.

* Pick a new version of perl and download the tar.gz
* Update the different scripts, primarily test_patches, with the new version
* mv patches/GOOD patches/RESEARCH
* Change to a temporary directory and run `NO_LOCAL_PATCHES=1 build_local_perl`
* See if it runs successfully, it generally should
* Run `test_patches` to update and test all patches
* You may need to move files from APPLIES to RESEARCH and re-run
  `test_patches` a few times as some patches depend on other patches
* Likely you will need to set NO_BSD_WRAPPER for the first few rounds
* After you do get to the BSD_WRAPPER, you probably will need to
    * First NO_LOCALE_test_fixes.patch will need to be applied
    * While doing this, won't pass without put_OpenBSD-MkTemp_in_MANIFEST.patch
    * unless you mv files/cpan out of the way, so need to do that.
* At some point you won't get any better results and you will actually have to
  look at the logs and update patches.
* Once all the patches have been regeneraed run the `update_unicore` script
* Eventually everything will build and tests will pass.
* After this, use `make_patched_perl` to build a patched perl directory
* Change into the perl build directory and run `regen_manpage_list`
* Copy the new Makefile.bsdwrapper1 to the git repo
* Then you can commit the patch changes!
* Now have people test on additional architectures.

### Updating in CVS
I am still not sure on this step.

The one note I am sure of is to remind someone that they should use "-k o"
when importing into cvs so that keywords don't get expanded.
