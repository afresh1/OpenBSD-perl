# They release a new perl, now what?

### Updating OpenBSD patches for a new version of perl

This is still an art, not as yet a complete doc, but a start.

* Pick a new version of perl and download the tar.gz
* Update the different scripts, primarily test_patches, with the new version
* mv patches/GOOD patches/RESEARCH
* Change to a temporary directory and run `NO_LOCAL_PATCHES=1 build_local_perl`
* See if it runs successfully, it generally should
* run the `update_unicore` script (this might not work first, unsure)
* Now run `test_patches` to try applying and building with all patches
* You may need to move files from APPLIES to RESEARCH a few times as some
  patches depend on other patches
* At some point you won't get any better results and you will actually have to
  look at the logs and update patches.
* Eventually everything will build and tests will pass.
* After this, use `build_local_perl` to build a "clean" perl install
* Change into the perl build directory and run `regen_manpage_list`
* Copy the new Makefile.bsdwrapper1
* Then you can commit the patch changes!
* Now have people test on additional architectures.

### Updating in CVS
I am still not sure on this step.

The one note I am sure of is to remind someone that they should use "-k o"
when importing into cvs so that keywords don't get expanded.
