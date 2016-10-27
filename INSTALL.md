# INSTALL instructions for python-libtrace 

## Installing python-libtrace

## Quick Start for Ubuntu 14.04/16.04

```bash
sudo apt install libtrace-dev libldns-dev
git clone https://github.com/nevil-brownlee/python-libtrace.git
cd python-libtrace
sudo make install-py2 # for python 2
```

## Detailed install instructions

Requirements:

 * python 2.7 or later, 3.4 or later
 * libtrace 3.0.21 or later (http://research.wand.net.nz/software/libtrace.php)
 * ldns, which requires an up-to-date version of openssl (libldns-dev)

Check that you have the right version of libtrace, python, openssl
and ldns (as listed above).  For openssl, you may need
to create a symbolic link in /usr/include, something like this:

```
ln -s /home/nevil/openssl-1.0.1j/include/openssl /usr/include/openssl
```

Then:

```
git clone https://github.com/nevil-brownlee/python-libtrace.git
cd python-libtrace
make install-py2 # for python 2
# or
make install-py3 # for python 3
```

The above series of commands will build python-libtrace and
install it into the place where python expects to find extension
modules on your system. python-libtrace can be built for both
python 2 and 3.

You'll probably need to use sudo for the make install step.

The library comes with a set of test cases. You can run them to
make sure the installation is complete. They are also useful, if
you want to make changes to the library. In this case, they can
be used to make sure your changes did not break anything in the
library.

Testing
-------

To run the tests, go to the 'test' subdirectory and run the script
'run_test' as follows for _python 2_:

```bash
export TZ=Pacific/Auckland  # Get the times right for trace file packets
cd test
python run_test.py -d v2-test-cases/ -t
```

Similar set of test cases exists in 'v3-test-cases' subdirectory. If you
use _python 3_, you can use those test cases and run them using run_test
as follows:

```bash
cd test
python3 run_test.py -d v3-test-cases/ -t
```

This command runs all test programs and reports the results. All tests
should pass to make sure the library works properly.

Using python-libtrace
---------------------

The best source of information on how to use libtrace and the 
tools that come with it is the libtrace wiki located at 
http://www.wand.net.nz/trac/libtrace/wiki

python-libtrace is documented in a set of html pages in the
doc subdirectory of the distribution.

A set of example programs is included in the doc/examples
subdirectory.

You should install these documentation files on a suitable
webserver at your site or you can view them at
http://www.cs.auckland.ac.nz/~nevil/python-libtrace

Nevil Brownlee
Email for queries or comments: n.brownlee@auckland.ac.nz

--------------------------------------------------------------

