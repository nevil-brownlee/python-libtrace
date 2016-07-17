# IPprefix-setup.py:  Build and install the ext1 extension

from distutils.core import setup, Extension

setup(
    name='ipp',
    version='1.0',
    description='IPprefix, a library for IP addresses and widths',
    author='Nevil Brownlee',
    author_email='n.brownlee@auckland.ac.nz',
    url='https://www.cs.auckland.ac.nz/~nevil/python-libtrace/',

    ext_modules = [
        Extension("ipp", ["ippmodule.c"],
        include_dirs = ['../include']
        )
       ],
    )
