# pldns-setup.py:  Build the pldns extension

from distutils.core import setup, Extension

setup(
    name='pldns',
    version='1.0',
    description='pldns, a Python wrapper for ldns',
    author='Nevil Brownlee',
    author_email='n.brownlee@auckland.ac.nz',
    url='https://www.cs.auckland.ac.nz/~nevil/python-ldns/',

    ext_modules = [
        Extension("pldns",
            sources = [
                "pldns.c" ],
            libraries = ['ldns'],
            library_dirs = ['/usr/local/lib'],
            include_dirs = ['/usr/local/include', '../include']
       )
    ]
)
