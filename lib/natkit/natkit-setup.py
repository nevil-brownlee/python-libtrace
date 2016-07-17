# Plt-setup.py:  Build and install the extension

from distutils.core import setup, Extension

setup(
    name='natkit',
    version='1.0',
    description="python-libtrace, Net Analysis ToolKIT",
    author='Nevil Brownlee',
    author_email='n.brownlee@auckland.ac.nz',
    url='https://www.cs.auckland.ac.nz/~nevil/python-libtrace/',

    ext_modules = [
        Extension(  "natkit", 
            sources = [
                "natkit.c" ],
            libraries = ['trace'],
            library_dirs = ['/usr/local/lib'],
            include_dirs = ['/usr/local/include', '../include']
       )
    ]
)
