# Plt-setup.py:  Build and install the extension

from distutils.core import setup, Extension

setup(
    name='plt',
    version='1.0',
    description="python-libtrace, python bindings for WAND's libtrace library",
    author='Nevil Brownlee',
    author_email='n.brownlee@auckland.ac.nz',
    url='https://www.cs.auckland.ac.nz/~nevil/python-libtrace/',

    ext_modules = [
        Extension(  "plt", 
            sources = [
                "tcp.c", "udp.c", "icmp.c", "icmp6.c",
                "ip6.c", "ip.c", "internet.c",
                "layers.c",
                "packet.c", "trace.c", "outputtrace.c",
                "pltmodule.c" ],
            libraries = ['trace'],
            library_dirs = ['/usr/local/lib'],
            include_dirs = ['/usr/local/include', '../include']
       )
    ]
)
