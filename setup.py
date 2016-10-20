from distutils.core import setup, Extension

setup(
    name='python-libtrace',
    version='1.0',
    description='Python-libtrace (incl ipp, natkit, pldns), a library for IP addresses and widths',
    author='Nevil Brownlee',
    author_email='n.brownlee@auckland.ac.nz',
    url='https://www.cs.auckland.ac.nz/~nevil/python-libtrace/',

    ext_modules = [
        Extension("ipp",
                  sources= ["lib/ipp/ippmodule.c"],
                  include_dirs = ['lib/include']
        ),
        Extension("natkit",
                  sources = [ "lib/natkit/natkit.c" ],
                  libraries = ['trace'],
                  include_dirs = ['lib/include'],
        ),
        Extension("plt",
                  sources=[
                      "lib/plt/tcp.c", "lib/plt/udp.c", "lib/plt/icmp.c", "lib/plt/icmp6.c",
                      "lib/plt/ip6.c", "lib/plt/ip.c", "lib/plt/internet.c",
                      "lib/plt/layers.c",
                      "lib/plt/packet.c", "lib/plt/trace.c", "lib/plt/outputtrace.c",
                      "lib/plt/pltmodule.c"],
                  libraries=['trace'],
                  library_dirs=['/usr/local/lib'],
                  include_dirs = ['lib/include'],
        ),
        Extension("pldns",
                  sources=["lib/pldns/pldns.c"],
                  libraries=['ldns'],
                  library_dirs=['/usr/local/lib'],
                  include_dirs = ['lib/include'],
        )
    ],
)
