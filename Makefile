# 1410, Sat 15 Mar 14 (PDT)
#
# Main Makefile for the python-libtrace distribution.
#
# python-libtrace: a python module to make it easy to use libtrace
# Copyright (C) 2015 by Nevil Brownlee, U Auckland | WAND
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


SHELL=/bin/sh
RM=rm -rf # Don't complain it files don't exist
T_MAKE=	make
BKFILES=build *~ \#* .*~
VERSION=

.PHONY:	all clean distclean install

build: 
	cd lib/ipp; python$(VERSION) ipp-setup.py build
	cd lib/plt; python$(VERSION) plt-setup.py build
	cd lib/natkit; python$(VERSION) natkit-setup.py build
	cd lib/pldns; python$(VERSION) pldns-setup.py build

install: build
	cd lib/ipp; python$(VERSION) ipp-setup.py install
	cd lib/plt; python$(VERSION) plt-setup.py install
	cd lib/natkit; python$(VERSION) natkit-setup.py install
	cd lib/pldns; python$(VERSION) pldns-setup.py install
	@./verify_install.sh $(VERSION)

clean:
	cd lib/ipp; $(RM) $(BKFILES)
	cd lib/plt; $(RM) $(BKFILES)
	cd lib/natkit; $(RM) $(BKFILES)
	cd lib/pldns; $(RM) $(BKFILES)

distclean: clean
	$(RM)  $(BKFILES)

py2: 
	@make VERSION=2 build 

py3: 
	@make VERSION=3 build

install-py2: 
	@make VERSION=2 install

install-py3: 
	@make VERSION=3 install
