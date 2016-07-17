#!/bin/sh

# 1423, Sat 15 Mar 14 (PDT)
#
# Make python-libtrace distribution tarball
#
# python-libtrace: a Ruby module to make it easy to use libtrace
# Copyright (C) 2008 by Nevil Brownlee, U Auckland | WAND
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


VER=`./plt-version.py`
echo "Making tarball for $VER  ..."

OLD=`echo ${PWD##*/}`  # Current directory name
N="python-libtrace-${VER}"  # New directory name

cd ..
if [ $OLD != $N ]
then
  mv $OLD $N
fi

tar zcf ${N}.tgz \
   $N/LICENSE $N/README $N/INSTALL $N/version.history \
   $N/Makefile $N/*.py $N/*.sh $N/exclude-list.txt \
   $N/lib/ipp/*.py $N/lib/ipp/*.c \
   $N/lib/plt/*.py $N/lib/plt/*.c \
   $N/lib/natkit/*.py $N/lib/natkit/*.c \
   $N/lib/pldns/*.py $N/lib/pldns/*.c \
   $N/lib/include/pv.h $N/lib/include/plt.h \
   $N/doc/*.html $N/doc/*.css  $N/doc/*.svg \
   $N/doc/examples/*.py $N/doc/examples/*.pcap\
   $N/test/run_test.py \
   $N/test/v2-test-cases/*.py $N/test/v2-test-cases/*.res \
   $N/test/v2-test-cases/*.pcap* \
   $N/test/v3-test-cases/*.py $N/test/v3-test-cases/*.res \
   $N/test/v3-test-cases/*.pcap* \

if [ $OLD != $N ]
then
mv $N $OLD
fi
cd $OLD
