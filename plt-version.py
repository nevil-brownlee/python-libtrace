#!/usr/bin/env python

import re

f = open('lib/include/plt.h', 'r')
for line in f:
    match = re.match(r'.*PLTversion\s+\"(.+)\"', line)
    if match:
        print match.group(1)
        exit()
