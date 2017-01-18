#!/usr/bin/env python

# Copyright (C) 2017 by Nevil Brownlee, U Auckland | WAND

import glob, re, os

def find_copyright(fn):
    #f = open(fn+".new", "r")
    f = open(fn, "r")
    print fn
    for line in f:
        if line.find("yright") >= 0:
            print "   %s" % line.strip()
            f.close()
            return True
    f.close()
    return False

def fix_file(fn, yyyy):
    print fn
    f = open(fn, "r");  nf = open(fn+".new", "w")
    for line in f:
        if line.find("yright") >= 0:
            #la = line.split('2014')
            la = re.split("20\d\d", line)
            print "--- %s" % la
            if len(la) == 2:
                nf.write(la[0] + yyyy + la[1])
            else:
                nf.write(line)
            #print "la = %s" % la
        else:
            nf.write(line)
    nf.close();  f.close()
    os.rename(fn+".new", fn)
    
def checkfiles(gstr, yyyy):
    for fn in glob.glob(gstr):
        find_copyright(fn)
        fix_file(fn, yyyy)

new_yyy = "2017"

checkfiles("*.py", new_yyy)
checkfiles("*.sh", new_yyy)
checkfiles("Makefile", new_yyy)
checkfiles("README", new_yyy)

checkfiles("lib/*/*.c", new_yyy)
checkfiles("lib/*/*.h", new_yyy)
checkfiles("test/*/*.py", new_yyy)
checkfiles("doc/examples/*.py", new_yyy)

