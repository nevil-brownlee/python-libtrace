#!/usr/bin/env python

# Copyright (C) 2015 by Nevil Brownlee, U Auckland | WAND

import glob, os

def find_copyright(fn):
    #f = open(fn+".new", "r")
    f = open(fn, "r")
    print fn
    for line in f:
        if line.find("yright") >= 0:
            print "   %s" % line.strip()
            return True
    f.close()
    return False

def fix_file(fn):
    print fn
    f = open(fn, "r");  nf = open(fn+".new", "w")
    for line in f:
        if line.find("yright") >= 0:
            la = line.split("2014")
            if len(la) == 2:
                nf.write(la[0] + "2015" + la[1])
            else:
                nf.write(line)
            #print "la = %s" % la
        else:
            nf.write(line)
    nf.close();  f.close()
    #os.rename(fn+".new", fn)
    
def checkfiles(gstr):
    for fn in glob.glob(gstr):
        find_copyright(fn)
        #fix_file(fn)

checkfiles("*.py")
checkfiles("*.sh")
checkfiles("Makefile")
checkfiles("README")

checkfiles("lib/*/*.c")
checkfiles("lib/*/*.h")
checkfiles("test/*/*.py")
checkfiles("doc/examples/*.py")

