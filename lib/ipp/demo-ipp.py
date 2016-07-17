import ipp, resource

#a = bytearray(b"Hell")
a = bytearray([130, 216, 38, 7])
p = ipp.IPprefix(4, a, 32)
print "p = %s, type = %s" % (str(p), type(p))

for n in range(0,100000):
    if (n % 10000):
        print "using %d" % resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

