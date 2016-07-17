
import ipp

v61 = ipp.from_s("d001:0df:0:123:0:0:130:216:38:123")
v62 = ipp.from_s("e001:0df:0:123::130:216:38:123")
v63 = ipp.from_s("f001:0df::123:0:0:130:216:38:123")

print "ascii  2001:0df:0:123:0:0:130:216:38:123"
print "  v61  %s" % v61
print "  v62  %s" % v62
print "  v63  %s" % v63

