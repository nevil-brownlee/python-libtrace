import ipp, sys, re

def test_string(name, val):
    print "%s = %s" % (name, val)
    try:
        prefix = ipp.from_s(val)
        print "%s = %s\n" % (name, prefix)
        ps = str(prefix)
        if ps.find("::") >= 0:
            #sl = re.findall("[^:]:[^:]", ps)
            sc = ps.replace("::", "!")
            if sc.count(":") == 5:
                nps = sc.replace("!", ":0:");
                print ">>> nps = %s\n" % nps
            
    except Exception, err:
        #traceback.print_exc()
        print "err = %s" % err

test_string("p61", "2001:df0:0:321:1:2:3:4/128")
test_string("p62", "2001:df0:0:0:1:2:3:4/128")
test_string("p63", "2001:df0:0:0:1:2::")
test_string("p64", "2001:df0:0:abcd::1")
test_string("p65", "2001:0:0df0::2")
test_string("p66", "2001::def0::2")
test_string("p67", "::ffff:1.2.3.4")  # From RFC 5952

test_string("p41", "130.216.38.7/24")

test_string("p42", "130.256.0.0")
test_string("p43", "130.216.0.0/33")
test_string("p44", "130.216.0.0/-1")

test_string("p45", "130.216")
test_string("p46", "130.216/24")

p = ipp.from_s("130.216.0.0/24")
print "\np = %s, type(q) = %s" % (p, type(p))
print

ba = bytearray([130, 216, 0, 0])
q = ipp.IPprefix(4, ba, 25)
#q = ipp.IPprefix()
print "q = %s, type(q) = %s" % (q, type(q))

#HomeFlow.py and test-v6-tunnal.py now fail
