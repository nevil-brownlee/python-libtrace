import os, sys
from optparse import OptionParser
from stat import *
import subprocess
import difflib
import re

# color codes
class colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'


class constants:
    SAME = 0
    SUCCESS = 0
    DIFFERENT = 1
    TOO_MANY_ERRORS = -1
    IO_ERROR = 2
    ERROR_THRESHOLD = 10


# prints program usage
def usage():
    sys.stdout.write ('usage: python'+ sys.argv[
        0]+ ' -t|-g -d <test-directory> [-r] [-n <num>] [-f <file-name>] [-w <working-dir>] [-h]\n')

#return python cmd according to the python interpreter version
def get_python_cmd():
    return ('python', 'python3')[sys.version_info[0]-2]

# checks command-line arguments
def check_args(options):
    if options.test_flag == options.gen_flag:
        sys.stdout.write('-t or -g should be specified\n')
        return False

    if options.dir == None:
        sys.stdout.write('test directory is not specified\n')
        return False
    elif not os.path.exists(options.dir):
        sys.stdout.write(options.dir+' does not exist\n')
        return False
    elif not S_ISDIR(os.stat(options.dir).st_mode):
        sys.stdout.write(options.dir+' is not a directory\n')
        return False

    if options.gen_flag and options.n > 1:
        sys.stdout.write('-n cannot be used with -g\n')
        return False

    if options.recursive_flag and options.file != None:
        sys.stdout.write('-r cannot be used with -f\n')
        return False

    if options.file != None:
        if not os.path.exists(options.dir + '/' + options.file):
            sys.stdout.write(options.file+" does not exist\n")
            return False
        elif not S_ISREG(os.stat(options.dir + '/' + options.file).st_mode) or not is_test_file(options.file):
            sys.stdout.write(options.file+" is not a test program\n")
            return False

    return True


# prints out content of a text file
def print_file(file_name):
    try:
        f = open(file_name, "r")
        sys.stdout.write(f.read())
        f.close()
    except:
        sys.stdout.write(colors.FAIL+"Failed: "+str(sys.exc_info()[1])+"\n"+colors.ENDC);
        sys.exit()



# saves data in a file
def write_file(file_name, data):
    try:
        f = open(file_name, "w")
        f.write(data)
        f.close()
    except:
        sys.stdout.write(colors.FAIL+"Failed: "+str(sys.exc_info()[1])+"\n"+colors.ENDC);
        sys.exit()


# runs a shell command
def execute_command(cmd, out_file, err_file):
    process = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out, err) = process.communicate()
    write_file(out_file, out.decode())
    write_file(err_file, err.decode())
    return process.returncode


# runs a test program and compares the result with the expected result file.
def test(dir, file, wdir):
    temp_result = os.path.join(wdir, 'res')
    temp_err = os.path.join(wdir, 'err')
    temp_diff = os.path.join(wdir, 'diff')
    test_prog = os.path.join(dir, file)
    sys.stdout.write('testing '+test_prog+': ')
    os.chdir(dir)

    #running test program
    
    cmd = [get_python_cmd(), test_prog]
    ret = execute_command(cmd, temp_result, temp_err)
    if ret != 0:
        # error running the test
        sys.stdout.write(colors.FAIL+'Failed (error running the test)\n'+colors.ENDC)
        print_file(temp_err)
        return False

    #the test ran without error. compare actual results with the expected results.
    dot = test_prog.rfind('.')
    test_result = test_prog[0:dot + 1] + 'res'
    ret = diff(test_result, temp_result, temp_diff, temp_err)
    if ret == constants.SUCCESS:
        sys.stdout.write('Passed\n')
        return True
    elif ret == constants.DIFFERENT:
        sys.stdout.write(colors.FAIL+'Failed'+colors.ENDC+'\n')
        print_file(temp_diff)
    elif ret == constants.TOO_MANY_ERRORS:
        sys.stdout.write(colors.FAIL+'Failed (too many errors)'+colors.ENDC+'\n')
        print_file(temp_diff)
        return False
    else:
        sys.stdout.write(colors.FAIL+'Failed'+colors.ENDC+'\n')
        print_file(temp_err)
        return False


#generates expected results file for a test
def generate(dir, file, wdir):
    test_prog = os.path.join(dir, file)
    temp_err = os.path.join(wdir, 'err')
    dot = test_prog.rfind('.')
    test_result = test_prog[0:dot + 1] + 'res'
    sys.stdout.write('Generating result file for '+test_prog+': ')
    os.chdir(dir)

    # run test program
    cmd = [get_python_cmd(), test_prog]
    ret = execute_command(cmd, test_result, temp_err)
    if ret != constants.SUCCESS:
        sys.stdout.write(colors.FAIL+'Failed (error running the test)'+colors.ENDC+'\n')
        print_file(temp_err)
        return False
    else:
        sys.stdout.write('Done\n')
        return True


#checks the file name extension to make sure it is a python program
def is_test_file(file_name):
    pattern = re.compile(r'test-.*\.py')
    if pattern.match(file_name):
        return True
    return False


#a wrapper which calls test or generate based on test_flag.
def run_test_prog(dir, file, wdir, test_flag):
    if test_flag:
        return test(dir, file, wdir)
    else:
        return generate(dir, file, wdir)


#compares two text files, line by line, and stores the differences in a third file.
#For every different line, the different columns are also tagged.
def diff(expected_result, actual_result, diff_result, diff_error):
    # open required files
    try:
        err = open(diff_error, 'w')
        expected = open(expected_result, 'r')
        actual = open(actual_result, 'r')
        diff = open(diff_result, 'w')
    except IOError as e:
        err.write('Failed: ' + e.strerror + ' (' + e.filename + ')\n')
        return constants.IO_ERROR

    # first try to compare files line by line and identify errors in each line, if there is any
    differ = constants.SAME
    too_many_errors = False
    for e_line, a_line in zip(expected, actual):
        if e_line != a_line:
            d = difflib.SequenceMatcher(None, e_line, a_line)
            indicator = ' ' * len(a_line)
            num_diff = 0;
            for ei, ai, size in d.get_matching_blocks():
                index = ai + size
                if index < len(a_line):
                    indicator = indicator[0:ai + size] + "^" + indicator[ai + size + 1:]
                    num_diff = num_diff + 1
            if (num_diff > constants.ERROR_THRESHOLD):
                # too many errors, might be a missing or added line. break and
                # use utility 'diff'.
                too_many_errors = True
                break;
            diff.write("  expected: %s  actual:   %s            %s\n" % (e_line, a_line, indicator))
            differ = constants.DIFFERENT

    # close files
    diff.close()
    expected.close()
    actual.close()
    err.close()

    # if there are too many differences, use utility 'diff'
    if (too_many_errors):
        cmd = ['diff', '-a', '--new-line-format=''  actual:   %L''', '--old-line-format=''  expected: %L''',
               '--unchanged-line-format=', expected_result, actual_result]
        differ = execute_command(cmd, diff_result, diff_error)
        if (differ == constants.DIFFERENT):
            differ = constants.TOO_MANY_ERRORS

    return differ


# Main Program

# define command-line arguments
parser = OptionParser()
parser.add_option("-t", action="store_true", dest='test_flag', default=False,
                  help="runs test program(s) and compares the result(s) with expected result(s).")
parser.add_option("-g", action="store_true", dest='gen_flag', default=False,
                  help="generates result file(s) and stores it/them in the same folder as the test program(s).")
parser.add_option("-d", dest="dir", default=None, help="test folder which contains test programs.")
parser.add_option("-r", action="store_true", dest='recursive_flag', default=False,
                  help="traverses the test folder recursively and runs/generates all tests.")
parser.add_option("-n", dest="n", type="int", default=1, help="number of runs (0: infinite, default: 1).")
parser.add_option("-f", dest="file", help="test file name.")
parser.add_option("-w", dest="wdir", default="/tmp", help="working directory (default: /tmp).")

# parse command-line arguments
(Options, args) = parser.parse_args()

# exit if there is an error in command-line arguments
if check_args(Options) == False:
    sys.stdout.write(sys.argv[0] + ": Failed\n")
    usage()
    sys.exit()

Options.dir = os.path.abspath(Options.dir)

# counters to count the number of successful and failed operations.
success = 0
failed = 0

i = 0
while i < Options.n or Options.n == 0:
    if Options.n != 1:
        sys.stdout.write(colors.HEADER+'\n'+'Run #'+ str(i + 1) +':'+colors.ENDC+ '\n')

    if Options.file != None:
        # run a single test file
        if run_test_prog(Options.dir, Options.file, Options.wdir, Options.test_flag):
            success = success + 1
        else:
            failed = failed + 1
    else:
        # Walk the directory tree and run tests.
        for root, directories, files in os.walk(Options.dir):
            for file_name in files:
                if is_test_file(file_name):
                    if run_test_prog(root, file_name, Options.wdir, Options.test_flag):
                        success = success + 1
                    else:
                        failed = failed + 1
            # if -r is not specified, then do not go deeper.
            if (not Options.recursive_flag):
                break
    i = i + 1

sys.stdout.write('\n''successful: '+str(success)+'\n')
sys.stdout.write('failed: '+str(failed)+'\n')
