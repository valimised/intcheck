#!/usr/bin/python2.7
# -*- coding: UTF8 -*-

#Copyright (c) 2011 - 2013 Cybernetica AS

"""
Tool for integrity checking directory-tree.

Checksum for a file is SHA-256 over its contents
Checksum for a directory is SHA-256 over directory-representation:

Checksums are stored in HEX encoding

* Checksums of all the files in directory are gathered
* Checksums of all the subdirectories are gathered
* The list of checksums is sorted alphabetically
* The list is concatenated - this concatenation is the directory-representation

All the checksums are stored in the integrity-check file (ICF)

The verification fails if:

* There are missing files or directories
* There are extra files or directories
* The contents of directories have changed
* The contents of files have changed

Otherwise the verification shall be successful
"""

import sys
import os
import os.path

READ_BUFFER_SIZE = 4096

METH_USAGE = 'meth_usage'
METH_EXEC = 'meth_exec'
METH_CHECK = 'meth_check'

COMMAND = None

ERR_ARGUMENTS = 'Invalid number of arguments'
ERR_OK = ''

def canonic_name(name, prefix):
    return name.replace(prefix, './', 1)

def canonic_root(root):
    if not root.endswith('/'):
        root += '/'
    return root

def walkerror(err):
    print 'WARNING! File or directory not included: "%s"' % err

# Checksum methods

def compute_checksum(ffile):
    import hashlib
    _rf = None
    try:
        _rf = open(ffile, "r")
        _s = hashlib.sha256() # pylint: disable=E1101
        _data = _rf.read(READ_BUFFER_SIZE)
        while _data:
            _s.update(_data)
            _data = _rf.read(READ_BUFFER_SIZE)

        return _s.hexdigest()
    finally:
        if _rf:
            _rf.close()


def compute_directory_checksum(lst):
    import hashlib
    _s = hashlib.sha256() # pylint: disable=E1101
    for el in lst:
        _s.update(el)
    return _s.hexdigest()


def analyze_directory(directory):
    checksums = {}
    # The directory tree is traversed in bottom-up order so that
    # we already have children's results when we analyze the parent
    for root, dirs, files in os.walk(directory, \
                                        topdown = False, onerror = walkerror):

        # We use canonic names to overcome naming problems
        # in case of different mountpoints
        rcn = canonic_name(root, directory)

        print 'Analyzing directory "%s" containing %d file(s), %d dir(s)' % \
                (rcn, len(files), len(dirs))

        # Checksum of the directory is the checksum of its children
        input_cs = []

        # First find checksums of subdirectories
        for dname in dirs:
            dn = os.path.join(root, dname)
            cdn = canonic_name(dn, directory)
            if os.path.islink(dn):
                continue

            if checksums.has_key(cdn):
                input_cs.append(checksums[cdn])
            else:
                print 'WARNING! Checksum for "%s" was not found' % cdn

        # Second find checksums for the files
        for fname in files:
            fn = os.path.join(root, fname)
            cfn = canonic_name(fn, directory)
            if os.path.islink(fn):
                continue

            cs = compute_checksum(fn)
            input_cs.append(cs)
            checksums[cfn] = cs

        # Sort the list to ensure deterministic outcome
        input_cs.sort()

        dcs = compute_directory_checksum(input_cs)

        # Cache the checksum for later use
        checksums[rcn] = dcs

    return checksums

# CMD help

def check_help():
    if not (len(sys.argv) == 3):
        return False, ERR_ARGUMENTS
    if not (sys.argv[2] in CMD_LIST.keys()):
        return False, 'Unknown command'
    return True, ERR_OK

def usage_help():
    print 'Command: HELP'
    print 'Display help-text about one of the available commands'
    print 'Usage: %s help <cmd>' % sys.argv[0]
    print '\t<cmd>:\t%s' % CMD_LIST.keys()

def exec_help():
    command = CMD_LIST[sys.argv[2]]
    command[METH_USAGE]()


# CMD create

def check_create():
    if not (len(sys.argv) == 4):
        return False, ERR_ARGUMENTS

    directory = sys.argv[2]
    if not os.path.exists(directory):
        return False, 'Path does not exist'

    if not os.path.isdir(directory):
        return False, 'Path is not a directory'

    of = sys.argv[3]
    if os.path.exists(of):
        return False, 'File "%s" already exists' % of

    return True, ERR_OK

def usage_create():
    print 'Command: CREATE'
    print 'Create integrity-check file (ICF) for given directory'
    print 'Usage: %s create <dir> <icf>' % sys.argv[0]
    print '\t<dir>:\tDirectory to create integrity-check file for'
    print '\t<icf>:\tIntegrity-check file to be created'


def exec_create():
    directory = sys.argv[2]
    outfile = sys.argv[3]

    results = analyze_directory(canonic_root(directory))

    _of = None
    try:
        _of = open(outfile, 'w')

        files = results.keys()
        files.sort()
        for el in files:
            _of.write('%s\t%s\n' % (results[el], el))
    finally:
        if _of:
            _of.close()


# CMD verify

def check_verify():
    if not (len(sys.argv) == 4):
        return False, ERR_ARGUMENTS

    directory = sys.argv[2]
    if not os.path.exists(directory):
        return False, 'Path does not exist'

    if not os.path.isdir(directory):
        return False, 'Path is not a directory'

    inf = sys.argv[3]
    if not os.path.exists(inf):
        return False, 'File "%s" does not exist' % inf

    if not os.path.isfile(inf):
        return False, 'Not a file: "%s"' % inf

    return True, ERR_OK

def usage_verify():
    print 'Command: VERIFY'
    print 'Verify integrity-check file (ICF) for given directory'
    print 'Usage: %s verify <dir> <icf>' % sys.argv[0]
    print '\t<dir>:\tDirectory to verify integrity-check file against'
    print '\t<icf>:\tIntegrity-check file to be used in verification'


def check_equal(disk, sign):

    ret = True

    disk_keys = disk.keys()
    disk_keys.sort()

    for el in disk_keys:

        if not sign.has_key(el):
            ret = False
            print 'ERROR! File "%s" is on DISK, but not in ICF' % el
            continue

        if not sign[el] == disk[el]:
            ret = False
            print 'ERROR! Checksums for "%s" differ: DISK(%s), ICF(%s)' % \
                            (el, disk[el], sign[el])

        del sign[el]

    sign_keys = sign.keys()
    sign_keys.sort()

    for el in sign_keys:
        print 'ERROR! File "%s" is in ICF, but not on DISK' % el

    return ret



def exec_verify():
    directory = sys.argv[2]
    infile = sys.argv[3]

    results_dir = analyze_directory(canonic_root(directory))
    results_file = {}

    _if = None
    try:
        _if = open(infile, 'r')
        lines = _if.readlines()
        for line in lines:
            record = line.rstrip().split('\t')
            if not len(record) == 2:
                raise Exception, 'Invalid input'
            results_file[record[1]] = record[0]
    finally:
        if _if:
            _if.close()

    if not check_equal(results_dir, results_file):
        print 'ERROR - Integrity check failed'
    else:
        print 'OK - Integrity check successful'
        print 'All directory and file checksums verified correctly'


CMD_CREATE = {METH_CHECK: check_create, \
            METH_EXEC: exec_create, \
            METH_USAGE: usage_create}

CMD_VERIFY = {METH_CHECK: check_verify, \
            METH_EXEC: exec_verify, \
            METH_USAGE: usage_verify}

CMD_HELP = {METH_CHECK: check_help, \
            METH_EXEC: exec_help, \
            METH_USAGE: usage_help}


CMD_LIST = {'create': CMD_CREATE, \
            'verify': CMD_VERIFY, \
            'help': CMD_HELP}


def usage():
    print 'Directory-structure integrity verification tool'
    print 'Usage: %s <cmd> <args>' % sys.argv[0]
    print '\t<cmd>:\t\t%s' % CMD_LIST.keys()
    print '\t<args>:\t\t%s help <cmd>' % sys.argv[0]
    sys.exit(0)


def check_usage():
    if len(sys.argv) < 2:
        usage()

    cmd = sys.argv[1]
    if not cmd in CMD_LIST:
        usage()

    global COMMAND
    COMMAND = CMD_LIST[cmd]

    res, ret_str = COMMAND[METH_CHECK]()

    if not res:
        print 'ERROR occured while executing command %s:' % cmd,
        print '"%s"' % ret_str
        COMMAND[METH_USAGE]()
        sys.exit(0)


if __name__ == '__main__':

    try:
        check_usage()
        if COMMAND:
            COMMAND[METH_EXEC]()
        else:
            print 'Error - unknown command'
    finally:
        pass


# vim:set ts=4 sw=4 et fileencoding=utf8:
