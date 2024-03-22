#!/usr/bin/env python3

# Copyright (c) 2011–2024 Cybernetica AS

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


import argparse
import hashlib
import logging
import os.path
import sys


READ_BUFFER_SIZE = 4096

EXIT_OK = 0
EXIT_ERR = 1
EXIT_VERIFY = 2
EXIT_USAGE = 3

log = logging.getLogger(__name__)


def canonic_name(name, prefix):
    return name.replace(prefix, './', 1)


def canonic_root(root):
    if not root.endswith('/'):
        root += '/'
    return root


def walkerror(err):
    log.warning("File or directory not included: %r", err)


# Checksum methods

def compute_checksum(ffile):
    _s = hashlib.sha256()
    with open(ffile, 'rb') as _rf:
        _data = _rf.read(READ_BUFFER_SIZE)
        while _data:
            _s.update(_data)
            _data = _rf.read(READ_BUFFER_SIZE)
    return _s.hexdigest()


def compute_directory_checksum(lst):
    _s = hashlib.sha256()
    for el in lst:
        _s.update(el.encode('utf-8'))
    return _s.hexdigest()


def analyze_directory(directory):
    checksums = {}
    # The directory tree is traversed in bottom-up order so that
    # we already have children's results when we analyze the parent
    for root, dirs, files in os.walk(directory, topdown=False,
                                     onerror=walkerror):

        # We use canonic names to overcome naming problems
        # in case of different mountpoints
        rcn = canonic_name(root, directory)

        print(f'Analyzing directory "{rcn}" containing '
              f'{len(files)} file(s), {len(dirs)} dir(s)')

        # Checksum of the directory is the checksum of its children
        input_cs = []

        # First find checksums of subdirectories
        for dname in dirs:
            dn = os.path.join(root, dname)
            cdn = canonic_name(dn, directory)
            if os.path.islink(dn):
                continue

            if cdn in checksums:
                input_cs.append(checksums[cdn])
            else:
                log.warning("Checksum for %r was not found", cdn)

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


def exec_create(directory, outfile):
    results = analyze_directory(canonic_root(directory))
    with open(outfile, 'w') as _of:
        for el in sorted(results):
            _of.write(f"{results[el]}\t{el}\n")


def check_equal(disk, sign):

    ret = True

    for ffile in sorted(disk):

        if ffile not in sign:
            ret = False
            log.error("File %r is on DISK, but not in ICF", ffile)
            continue

        if not sign[ffile] == disk[ffile]:
            ret = False
            log.error(
                "Checksums for %r differ: DISK(%s), ICF(%s)",
                ffile,
                disk[ffile],
                sign[ffile],
            )

        del sign[ffile]

    for ffile in sorted(sign):
        log.error("File %r is in ICF, but not on DISK", ffile)

    return ret


def exec_verify(directory, infile):
    results_dir = analyze_directory(canonic_root(directory))
    results_file = {}

    with open(infile, 'r') as _if:
        for line_no, line in enumerate(_if.readlines(), start=1):
            try:
                checksum, filepath = line.rstrip().split("\t")
            except ValueError:
                log.error("Invalid line #%d: %r", line_no, line)
                return False
            results_file[filepath] = checksum

    return check_equal(results_dir, results_file)


class ExistingDirectory(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if not os.path.exists(values):
            raise ValueError(f'Path "{values}" does not exist')

        if not os.path.isdir(values):
            raise ValueError(f'Path "{values}" is not a directory')

        setattr(namespace, self.dest, values)


class ExistingFile(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):

        if not os.path.exists(values):
            raise ValueError(f'File "{values}" does not exist')

        if not os.path.isfile(values):
            raise ValueError(f'Not a file: "{values}"')

        setattr(namespace, self.dest, values)


class NewFile(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if os.path.exists(values):
            raise ValueError(f'File "{values}" already exists')
        setattr(namespace, self.dest, values)


class IntcheckParser:

    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description='Directory-structure integrity verification tool',
            usage='''intcheck <command> [<args>]

The available commands are:
   create     Create directory integrity-check file
   verify     Verify directory integrity-check file
''')
        self.parser.add_argument('command', help='Subcommand to run')

    def parse(self):
        args = self.parser.parse_args(sys.argv[1:2])

        if not hasattr(self, args.command):
            log.error("Unrecognized command")
            self.parser.print_help()
            sys.exit(EXIT_USAGE)
        return args.command, getattr(self, args.command)()

    def create(self):
        pp = argparse.ArgumentParser(
            description='Create directory integrity-check file (ICF)')
        pp.add_argument('directory',
                        action=ExistingDirectory,
                        help='Directory to create ICF for')
        pp.add_argument('icf',
                        action=NewFile,
                        help='ICF to be created')
        args = pp.parse_args(sys.argv[2:])
        return args

    def verify(self):
        pp = argparse.ArgumentParser(
            description='Verify directory integrity-check file (ICF)')
        pp.add_argument('directory',
                        action=ExistingDirectory,
                        help='Directory to verify ICF against')
        pp.add_argument('icf',
                        action=ExistingFile,
                        help='ICF to be used in verification')
        args = pp.parse_args(sys.argv[2:])
        return args


def main():
    """Main routine."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    parser = IntcheckParser()
    try:
        cmd, args = parser.parse()
    except ValueError as err:
        log.error(str(err))
        return EXIT_ERR

    if cmd == 'verify':
        if not exec_verify(args.directory, args.icf):
            log.error("Integrity check failed")
            return EXIT_VERIFY

        print('OK - Integrity check successful')
        print('All directory and file checksums verified correctly')

    elif cmd == 'create':
        exec_create(args.directory, args.icf)
        print('OK - Integrity file created successfully')

    return EXIT_OK


if __name__ == '__main__':
    sys.exit(main())
