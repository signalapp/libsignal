#!/usr/bin/env python3

#
# Copyright (C) 2020-2021 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

import difflib
import itertools
import os
import subprocess
import re
import sys


# If the command-line handling below gets any more complicated, this should be switched to argparse.
def print_usage_and_exit():
    print('usage: %s [--verify]' % sys.argv[0], file=sys.stderr)
    sys.exit(2)


def translate_to_ts(typ):
    typ = typ.replace(' ', '')

    type_map = {
        "()": "void",
        "&[u8]": "Buffer",
        "i32": "number",
        "u8": "number",
        "u32": "number",
        "u64": "Buffer",  # FIXME: eventually this should be a bigint
        "bool": "boolean",
        "String": "string",
        "&str": "string",
        "Vec<u8>": "Buffer",
        "Context": "null",
        "ServiceId": "Buffer",
        "Aci": "Buffer",
        "Pni": "Buffer",
    }

    if typ in type_map:
        return type_map[typ]

    if typ.startswith('[u8;') or typ.startswith('&[u8;'):
        return 'Buffer'

    if typ.startswith('&mutdyn'):
        return typ[7:]

    if typ.startswith('&mut'):
        return 'Wrapper<' + typ[4:] + '>'

    if typ.startswith('&[&'):
        assert typ.endswith(']')
        return 'Wrapper<' + translate_to_ts(typ[3:-1]) + '>[]'

    if typ.startswith('&['):
        assert typ.endswith(']')
        return 'Wrapper<' + translate_to_ts(typ[2:-1]) + '>[]'

    if typ.startswith('&'):
        return 'Wrapper<' + typ[1:] + '>'

    if typ.startswith('Option<'):
        assert typ.endswith('>')
        return translate_to_ts(typ[7:-1]) + ' | null'

    if typ.startswith('Result<'):
        assert typ.endswith('>')
        if ',' in typ:
            success_type = typ[7:].split(',')[0]
        else:
            success_type = typ[7:-1]
        return translate_to_ts(success_type)

    if typ.startswith('Promise<'):
        assert typ.endswith('>')
        return 'Promise<' + translate_to_ts(typ[8:-1]) + '>'

    return typ


ignore_this_warning = re.compile(
    "("
    r"warning: \d+ warnings? emitted"
    ")")


def camelcase(arg):
    parts = arg.split('_')
    return parts[0] + ''.join(x.title() for x in parts[1:])


def collect_decls(crate_dir, features=()):
    args = [
        'cargo',
        'rustc',
        '-q',
        '--profile=check',
        '--features', ','.join(features),
        '--message-format=short',
        '--',
        '-Zunpretty=expanded']
    rustc = subprocess.Popen(args, cwd=crate_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    (stdout, stderr) = rustc.communicate()

    stdout = str(stdout.decode('utf8'))
    stderr = str(stderr.decode('utf8'))

    had_error = False
    for l in stderr.split('\n'):
        if l == "":
            continue

        if ignore_this_warning.match(l):
            continue

        print(l, file=sys.stderr)
        had_error = True

    if had_error:
        print("Exiting with error")
        sys.exit(1)

    comment_decl = re.compile(r'\s*///\s*ts: (.+)')
    # Note that the doc attribute is sometimes wrapped onto two lines.
    attr_decl = re.compile(r'\s*(?:#\[doc\s*=\s*)?"ts: (.+)"\]')

    # Make sure /not/ to match arguments with nested parentheses,
    # which won't survive textual splitting below.
    function_sig = re.compile(r'(.+)\(([^()]*)\): (.+);?')

    for line in stdout.split('\n'):
        match = comment_decl.match(line) or attr_decl.match(line)
        if match is None:
            continue

        (decl,) = match.groups()

        function_match = function_sig.match(decl)
        if function_match is None:
            yield decl
            continue

        (prefix, args, ret_type) = function_match.groups()

        ts_ret_type = translate_to_ts(ret_type)
        ts_args = []
        if args:
            if '::' in args:
                raise Exception(f'Paths are not supported. Use alias for the type of \'{args}\'')

            for arg in args.split(', '):
                (arg_name, arg_type) = arg.split(': ')
                ts_arg_type = translate_to_ts(arg_type)
                ts_args.append('%s: %s' % (camelcase(arg_name.strip()), ts_arg_type))

        yield '%s(%s): %s;' % (prefix, ', '.join(ts_args), ts_ret_type)


mode = None
if len(sys.argv) > 2:
    print_usage_and_exit()
elif len(sys.argv) == 2:
    mode = sys.argv[1]
    if mode != '--verify':
        print_usage_and_exit()

our_abs_dir = os.path.dirname(os.path.realpath(__file__))

decls = itertools.chain(
    collect_decls(os.path.join(our_abs_dir, '..')),
    collect_decls(os.path.join(our_abs_dir, '..', '..', 'shared'), features=('node', 'signal-media')))

output_file_name = 'Native.d.ts'
contents = open(os.path.join(our_abs_dir, output_file_name + '.in')).read()
contents += "\n"
contents += "\n".join(sorted(decls))
contents += "\n"

output_file = os.path.join(our_abs_dir, '..', '..', '..', '..', 'node', output_file_name)

if not os.access(output_file, os.F_OK):
    raise Exception("Didn't find %s where it was expected" % output_file_name)

if not mode:
    with open(output_file, 'w') as fh:
        fh.write(contents)
elif mode == '--verify':
    with open(output_file) as fh:
        current_contents = fh.readlines()
    diff = difflib.unified_diff(current_contents, contents.splitlines(keepends=True))
    first_line = next(diff, None)
    if first_line:
        sys.stdout.write(first_line)
        sys.stdout.writelines(diff)
        sys.exit("error: %s not up to date; re-run %s!" % (output_file_name, sys.argv[0]))
else:
    raise Exception("mode not properly validated")
