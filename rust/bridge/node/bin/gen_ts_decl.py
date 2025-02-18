#!/usr/bin/env python3

#
# Copyright (C) 2020-2021 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

import collections
import difflib
import itertools
import os
import subprocess
import re
import sys

from typing import Iterable, Iterator, Tuple

Args = collections.namedtuple('Args', ['verify'])


def parse_args() -> Args:
    def print_usage_and_exit() -> None:
        print('usage: %s [--verify]' % sys.argv[0], file=sys.stderr)
        sys.exit(2)

    # If the command-line handling below gets any more complicated, this should be switched to argparse.
    mode = None
    if len(sys.argv) > 2:
        print_usage_and_exit()
    elif len(sys.argv) == 2:
        mode = sys.argv[1]
        if mode != '--verify':
            print_usage_and_exit()

    return Args(verify=mode is not None)


def split_rust_args(args: str) -> Iterator[Tuple[str, str]]:
    """
    Split Rust `arg: Type` pairs separated by commas.

    Account for templates, tuples, and slices.
    """
    while ':' in args:
        (name, args) = args.split(':', maxsplit=1)
        if name.startswith('mut '):
            name = name[4:]
        open_pairs = 0
        for (i, c) in enumerate(args):
            if c == ',' and open_pairs == 0:
                ty = args[:i]
                args = args[i + 1:]
                yield (name.strip(), ty.strip())
                break
            elif c in ['<', '(', '[']:
                open_pairs += 1
            elif c in ['>', ')', ']']:
                open_pairs -= 1
        else:
            yield (name.strip(), args.strip())


def translate_to_ts(typ: str) -> str:
    typ = typ.replace(' ', '')

    type_map = {
        "()": "void",
        "&[u8]": "Buffer",
        "i32": "number",
        "u8": "number",
        "u16": "number",
        "u32": "number",
        "u64": "bigint",
        "bool": "boolean",
        "String": "string",
        "&str": "string",
        "Vec<u8>": "Buffer",
        "Box<[u8]>": "Buffer",
        "ServiceId": "Buffer",
        "Aci": "Buffer",
        "Pni": "Buffer",
        "E164": "string",
        "ServiceIdSequence<'_>": "Buffer",
        "PathAndQuery": "string",
    }

    if typ in type_map:
        return type_map[typ]

    if typ.startswith('[u8;') or typ.startswith('&[u8;'):
        return 'Buffer'

    if typ.startswith('&mutdyn'):
        return typ[7:]

    if typ.startswith('&dyn'):
        return typ[4:]

    if typ.startswith('&mut'):
        return 'Wrapper<' + typ[4:] + '>'

    if typ.startswith('&[&'):
        assert typ.endswith(']')
        return 'Wrapper<' + translate_to_ts(typ[3:-1]) + '>[]'

    if typ.startswith('Box<['):
        assert typ.endswith(']>')
        return translate_to_ts(typ[5:-2]) + '[]'

    if typ.startswith('Box<dyn'):
        assert typ.endswith('>')
        return translate_to_ts(typ[7:-1])

    if typ.startswith('Vec<'):
        assert typ.endswith('>')
        return translate_to_ts(typ[4:-1]) + '[]'

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

    if typ.startswith('CancellablePromise<'):
        assert typ.endswith('>')
        return 'CancellablePromise<' + translate_to_ts(typ[19:-1]) + '>'

    if typ.startswith('AsType<'):
        assert typ.endswith('>')
        assert ',' in typ
        return translate_to_ts(typ.split(',')[1][:-1])

    if typ.startswith('Ignored<'):
        assert typ.endswith('>')
        return 'null'

    return typ


DIAGNOSTICS_TO_IGNORE = [
    r"warning: \d+ warnings? emitted",
    r"warning: unused import",
    r"warning: field.+ never read",
    r"warning: variant.+ never constructed",
    r"warning: method.+ never used",
    r"warning: associated function.+ never used",
]
SHOULD_IGNORE_PATTERN = re.compile("(" + ")|(".join(DIAGNOSTICS_TO_IGNORE) + ")")


def camelcase(arg: str) -> str:
    return re.sub(
        # Preserve double-underscores and leading underscores,
        # but remove single underscores and capitalize the following letter.
        r'([^_])_([^_])',
        lambda match: match.group(1) + match.group(2).upper(),
        arg)


def collect_decls(crate_dir: str, features: Iterable[str] = ()) -> Iterator[str]:
    args = [
        'cargo',
        'rustc',
        '-q',
        '--profile=check',
        '--features', ','.join(features),
        '--message-format=short',
        '--color=never',
        '--',
        '-Zunpretty=expanded']
    rustc = subprocess.Popen(args, cwd=crate_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    (raw_stdout, raw_stderr) = rustc.communicate()

    stdout = str(raw_stdout.decode('utf8'))
    stderr = str(raw_stderr.decode('utf8'))

    had_error = False
    for l in stderr.split('\n'):
        if l == "":
            continue

        if SHOULD_IGNORE_PATTERN.search(l):
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

        (prefix, fn_args, ret_type) = function_match.groups()

        ts_ret_type = translate_to_ts(ret_type)
        ts_args = []
        if '::' in fn_args:
            raise Exception(f'Paths are not supported. Use alias for the type of \'{fn_args}\'')

        for (arg_name, arg_type) in split_rust_args(fn_args):
            ts_arg_type = translate_to_ts(arg_type)
            ts_args.append('%s: %s' % (camelcase(arg_name.strip()), ts_arg_type))

        yield '%s(%s): %s;' % (prefix, ', '.join(ts_args), ts_ret_type)


def expand_template(template_file: str, decls: Iterable[str]) -> str:
    with open(template_file, "r") as f:
        contents = f.read()
        contents += "\n"
        contents += "\n".join(sorted(decls))
        contents += "\n"

        return contents


def verify_contents(expected_output_file: str, expected_contents: str) -> None:
    with open(expected_output_file) as fh:
        current_contents = fh.readlines()
    diff = difflib.unified_diff(current_contents, expected_contents.splitlines(keepends=True))
    first_line = next(diff, None)
    if first_line:
        sys.stdout.write(first_line)
        sys.stdout.writelines(diff)
        sys.exit(f"error: {expected_output_file} not up to date; re-run {sys.argv[0]}!")


Crate = collections.namedtuple('Crate', ["path", "features"], defaults=[()])


def convert_to_typescript(rust_crates: Iterable[Crate], ts_in_path: str, ts_out_path: str, verify: bool) -> None:
    decls = itertools.chain.from_iterable(collect_decls(crate.path, crate.features) for crate in rust_crates)
    contents = expand_template(ts_in_path, decls)

    if not os.access(ts_out_path, os.F_OK):
        raise Exception(f"Didn't find {ts_out_path} where it was expected")

    if not verify:
        with open(ts_out_path, 'w') as fh:
            fh.write(contents)
    else:
        verify_contents(ts_out_path, contents)


def main() -> None:
    args = parse_args()
    our_abs_dir = os.path.dirname(os.path.realpath(__file__))
    output_file_name = 'Native.d.ts'

    convert_to_typescript(
        rust_crates=[
            Crate(path=os.path.join(our_abs_dir, '..')),
            Crate(path=os.path.join(our_abs_dir, '..', '..', 'shared'), features=('node', 'signal-media')),
            Crate(path=os.path.join(our_abs_dir, '..', '..', 'shared', 'types'), features=('node', 'signal-media')),
            Crate(path=os.path.join(our_abs_dir, '..', '..', 'shared', 'testing'), features=('node', 'signal-media')),
        ],
        ts_in_path=os.path.join(our_abs_dir, output_file_name + '.in'),
        ts_out_path=os.path.join(our_abs_dir, '..', '..', '..', '..', 'node', output_file_name),
        verify=args.verify,
    )


if __name__ == '__main__':
    main()
