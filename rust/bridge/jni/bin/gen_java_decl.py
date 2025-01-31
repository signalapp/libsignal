#!/usr/bin/env python3

#
# Copyright (C) 2020-2021 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

import collections
import difflib
import os
import subprocess
import re
import sys

from typing import Iterable, Iterator, Tuple

Args = collections.namedtuple('Args', 'verify')


def parse_args() -> Args:
    def print_usage_and_exit() -> None:
        print(f'usage: {sys.argv[0]} [--verify]', file=sys.stderr)
        sys.exit(2)

    # If the command-line handling below gets any more complicated, this should be switched to argparse.
    mode = None
    if len(sys.argv) > 2:
        print_usage_and_exit()

    if len(sys.argv) == 2:
        mode = sys.argv[1]
        if mode != '--verify':
            print_usage_and_exit()

    return Args(verify=mode is not None)


IGNORE_THIS_WARNING = re.compile(
    "("
    r"WARN: Can't find .*\. This usually means that this type was incompatible or not found\.|"
    r"WARN: Missing `\[defines\]` entry for `feature = \".*\"` in cbindgen config\.|"
    r"WARN: Missing `\[defines\]` entry for `target_os = \"android\"` in cbindgen config\.|"
    r"WARN: Missing `\[defines\]` entry for `ios_device_as_detected_in_build_rs` in cbindgen config\.|"
    r"WARN: Skip libsignal-bridge(-testing)?::.+ - \(not `(pub|no_mangle)`\)\.|"
    r"WARN: Couldn't find path for Array\(Path\(GenericPath \{ .+ \}\), Name\(\"LEN\"\)\), skipping associated constants|"
    r"WARN: Cannot find a mangling for generic path GenericPath { path: Path { name: \"JavaCompletableFuture\" }.+|"
    r"WARN: Cannot find a mangling for generic path GenericPath { path: Path { name: \"Throwing\" }.+"
    ")")


def run_cbindgen(cwd: str) -> str:
    cbindgen = subprocess.Popen(['cbindgen'], cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    (raw_stdout, raw_stderr) = cbindgen.communicate()

    stdout = str(raw_stdout.decode('utf8'))
    stderr = str(raw_stderr.decode('utf8'))

    unknown_warning = False

    for l in stderr.split('\n'):
        if l == "":
            continue

        if IGNORE_THIS_WARNING.match(l):
            continue

        print(l, file=sys.stderr)
        unknown_warning = True

    if unknown_warning:
        raise Exception("cbindgen produced unknown warning")

    return stdout


def box_primitive_if_needed(typ: str) -> str:
    type_map = {
        "void": "Void",
        "boolean": "Boolean",
        "char": "Character",
        "byte": "Byte",
        "short": "Short",
        "int": "Integer",
        "long": "Long",
        "float": "Float",
        "double": "Double",
    }

    return type_map.get(typ, typ)


def translate_to_java(typ: str) -> Tuple[str, bool]:
    type_map = {
        "void": "void",
        "JString": "String",
        "JObject": "Object",
        "JClass": "Class",
        "JByteArray": "byte[]",
        "JLongArray": "long[]",
        "JObjectArray": "Object[]",
        "ObjectHandle": "long",
        "jint": "int",
        "jlong": "long",
        "jboolean": "boolean",
        "JavaArrayOfByteArray": "byte[][]",
        "JavaByteBufferArray": "ByteBuffer[]",
    }

    if typ in type_map:
        return (type_map[typ], False)

    if typ == 'Throwing':
        return ('void', True)

    if (stripped := typ.removeprefix('Throwing<')) != typ:
        assert stripped.endswith('>')
        return (translate_to_java(stripped.removesuffix('>'))[0], True)

    if (stripped := typ.removeprefix('JavaCompletableFuture<')) != typ:
        assert stripped.endswith('>')
        inner = translate_to_java(stripped.removesuffix('>'))[0]
        return (f'CompletableFuture<{box_primitive_if_needed(inner)}>', False)

    # Assume anything else prefixed with "Java" refers to an object
    if typ.startswith('Java'):
        return (typ[4:], False)

    raise Exception("Don't know what to do with a", typ)


JAVA_DECL = re.compile(r"""
    ([a-zA-Z0-9]+(?:<.+>)?)[ ]                             # (0) A possibly-generic return type
    Java_org_signal_libsignal_internal_Native(?:Testing)?_ # The required JNI prefix
    (([a-zA-Z0-9]+)                                        # (1) The method name, with (2) a grouping prefix
    (?:_1[a-zA-Z0-9_]*)?)                                  # ...possibly followed by an underscore and then more name
    \(JNIEnv[ ].?env,[ ]JClass[ ]class_                    # and then the required JNI args,
    (,[ ].*)?\);                                           # then (3) actual args
    """, re.VERBOSE)


def parse_decls(cbindgen_output: str) -> Iterator[str]:
    cur_type = None

    for line in cbindgen_output.split('\n'):
        if line == '':
            continue

        match = JAVA_DECL.match(line)
        if match is None:
            raise Exception("Could not understand", line)

        (ret_type, method_name, this_type, args) = match.groups()

        # Add newlines between groups of functions for readability
        if cur_type is None or this_type != cur_type:
            yield ""
            cur_type = this_type

        java_fn_name = method_name.replace('_1', '_')
        (java_ret_type, is_throwing) = translate_to_java(ret_type)
        java_args = []

        if args is not None:
            for arg in args.split(', ')[1:]:
                (arg_type, arg_name) = arg.split(' ')
                (java_arg_type, _is_throwing) = translate_to_java(arg_type)
                java_args.append('%s %s' % (java_arg_type, arg_name))

        yield ("  public static native %s %s(%s)%s;" % (
            java_ret_type,
            java_fn_name,
            ", ".join(java_args),
            " throws Exception" if is_throwing else ""))


def expand_template(template_file: str, decls: Iterable[str]) -> str:
    with open(template_file, "r") as f:
        contents = f.read().replace('\n  // INSERT DECLS HERE', "\n".join(decls))
    return contents


def verify_contents(expected_output_file: str, expected_contents: str) -> None:
    with open(expected_output_file) as fh:
        current_contents = fh.readlines()
    diff = difflib.unified_diff(current_contents, expected_contents.splitlines(keepends=True))
    first_line = next(diff, None)
    if first_line:
        sys.stdout.write(first_line)
        sys.stdout.writelines(diff)
        sys.exit("error: Native.java not up to date; re-run %s!" % sys.argv[0])


def convert_to_java(rust_crate_dir: str, java_in_path: str, java_out_path: str, verify: bool) -> None:
    stdout = run_cbindgen(rust_crate_dir)

    decls = list(parse_decls(stdout))

    contents = expand_template(java_in_path, decls)

    if not os.access(java_out_path, os.F_OK):
        raise Exception(f"Didn't find expected file {java_out_path}")

    if not verify:
        with open(java_out_path, 'w') as fh:
            fh.write(contents)
    else:
        verify_contents(java_out_path, contents)


def main() -> None:
    args = parse_args()

    our_abs_dir = os.path.dirname(os.path.realpath(__file__))
    convert_to_java(
        rust_crate_dir=os.path.join(our_abs_dir, '..', 'impl'),
        java_in_path=os.path.join(our_abs_dir, 'Native.java.in'),
        java_out_path=os.path.join(our_abs_dir, '..', '..', '..', '..', 'java', 'shared', 'java', 'org', 'signal', 'libsignal', 'internal', 'Native.java'),
        verify=args.verify,
    )

    convert_to_java(
        rust_crate_dir=os.path.join(our_abs_dir, '..', 'testing'),
        java_in_path=os.path.join(our_abs_dir, 'NativeTesting.java.in'),
        java_out_path=os.path.join(our_abs_dir, '..', '..', '..', '..', 'java', 'shared', 'java', 'org', 'signal', 'libsignal', 'internal', 'NativeTesting.java'),
        verify=args.verify,
    )


if __name__ == "__main__":
    main()
