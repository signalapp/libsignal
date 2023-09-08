#!/usr/bin/env python3

#
# Copyright (C) 2020-2021 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

import difflib
import os
import subprocess
import re
import sys


# If the command-line handling below gets any more complicated, this should be switched to argparse.
def print_usage_and_exit():
    print('usage: %s [--verify]' % sys.argv[0], file=sys.stderr)
    sys.exit(2)


mode = None
if len(sys.argv) > 2:
    print_usage_and_exit()
elif len(sys.argv) == 2:
    mode = sys.argv[1]
    if mode != '--verify':
        print_usage_and_exit()

our_abs_dir = os.path.dirname(os.path.realpath(__file__))

cbindgen = subprocess.Popen(['cbindgen'], cwd=os.path.join(our_abs_dir, '..'), stdout=subprocess.PIPE, stderr=subprocess.PIPE)

(stdout, stderr) = cbindgen.communicate()

stdout = str(stdout.decode('utf8'))
stderr = str(stderr.decode('utf8'))

ignore_this_warning = re.compile(
    "("
    r"WARN: Can't find .*\. This usually means that this type was incompatible or not found\.|"
    r"WARN: Missing `\[defines\]` entry for `feature = \".*\"` in cbindgen config\.|"
    r"WARN: Skip libsignal-bridge::.+ - \(not `(?:pub|no_mangle)`\)\.|"
    r"WARN: Couldn't find path for Array\(Path\(GenericPath \{ .+ \}\), Name\(\"LEN\"\)\), skipping associated constants"
    ")")

unknown_warning = False

for l in stderr.split('\n'):
    if l == "":
        continue

    if ignore_this_warning.match(l):
        continue

    print(l, file=sys.stderr)
    unknown_warning = True

if unknown_warning:
    sys.exit(1)

java_decl = re.compile(r'([a-zA-Z]+) Java_org_signal_libsignal_internal_Native_([A-Z][a-zA-Z0-9]+)_1([A-Za-z0-9]+)\(JNIEnv .?env, JClass class_(, .*)?\);')


def translate_to_java(typ):
    # jobject as a return type is not given here; instead use a type
    type_map = {
        "void": "void",
        "jstring": "String",
        "JString": "String",
        "JObject": "Object",
        "JClass": "Class",
        "jbyteArray": "byte[]",
        "jlongArray": "long[]",
        "ObjectHandle": "long",
        "jint": "int",
        "jlong": "long",
        "jboolean": "boolean",
    }

    if typ in type_map:
        return type_map[typ]

    # Assume anything prefixed with "Java" refers to an object
    if typ.startswith('JavaReturn'):
        return typ[10:]
    if typ.startswith('Java'):
        return typ[4:]

    raise Exception("Don't know what to do with a", typ)


cur_type = None
decls = []

for line in stdout.split('\n'):
    if line == '':
        continue

    match = java_decl.match(line)
    if match is None:
        raise Exception("Could not understand", line)

    (ret_type, this_type, method_name, args) = match.groups()

    # Add newlines between groups of functions for readability
    if cur_type is None or this_type != cur_type:
        decls.append("")
        cur_type = this_type

    java_fn_name = '%s_%s' % (this_type, method_name)
    java_ret_type = translate_to_java(ret_type)
    java_args = []

    if args is not None:
        for arg in args.split(', ')[1:]:
            (arg_type, arg_name) = arg.split(' ')
            java_arg_type = translate_to_java(arg_type)
            java_args.append('%s %s' % (java_arg_type, arg_name))

    decls.append("  public static native %s %s(%s);" % (java_ret_type, java_fn_name, ", ".join(java_args)))

template_file = open(os.path.join(our_abs_dir, 'Native.java.in')).read()

contents = template_file.replace('\n  // INSERT DECLS HERE', "\n".join(decls))

native_java = os.path.join(our_abs_dir, '../../../../java/shared/java/org/signal/libsignal/internal/Native.java')

if not os.access(native_java, os.F_OK):
    raise Exception("Didn't find Native.java where it was expected")

if not mode:
    with open(native_java, 'w') as fh:
        fh.write(contents)
elif mode == '--verify':
    with open(native_java) as fh:
        current_contents = fh.readlines()
    diff = difflib.unified_diff(current_contents, contents.splitlines(keepends=True))
    first_line = next(diff, None)
    if first_line:
        sys.stdout.write(first_line)
        sys.stdout.writelines(diff)
        sys.exit("error: Native.java not up to date; re-run %s!" % sys.argv[0])
else:
    raise Exception("mode not properly validated")
