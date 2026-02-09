#!/usr/bin/env python3
"""
Transform signal_ffi.h into C++-compatible signal_ffi_cpp.h.

cbindgen generates C-style patterns that are invalid C++:
  enum X { A = 0, B = 1, }; typedef uint8_t X;

In C++, re-declaring X as a typedef after defining it as an enum is an error.
This script auto-detects such patterns and transforms them to:
  enum X : uint8_t { A = 0, B = 1, };
"""

import re
import sys


def patch_header(input_path: str, output_path: str) -> None:
    with open(input_path, 'r') as f:
        content = f.read()

    # Find all enum names defined as `enum NAME {`
    enum_names = set(re.findall(r'^enum (\w+) \{', content, re.MULTILINE))

    # Find all `typedef uintN_t NAME;` lines where NAME is also an enum
    typedef_pattern = re.compile(r'^typedef (uint\d+_t) (\w+);$', re.MULTILINE)
    enums_with_typedef = {}
    for m in typedef_pattern.finditer(content):
        int_type, name = m.group(1), m.group(2)
        if name in enum_names:
            enums_with_typedef[name] = int_type

    if not enums_with_typedef:
        # No transformation needed, just copy
        with open(output_path, 'w') as f:
            f.write(content)
        return

    lines = content.split('\n')
    out_lines = []
    for line in lines:
        # Transform `enum NAME {` → `enum NAME : uint8_t {`
        m = re.match(r'^enum (\w+) \{$', line)
        if m and m.group(1) in enums_with_typedef:
            int_type = enums_with_typedef[m.group(1)]
            out_lines.append(f'enum {m.group(1)} : {int_type} {{')
            continue

        # Remove `typedef uintN_t NAME;` for enum names
        m = re.match(r'^typedef uint\d+_t (\w+);$', line)
        if m and m.group(1) in enums_with_typedef:
            continue

        out_lines.append(line)

    with open(output_path, 'w') as f:
        f.write('\n'.join(out_lines))

    names = ', '.join(sorted(enums_with_typedef.keys()))
    print(f"  Patched {len(enums_with_typedef)} enum(s) for C++: {names}")


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.h> <output.h>", file=sys.stderr)
        sys.exit(1)
    patch_header(sys.argv[1], sys.argv[2])
