#!/usr/bin/env python3

#
# Copyright (C) 2021 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

import hashlib
import optparse
import os
import shlex
import shutil
import subprocess
import sys

from typing import List, Optional


def maybe_dump_debug_symbols(*, src_path: str, src_checksum_path: str, dst_path: str, dst_checksum_path: str) -> None:
    dump_syms = shutil.which('dump_syms')
    if not dump_syms:
        print("note: dump_syms not installed; skipping debug info processing")
        return

    with open(src_checksum_path, 'rb') as f:
        digest = hashlib.sha256()
        # Use read1 to use the file object's buffering.
        # We don't want to load the entire input in memory if we can help it.
        while next := f.read1():
            digest.update(next)
        checksum = digest.hexdigest()

    if os.path.exists(dst_checksum_path):
        with open(dst_checksum_path, 'r') as f:
            if f.read() == checksum:
                print("Debug info did not change")
                return

    with open(dst_checksum_path, 'w') as f:
        f.write(checksum)

    print("Dumping debug symbols to %s" % dst_path)
    subprocess.check_call([dump_syms, src_path, '-o', dst_path])


def main(args: Optional[List[str]] = None) -> int:
    if args is None:
        args = sys.argv

    if sys.platform == 'win32':
        args = shlex.split(' '.join(args), posix=0)

    print("Invoked with '%s'" % (' '.join(args)))

    parser = optparse.OptionParser()
    parser.add_option('--out-dir', '-o', default=None, metavar='DIR',
                      help='specify destination dir (default build/$CONFIGURATION_NAME)')
    parser.add_option('--configuration', default='Release', metavar='C',
                      help='specify build configuration (Release or Debug)')
    parser.add_option('--os-name', default=None, metavar='OS',
                      help='specify Node OS name')
    parser.add_option('--cargo-build-dir', default='target', metavar='PATH',
                      help='specify cargo build dir (default %default)')
    parser.add_option('--cargo-target', default=None,
                      help='specify cargo target')
    parser.add_option('--node-arch', default=None,
                      help='specify node arch (x64, ia32, arm64)')

    (options, args) = parser.parse_args(args)

    configuration_name = options.configuration.strip('"')
    if configuration_name is None:
        print('ERROR: --configuration is required')
        return 1
    elif configuration_name not in ['Release', 'Debug']:
        print("ERROR: Unknown value for --configuration '%s'" % (configuration_name))
        return 1

    node_os_name = options.os_name
    if node_os_name is None:
        print('ERROR: --os-name is required')
        return 1

    cargo_target = options.cargo_target
    if cargo_target is None:
        print('ERROR: --cargo-target is required')
        return 1

    node_arch = options.node_arch
    if node_arch is None:
        print('ERROR: --node_arch is required')
        return 1

    out_dir = options.out_dir.strip('"') or os.path.join('build', configuration_name)

    features = []
    if 'npm_config_libsignal_debug_level_logs' not in os.environ:
        features.append('log/release_max_level_info')

    cmdline = ['cargo', 'build', '--target', cargo_target, '-p', 'libsignal-node', '--features', ','.join(features)]
    if configuration_name == 'Release':
        cmdline.append('--release')
    print("Running '%s'" % (' '.join(cmdline)))

    cargo_env = os.environ.copy()
    cargo_env['RUSTFLAGS'] = cargo_env.get('RUSTFLAGS') or ''
    cargo_env['CARGO_BUILD_TARGET_DIR'] = options.cargo_build_dir
    cargo_env['MACOSX_DEPLOYMENT_TARGET'] = '10.13'
    # Build with debug line tables, but not full debug info.
    cargo_env['CARGO_PROFILE_RELEASE_DEBUG'] = '1'
    # On Linux, cdylibs don't include public symbols from their dependencies,
    # even if those symbols have been re-exported in the Rust source.
    # Using LTO works around this at the cost of a slightly slower build.
    # https://github.com/rust-lang/rfcs/issues/2771
    cargo_env['CARGO_PROFILE_RELEASE_LTO'] = 'thin'
    # Enable ARMv8 cryptography acceleration when available
    cargo_env['RUSTFLAGS'] += ' --cfg aes_armv8'

    # If set (below), will post-process the build library using this instead of just `cp`-ing it.
    objcopy = None

    if node_os_name == 'win32':
        # By default, Rust on Windows depends on an MSVC component for the C runtime.
        # Link it statically to avoid propagating that dependency.
        cargo_env['RUSTFLAGS'] += ' -C target-feature=+crt-static'

        # Hint to the Rust compiler that we're cross-compiling. This shouldn't be necessary
        # since the invoking build script (if any) should be doing that but it's needed
        # since Rust nightly-2024-10-03.
        cargo_env['VSCMD_ARG_TGT_ARCH'] = node_arch

        # Save the debug info in PDB format...
        cargo_env['CARGO_PROFILE_RELEASE_SPLIT_DEBUGINFO'] = 'packed'
        # ...and DLLs don't have anything to strip.
        # (If you turn on stripping the PDB doesn't get generated at all.)
        lib_format = '{}.dll'
        debug_format = '{}.pdb'
        debug_format_for_checksum = debug_format

        abs_build_dir = os.path.abspath(options.cargo_build_dir)
        if 'GITHUB_WORKSPACE' in cargo_env:
            # Avoid long build directory paths on GitHub Actions,
            # breaking the old Win32 limit of 260 characters.
            # (https://docs.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation)
            # We don't do this everywhere because it breaks cleaning.
            #
            # In the long run, Visual Studio's CLI tools will become long-path aware and this should
            # become unnecessary.
            # It would be nice if using extended-length path syntax `\\?\` was sufficient,
            # but that also isn't accepted by all of Visual Studio's CLI tools.
            tmpdir = cargo_env['RUNNER_TEMP']
            if len(tmpdir) < len(abs_build_dir):
                cargo_env['CARGO_BUILD_TARGET_DIR'] = os.path.join(tmpdir, "libsignal")

    elif node_os_name == 'darwin':
        # Save the debug info in dSYM format...
        cargo_env['CARGO_PROFILE_RELEASE_SPLIT_DEBUGINFO'] = 'packed'
        # ...then have Rust strip the library.
        cargo_env['CARGO_PROFILE_RELEASE_STRIP'] = 'symbols'
        lib_format = 'lib{0}.dylib'
        debug_format = 'lib{0}.dylib.dSYM'
        # The dSYM format is a directory, not a single file.
        # We use the single file that contains the DWARF information for our checksum,
        # since our primary purpose for debug info is symbolicating crashdumps,
        # which uses the line tables stored as DWARF.
        debug_format_for_checksum = os.path.join(debug_format, 'Contents', 'Resources', 'DWARF', lib_format)

        # macOS has a nice place for us to stash our version number.
        if 'npm_package_version' in cargo_env:
            cargo_env['RUSTFLAGS'] += ' -Clink-arg=-Wl,-current_version,%s' % cargo_env['npm_package_version']

    else:
        # Assume Linux-like.
        # DWP files don't seem ready for everyday use.
        # We'll just save the whole unstripped binary.
        lib_format = 'lib{}.so'
        debug_format = 'lib{}.so'
        debug_format_for_checksum = debug_format

        objcopy = shutil.which('%s-linux-gnu-objcopy' % cargo_target.split('-')[0]) or 'objcopy'

    print("with environment:")
    for (k, v) in cargo_env.items():
        print("%s=%s" % (k, v))
    print("", flush=True)

    subprocess.check_call(cmdline, env=cargo_env)

    libs_in = os.path.join(cargo_env['CARGO_BUILD_TARGET_DIR'],
                           cargo_target,
                           configuration_name.lower())

    src_path = os.path.join(libs_in, lib_format.format('signal_node'))
    if os.access(src_path, os.R_OK):
        dst_base = 'libsignal_client_%s_%s' % (node_os_name, node_arch)

        dst_path = os.path.join(out_dir, dst_base + '.node')
        print("Copying %s to %s" % (src_path, dst_path))
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)
        if objcopy:
            subprocess.check_call([objcopy, '-S', src_path, dst_path])
        else:
            shutil.copyfile(src_path, dst_path)

        maybe_dump_debug_symbols(
            src_path=os.path.join(libs_in, debug_format.format('signal_node')),
            src_checksum_path=os.path.join(libs_in, debug_format_for_checksum.format('signal_node')),
            dst_path=os.path.join(out_dir, dst_base + '-debuginfo.sym'),
            dst_checksum_path=os.path.join(out_dir, dst_base + '-debuginfo.sha256'),
        )
    else:
        print("ERROR: did not find generated library")
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
