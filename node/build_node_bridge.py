#!/usr/bin/env python3

#
# Copyright (C) 2021 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

import optparse
import sys
import subprocess
import os
import shutil
import shlex


def main(args=None):
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

    cmdline = ['cargo', 'build', '--target', cargo_target, '-p', 'libsignal-node']
    if configuration_name == 'Release':
        cmdline.append('--release')
    print("Running '%s'" % (' '.join(cmdline)))

    cargo_env = os.environ.copy()
    cargo_env['CARGO_BUILD_TARGET_DIR'] = options.cargo_build_dir
    cargo_env['MACOSX_DEPLOYMENT_TARGET'] = '10.13'
    # On Linux, cdylibs don't include public symbols from their dependencies,
    # even if those symbols have been re-exported in the Rust source.
    # Using LTO works around this at the cost of a slightly slower build.
    # https://github.com/rust-lang/rfcs/issues/2771
    cargo_env['CARGO_PROFILE_RELEASE_LTO'] = 'thin'

    if node_os_name == 'win32':
        # By default, Rust on Windows depends on an MSVC component for the C runtime.
        # Link it statically to avoid propagating that dependency.
        cargo_env['RUSTFLAGS'] = '-C target-feature=+crt-static'

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

    cmd = subprocess.Popen(cmdline, env=cargo_env)
    cmd.wait()

    if cmd.returncode != 0:
        print('ERROR: cargo failed')
        return 1

    libs_in = os.path.join(cargo_env['CARGO_BUILD_TARGET_DIR'],
                           cargo_target,
                           configuration_name.lower())

    found_a_lib = False
    for lib_format in ['%s.dll', 'lib%s.so', 'lib%s.dylib']:
        src_path = os.path.join(libs_in, lib_format % 'signal_node')
        if os.access(src_path, os.R_OK):
            dst_path = os.path.join(out_dir, 'libsignal_client_%s_%s.node' % (node_os_name, node_arch))
            print("Copying %s to %s" % (src_path, dst_path))
            if not os.path.exists(out_dir):
                os.makedirs(out_dir)
            shutil.copyfile(src_path, dst_path)
            found_a_lib = True
            break

    if not found_a_lib:
        print("ERROR did not find generated library")
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
