#!/usr/bin/env python3

#
# Copyright (C) 2021 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

import errno
import hashlib
import mmap
import optparse
import os
import shlex
import shutil
import subprocess
import sys
from typing import List, Optional

sys.path.append(os.path.join(
    os.path.dirname(os.path.abspath(os.path.dirname(__file__))),
    'bin'))
import build_helpers  # noqa: E402 (we need to modify sys.path before this import)


def check_for_debug_level_logs(src_path: str) -> None:
    with open(src_path, 'rb') as f:
        with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as m:
            # See libsignal-node's logging.rs.
            if m.find(b'-LEVEL LOGS ENABLED') != -1:
                raise AssertionError('debug-level logs found in build that should not have them!')


def check_for_attest_testutil(src_path: str) -> None:
    with open(src_path, 'rb') as f:
        with mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as m:
            if m.find(b'ATTEST TEST-UTIL IS ENABLED') != -1:
                raise AssertionError('attest library included with test-util enabled!')


def maybe_dump_debug_symbols(*, src_path: str, src_checksum_path: str, dst_path: str, dst_checksum_path: str) -> None:
    dump_syms = shutil.which('dump_syms')
    if not dump_syms:
        print('note: dump_syms not installed; skipping debug info processing')
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
                print('Debug info did not change')
                return

    with open(dst_checksum_path, 'w') as f:
        f.write(checksum)

    print(f'Dumping debug symbols to {dst_path}')
    subprocess.check_call([dump_syms, src_path, '-o', dst_path])


def copy_to_prebuild_dir(
    *,
    libs_in: str,
    lib_basename: str,
    lib_format: str,
    debug_format: str,
    debug_format_for_checksum: str,
    prebuild_dir: str,
    is_debug: bool,
    allow_debug_level_logs: bool,
    node_os_name: str,
    node_arch: str,
    objcopy: Optional[str]
) -> None:
    src_path = os.path.join(libs_in, lib_format.format(lib_basename))
    if not os.access(src_path, os.R_OK):
        raise FileNotFoundError(errno.ENOENT, 'did not find generated library', src_path)

    if not allow_debug_level_logs:
        check_for_debug_level_logs(src_path)
    check_for_attest_testutil(src_path)

    platform_prebuild_dir = os.path.join(prebuild_dir, f'{node_os_name}-{node_arch}')
    prebuild_path = os.path.join(platform_prebuild_dir, '@signalapp+libsignal-client.node')
    print(f'Copying {src_path} to {prebuild_path}')
    os.makedirs(platform_prebuild_dir, exist_ok=True)
    if objcopy and not is_debug:
        subprocess.check_call([objcopy, '-S', src_path, prebuild_path])
    else:
        shutil.copyfile(src_path, prebuild_path)

    if not is_debug:
        debug_info_filename = f'libsignal_client_{node_os_name}_{node_arch}-debuginfo.sym'
        maybe_dump_debug_symbols(
            src_path=os.path.join(libs_in, debug_format.format(lib_basename)),
            src_checksum_path=os.path.join(libs_in, debug_format_for_checksum.format(lib_basename)),
            dst_path=os.path.join(prebuild_dir, debug_info_filename),
            dst_checksum_path=os.path.join(prebuild_dir, debug_info_filename + '.sha256'),
        )


def main(args: Optional[List[str]] = None) -> int:
    if args is None:
        args = sys.argv

    if sys.platform == 'win32':
        args = shlex.split(' '.join(args), posix=0)

    print(f"Invoked with '{' '.join(args)}'")

    parser = optparse.OptionParser()
    parser.add_option('--configuration', '-C', default='Release', metavar='CONFIG',
                      help='specify build configuration (Release or Debug)')
    # Luckily, Python's sys.platform matches Node's OS names for our supported targets.
    parser.add_option('--os-name', default=sys.platform, metavar='OS',
                      help='specify Node OS name')
    parser.add_option('--cargo-build-dir', default=os.path.join('..', 'target'), metavar='PATH',
                      help='specify cargo build dir (default %default)')
    parser.add_option('--cargo-target', default=None,
                      help='specify cargo target')
    parser.add_option('--node-arch', '--arch', default=None,
                      help='specify node arch (x64, ia32, arm64)')
    parser.add_option('--debug-level-logs', action='store_true',
                      help='include log levels below INFO (default for Debug builds)')

    (options, args) = parser.parse_args(args)

    configuration_name = options.configuration.strip('"')
    if configuration_name is None:
        print('ERROR: --configuration is required')
        return 1
    elif configuration_name not in ['Release', 'Debug']:
        print(f"ERROR: Unknown value for --configuration '{configuration_name}'")
        return 1

    node_os_name = options.os_name

    node_arch = options.node_arch
    if node_arch is None:
        # Python doesn't provide many guarantees about the format of platform.machine(),
        # so we turn to Node instead.
        node_arch = subprocess.check_output(
            ['node', '-e', "console.log(require('node:process').arch)"],
            encoding='utf8').strip()

    cargo_target = options.cargo_target
    if cargo_target is None:
        cargo_arch = {
            'ia32': 'i686',
            'x64': 'x86_64',
            'arm64': 'aarch64',
        }.get(node_arch, node_arch)
        cargo_target_suffix = {
            'darwin': 'apple-darwin',
            'win32': 'pc-windows-msvc',
            'linux': 'unknown-linux-gnu',
        }.get(node_os_name, node_os_name)
        cargo_target = f'{cargo_arch}-{cargo_target_suffix}'

    # Fetch all dependencies first, so we can check information about them in constructing our
    # command lines.
    subprocess.check_call(['cargo', 'fetch'])

    features = []
    allow_debug_level_logs = False
    if options.debug_level_logs:
        allow_debug_level_logs = True
    else:
        features.append('log/release_max_level_info')

    cmdline = ['cargo', 'build', '--target', cargo_target, '-p', 'libsignal-node', '--features', ','.join(features)]
    if configuration_name == 'Release':
        cmdline.append('--release')
    else:
        allow_debug_level_logs = True
    print(f"Running '{' '.join(cmdline)}'")

    cargo_env = os.environ.copy()
    cargo_env['RUSTFLAGS'] = cargo_env.get('RUSTFLAGS') or ''
    cargo_env['CARGO_BUILD_TARGET_DIR'] = options.cargo_build_dir
    cargo_env['MACOSX_DEPLOYMENT_TARGET'] = '12'
    # Build with debug line tables, but not full debug info.
    cargo_env['CARGO_PROFILE_RELEASE_DEBUG'] = '1'
    # Use full LTO to reduce binary size
    cargo_env['CARGO_PROFILE_RELEASE_LTO'] = 'fat'
    cargo_env['CARGO_PROFILE_RELEASE_CODEGEN_UNITS'] = '1'
    # Enable ARMv8 cryptography acceleration when available
    cargo_env['RUSTFLAGS'] += ' --cfg aes_armv8'
    # Access tokio's unstable metrics
    cargo_env['RUSTFLAGS'] += ' --cfg tokio_unstable'
    # Work around CMake bug introduced in cmake-rs v1.49.0
    # https://github.com/rust-lang/cmake-rs/pull/158#issuecomment-1544782070
    cargo_env['CMAKE_ARGS'] = '-DCMAKE_SYSTEM_NAME='
    # Strip absolute paths
    for path in build_helpers.rust_paths_to_remap():
        cargo_env['RUSTFLAGS'] += f' --remap-path-prefix {path}='

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
                cargo_env['CARGO_BUILD_TARGET_DIR'] = os.path.join(tmpdir, 'libsignal')

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
        if version_number := cargo_env.get('npm_package_version'):
            cargo_env['RUSTFLAGS'] += f' -Clink-arg=-Wl,-current_version,{version_number}'

    else:
        # Assume Linux-like.
        # DWP files don't seem ready for everyday use.
        # We'll just save the whole unstripped binary.
        lib_format = 'lib{}.so'
        debug_format = 'lib{}.so'
        debug_format_for_checksum = debug_format

        cargo_arch = cargo_target.split('-')[0]
        objcopy = shutil.which(f'{cargo_arch}-linux-gnu-objcopy') or 'objcopy'

    print('with environment:')
    for (k, v) in cargo_env.items():
        print(f'{k}={v}')
    print('', flush=True)

    subprocess.check_call(cmdline, env=cargo_env)

    libs_in = os.path.join(cargo_env['CARGO_BUILD_TARGET_DIR'],
                           cargo_target,
                           configuration_name.lower())

    copy_to_prebuild_dir(
        libs_in=libs_in,
        lib_basename='signal_node',
        lib_format=lib_format,
        debug_format=debug_format,
        debug_format_for_checksum=debug_format_for_checksum,
        prebuild_dir='prebuilds',
        is_debug=(configuration_name == 'Debug'),
        allow_debug_level_logs=allow_debug_level_logs,
        node_os_name=node_os_name,
        node_arch=node_arch,
        objcopy=objcopy,
    )

    return 0


if __name__ == '__main__':
    sys.exit(main())
