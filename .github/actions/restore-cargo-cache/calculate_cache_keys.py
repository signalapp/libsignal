#!/usr/bin/env python3
"""Calculate cache keys for GitHub Actions workflow."""

import argparse
import hashlib
import pathlib
import subprocess
import sys
from typing import Optional, Sequence, Tuple


def run_command(cmd: Sequence[str], check: bool = True) -> Tuple[int, str, str]:
    """Run a command and return its exit code, stdout, and stderr."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=check,
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.CalledProcessError as exc:
        stdout = exc.stdout.strip() if exc.stdout else ''
        stderr = exc.stderr.strip() if exc.stderr else ''
        return exc.returncode, stdout, stderr


def get_merge_base() -> str:
    """Get the merge base commit with origin/main."""
    # Deepen all currently tracked tags to help find the merge base
    run_command(['git', 'fetch', '--deepen=100', 'origin'], check=False)

    code, output, _ = run_command(
        ['git', 'merge-base', 'HEAD', 'origin/main'],
        check=False,
    )

    if code != 0 or not output:
        print('Warning: could not determine merge base', file=sys.stderr)
        return 'none'

    return output


def get_merge_base_parent(commit: str) -> str:
    """Get the parent commit of the given commit."""
    returncode, output, _ = run_command(
        ['git', 'rev-parse', f'{commit}^'],
        check=False,
    )
    if returncode != 0 or not output:
        return 'none'
    return output


def get_working_tree_hash() -> str:
    """Get a hash representing the current working tree state."""
    returncode, working_tree_hash, _ = run_command(
        ['git', 'rev-parse', 'HEAD^{tree}'],
        check=False,
    )

    if returncode != 0 or not working_tree_hash:
        raise RuntimeError('Could not determine working tree hash')

    return working_tree_hash


def read_rust_toolchain_file(path: pathlib.Path) -> Optional[str]:
    """Read the rust-toolchain file if present."""
    if not path.exists():
        return None

    content = path.read_text(encoding='utf-8').strip()
    return content or None


def resolve_toolchain(override: Optional[str]) -> str:
    """Determine which toolchain spec to use."""
    if override:
        return override

    workspace_root = pathlib.Path.cwd()
    toolchain_from_file = read_rust_toolchain_file(workspace_root / 'rust-toolchain')
    if toolchain_from_file:
        return toolchain_from_file

    raise RuntimeError('Could not determine toolchain')


def get_rustc_version(toolchain: str) -> str:
    """Resolve the full rustc --version string for the given toolchain."""
    if not toolchain:
        return 'unknown'

    returncode, stdout, stderr = run_command(['rustup', 'run', toolchain, 'rustc', '--version'], check=False)
    if returncode == 0 and stdout:
        return stdout

    if stderr:
        print(f'Warning: command rustup run {toolchain} rustc --version failed: {stderr}', file=sys.stderr)

    raise RuntimeError(f'Could not determine rustc version for toolchain {toolchain}')


def main() -> None:
    parser = argparse.ArgumentParser(description='Calculate cache keys')
    parser.add_argument(
        '--toolchain',
        default='workspace',
        help='Rust toolchain spec to use, or "workspace" to use the repository configuration.',
    )
    args = parser.parse_args()

    requested = args.toolchain.strip()
    if not requested or requested == 'workspace':
        requested = None
    toolchain = resolve_toolchain(requested)
    rustc_version = get_rustc_version(toolchain)
    rustc_version_hash = hashlib.sha256(rustc_version.encode()).hexdigest()[:32]

    lca = get_merge_base()
    lca_parent = get_merge_base_parent(lca)
    lca_grandparent = get_merge_base_parent(lca_parent)
    current = get_working_tree_hash()

    print(f'rustc-version={rustc_version_hash}')
    print(f'cache-key-merge-base={lca}')
    print(f'cache-key-merge-base-parent={lca_parent}')
    print(f'cache-key-merge-base-grandparent={lca_grandparent}')
    print(f'cache-key-current={current}')

    debug_parts = [
        f'Toolchain={toolchain}',
        f'RustcVersion={rustc_version}',
        f'LCA={lca}',
        f'LCAParent={lca_parent}',
        f'LCAGrandparent={lca_grandparent}',
        f'Current={current}',
    ]
    print('Debug: ' + '; '.join(debug_parts), file=sys.stderr)


if __name__ == '__main__':
    main()
