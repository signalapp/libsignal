#!/usr/bin/env python3

"""
Lint our Cargo.toml files

- In the root Cargo.toml, ensure that all crates are workspace members (save the intentionally missing crates)
- Ensure that all crates inherit workspace's lints, authors, license, edition, and rust-version
"""

import typing
from pathlib import Path

import tomllib

# The workspace root
ROOT = Path(__file__).absolute().parent.parent

root_manifest_path = ROOT / 'Cargo.toml'
root_manifest = tomllib.loads(root_manifest_path.read_text())
crate_manifests = set(ROOT.glob('**/Cargo.toml')) - {root_manifest_path}

crate_members = set(root_manifest['workspace']['members'])
INTENTIONALLY_MISSING_CRATES = {
    'rust/attest/fuzz',
    'rust/bridge/node/futures',
    'rust/bridge/node/futures/tests-node-module',
    'rust/protocol/cross-version-testing',
    'rust/protocol/fuzz',
}
mistakenly_included_crates = INTENTIONALLY_MISSING_CRATES & crate_members
if len(mistakenly_included_crates) > 0:
    raise Exception(f'Mistakenly included crates: {mistakenly_included_crates}')
missing_crate_members = (
    {
        str(x.relative_to(ROOT).parent)
        for x in crate_manifests
        if not x.is_relative_to(ROOT / 'target')
    } - crate_members - INTENTIONALLY_MISSING_CRATES
)
if len(missing_crate_members) > 0:
    raise Exception(f'Missing crate members: {missing_crate_members}')

WORKSPACE = {'workspace': True}
violations = []
for crate in root_manifest['workspace']['members']:
    cargo_toml = ROOT / crate / 'Cargo.toml'
    manifest = tomllib.loads(cargo_toml.read_text())
    for path, expected in [
        (['package', 'authors'], WORKSPACE),
        (['package', 'license'], WORKSPACE),
        (['package', 'edition'], WORKSPACE),
        (['package', 'rust-version'], WORKSPACE),
        (['lints'], WORKSPACE),
    ]:
        value: typing.Any = manifest
        for element in path:
            if not isinstance(value, dict):
                value = 'Key path failed'
                break
            value = value.get(element)
        if value != expected:
            violations.append(
                f'Missing {path} to be {repr(expected)}. (Got {repr(value)}) in {cargo_toml.relative_to(ROOT)}'
            )

if len(violations) > 0:
    raise Exception('\n'.join(violations))
