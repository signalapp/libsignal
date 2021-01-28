#
# Copyright (C) 2020 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

{
    'conditions': [
        ['OS=="mac"', {'variables': {'NODE_OS_NAME': 'darwin'}},
         'OS=="win"', {'variables': {'NODE_OS_NAME': 'win32'}},
         {'variables': {'NODE_OS_NAME': '<(OS)'}}],
    ],
    'targets': [
        {
            'target_name': 'libsignal_client_<(NODE_OS_NAME).node',
            'type': 'none',
            'actions': [
                {
                    'action_name': 'node/build_node_bridge.py',
                    'action': [
                        'python',
                        'node/build_node_bridge.py',
                        '--out-dir', '<(PRODUCT_DIR)/',
                        '--os-name', '<(NODE_OS_NAME)',
                        '--configuration', '<(CONFIGURATION_NAME)',
                        '--cargo-build-dir', '<(INTERMEDIATE_DIR)/rust'
                        ],
                    'inputs': [],
                    'outputs': [
                        '<(PRODUCT_DIR)/<(_target_name)',
                        # This really needs to be environment-variable-sensitive, but node-gyp doesn't support that. Cargo will still save work if possible.
                        '<(PRODUCT_DIR)/nonexistent-file-to-force-rebuild'
                    ]
                }
            ]
        }
    ]
}
