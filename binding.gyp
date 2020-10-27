#
# Copyright (C) 2020 Signal Messenger, LLC.
# SPDX-License-Identifier: AGPL-3.0-only
#

{
    'targets': [
        {
            'target_name': 'libsignal_client.node',
            'type': 'none',
            'actions': [
                {
                    'action_name': 'bin/build-node-bridge',
                    'action': [
                        'env',
                        'CONFIGURATION_NAME=<(CONFIGURATION_NAME)',
                        'CARGO_BUILD_TARGET_DIR=<(INTERMEDIATE_DIR)/rust',
                        'bin/build-node-bridge',
                        '-o', '<(PRODUCT_DIR)/'],
                    'inputs': [],
                    'outputs': [
                        '<(PRODUCT_DIR)/libsignal_client.node',
                        # This really needs to be environment-variable-sensitive, but node-gyp doesn't support that. Cargo will still save work if possible.
                        '<(PRODUCT_DIR)/nonexistent-file-to-force-rebuild'
                    ]
                }
            ]
        }
    ]
}
