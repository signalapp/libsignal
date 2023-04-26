//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

pub const NUM_AUTH_CRED_ATTRIBUTES: usize = 3;
pub const NUM_PROFILE_KEY_CRED_ATTRIBUTES: usize = 4;
pub const NUM_RECEIPT_CRED_ATTRIBUTES: usize = 2;

pub const PRESENTATION_VERSION_1: u8 = 0;
pub const PRESENTATION_VERSION_2: u8 = 1;
pub const PRESENTATION_VERSION_3: u8 = 2;

pub const AES_KEY_LEN: usize = 32;
pub const AESGCM_NONCE_LEN: usize = 12;
pub const AESGCM_TAG_LEN: usize = 16;
pub const GROUP_MASTER_KEY_LEN: usize = 32;
pub const GROUP_SECRET_PARAMS_LEN: usize = 289;
pub const GROUP_PUBLIC_PARAMS_LEN: usize = 97;
pub const GROUP_IDENTIFIER_LEN: usize = 32;
pub const AUTH_CREDENTIAL_LEN: usize = 181;
pub const AUTH_CREDENTIAL_PRESENTATION_V2_LEN: usize = 461;
pub const AUTH_CREDENTIAL_RESPONSE_LEN: usize = 361;
pub const AUTH_CREDENTIAL_WITH_PNI_LEN: usize = 265;
pub const AUTH_CREDENTIAL_WITH_PNI_RESPONSE_LEN: usize = 425;
pub const PROFILE_KEY_LEN: usize = 32;
pub const PROFILE_KEY_CIPHERTEXT_LEN: usize = 65;
pub const PROFILE_KEY_COMMITMENT_LEN: usize = 97;
pub const EXPIRING_PROFILE_KEY_CREDENTIAL_LEN: usize = 153;
pub(crate) const PROFILE_KEY_CREDENTIAL_PRESENTATION_V1_LEN: usize = 713;
pub const PROFILE_KEY_CREDENTIAL_PRESENTATION_V2_LEN: usize = 713;
pub const PROFILE_KEY_CREDENTIAL_REQUEST_LEN: usize = 329;
pub const PROFILE_KEY_CREDENTIAL_REQUEST_CONTEXT_LEN: usize = 473;
pub const EXPIRING_PROFILE_KEY_CREDENTIAL_RESPONSE_LEN: usize = 497;
pub const PROFILE_KEY_VERSION_LEN: usize = 32;
pub const PROFILE_KEY_VERSION_ENCODED_LEN: usize = 64;
pub const RECEIPT_CREDENTIAL_LEN: usize = 129;
pub const RECEIPT_CREDENTIAL_PRESENTATION_LEN: usize = 329;
pub const RECEIPT_CREDENTIAL_REQUEST_LEN: usize = 97;
pub const RECEIPT_CREDENTIAL_REQUEST_CONTEXT_LEN: usize = 177;
pub const RECEIPT_CREDENTIAL_RESPONSE_LEN: usize = 409;
pub const RECEIPT_SERIAL_LEN: usize = 16;
pub const RESERVED_LEN: usize = 1;
pub const SERVER_SECRET_PARAMS_LEN: usize = 2305;
pub const SERVER_PUBLIC_PARAMS_LEN: usize = 417;
pub const UUID_CIPHERTEXT_LEN: usize = 65;
pub const RANDOMNESS_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;
pub const UUID_LEN: usize = 16;
pub const ACCESS_KEY_LEN: usize = 16;

/// Seconds in a 24-hour cycle (ignoring leap seconds).
pub const SECONDS_PER_DAY: u64 = 86400;

pub const TEST_ARRAY_16: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

pub const TEST_ARRAY_16_1: [u8; 16] = [
    100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115,
];

pub const TEST_ARRAY_32: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];

pub const TEST_ARRAY_32_1: [u8; 32] = [
    100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118,
    119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131,
];

pub const TEST_ARRAY_32_2: [u8; 32] = [
    200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218,
    219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231,
];

pub const TEST_ARRAY_32_3: [u8; 32] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32,
];

pub const TEST_ARRAY_32_4: [u8; 32] = [
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33,
];

pub const TEST_ARRAY_32_5: [u8; 32] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 34,
];
