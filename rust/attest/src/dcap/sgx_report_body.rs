//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! SGX report body, ported from Open Enclave headers in v0.17.7.

use bitflags::bitflags;
use std::convert::{TryFrom, TryInto};
use std::intrinsics::transmute;

use crate::endian::*;

// Inline header file references are paths from the root of the repository tree.
// https://github.com/openenclave/openenclave/tree/v0.17.7

// sgx_report.h
const SGX_CPUSVN_SIZE: usize = 16;
const SGX_HASH_SIZE: usize = 32;

pub type MREnclave = [u8; SGX_HASH_SIZE];

#[derive(Debug)]
#[repr(C)]
// sgx_report_body_t
pub(crate) struct SgxReportBody {
    //     /* (0) CPU security version */
    //     uint8_t cpusvn[SGX_CPUSVN_SIZE];
    cpusvn: [u8; SGX_CPUSVN_SIZE],

    //     /* (16) Selector for which fields are defined in SSA.MISC */
    //     uint32_t miscselect;
    pub miscselect: UInt32LE,

    //     /* (20) Reserved */
    //     uint8_t reserved1[12];
    _reserved1: [u8; 12],

    //     /* (32) Enclave extended product ID */
    //     uint8_t isvextprodid[16];
    _isvextprodid: [u8; 16],

    //
    //     /* (48) Enclave attributes */
    //     sgx_attributes_t attributes;
    pub sgx_attributes: [u8; 16],
    //
    //     /* (64) Enclave measurement */
    //     uint8_t mrenclave[SGX_HASH_SIZE];
    pub mrenclave: MREnclave,

    //
    //     /* (96) Reserved */
    //     uint8_t reserved2[32];
    _reserved2: [u8; 32],

    //
    //     /* (128) The value of the enclave's SIGNER measurement */
    //     uint8_t mrsigner[SGX_HASH_SIZE];
    pub mrsigner: [u8; SGX_HASH_SIZE],

    //     /* (160) Reserved */
    //     uint8_t reserved3[32];
    _reserved3: [u8; 32],

    //     /* (192) Enclave Configuration ID*/
    //     uint8_t configid[64];
    _configid: [u8; 64],

    //     /* (256) Enclave product ID */
    //     uint16_t isvprodid;
    pub isvprodid: UInt16LE,

    //     /* (258) Enclave security version */
    //     uint16_t isvsvn;
    pub isvsvn: UInt16LE,

    //     /* (260) Enclave Configuration Security Version*/
    //     uint16_t configsvn;
    _configsvn: UInt16LE,

    //     /* (262) Reserved */
    //     uint8_t reserved4[42];
    _reserved4_bytes: [u8; 42],

    //     /* (304) Enclave family ID */
    //     uint8_t isvfamilyid[16];
    _isvfamilyid: [u8; 16],

    //     /* (320) User report data */
    //     sgx_report_data_t report_data;  // unsigned char field[64];
    pub sgx_report_data_bytes: [u8; 64],
}

static_assertions::const_assert_eq!(1, std::mem::align_of::<SgxReportBody>());
static_assertions::const_assert_eq!(384, std::mem::size_of::<SgxReportBody>());

bitflags! {
    /// SGX enclave flags
    ///
    /// Defined in https://github.com/intel/linux-sgx/blob/master/common/inc/sgx_attributes.h
    pub struct SgxFlags : u64 {
        const INITED = 0b00000001;
        const DEBUG = 0b00000010;
        const MODE64BIT = 0b00000100;
        const PROVISION_KEY = 0b00001000;
        const EINITTOKEN_KEY = 0b00100000;
        const KSS = 0b10000000;
    }
}

impl SgxReportBody {
    pub fn has_flag(&self, flag: SgxFlags) -> bool {
        // first 8 bytes are little endian SGX flags
        let bytes: [u8; 8] = self.sgx_attributes[0..8].try_into().unwrap();
        SgxFlags::from_bits_truncate(u64::from_le_bytes(bytes)).contains(flag)
    }
}

impl TryFrom<[u8; std::mem::size_of::<SgxReportBody>()]> for SgxReportBody {
    type Error = super::Error;

    fn try_from(src: [u8; std::mem::size_of::<SgxReportBody>()]) -> super::Result<Self> {
        unsafe { Ok(transmute(src)) }
    }
}
