//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![deny(unsafe_code)]

pub mod cds2;
pub mod client_connection;
pub mod constants;
pub mod dcap;
pub mod enclave;
pub mod hsm_enclave;
pub mod nitro;
pub mod sgx_session;
pub mod snow_resolver;
pub mod svr2;
pub mod tpm2snp;

mod cert_chain;
mod endian;
mod error;
mod expireable;
mod proto;
mod util;
