//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::Duration;

use hex_literal::hex;

use crate::enclave::{Cdsi, EnclaveEndpoint, MrEnclave, Sgx};

pub(crate) const WS_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(5);
pub(crate) const WS_MAX_IDLE_TIME: Duration = Duration::from_secs(15);
pub(crate) const WS_MAX_CONNECTION_TIME: Duration = Duration::from_secs(2);

pub struct Env<'a, Svr3> {
    pub cdsi: EnclaveEndpoint<'a, Cdsi>,
    pub svr2: EnclaveEndpoint<'a, Sgx>,
    pub svr3: Svr3,
    pub chat_host: &'a str,
}

pub struct Svr3Env<'a>(EnclaveEndpoint<'a, Sgx>);

impl<'a> Svr3Env<'a> {
    pub const fn new(sgx: EnclaveEndpoint<'a, Sgx>) -> Self {
        Self(sgx)
    }
    #[inline]
    pub fn sgx(&self) -> EnclaveEndpoint<'a, Sgx> {
        self.0
    }
}

pub const STAGING: Env<'static, Svr3Env> = Env {
    chat_host: "chat.staging.signal.org",
    cdsi: EnclaveEndpoint {
        host: "cdsi.staging.signal.org",
        mr_enclave: MrEnclave::new(&hex!(
            "0f6fd79cdfdaa5b2e6337f534d3baf999318b0c462a7ac1f41297a3e4b424a57"
        )),
    },
    svr2: EnclaveEndpoint {
        host: "svr2.staging.signal.org",
        mr_enclave: MrEnclave::new(&hex!(
            "a8a261420a6bb9b61aa25bf8a79e8bd20d7652531feb3381cbffd446d270be95"
        )),
    },
    svr3: Svr3Env::new(EnclaveEndpoint {
        host: "backend1.svr3.test.signal.org",
        mr_enclave: MrEnclave::new(&hex!(
            "acb1973aa0bbbd14b3b4e06f145497d948fd4a98efc500fcce363b3b743ec482"
        )),
    }),
};

pub const PROD: Env<'static, Svr3Env> = Env {
    chat_host: "chat.signal.org",
    cdsi: EnclaveEndpoint {
        host: "cdsi.signal.org",
        mr_enclave: MrEnclave::new(&hex!(
            "0f6fd79cdfdaa5b2e6337f534d3baf999318b0c462a7ac1f41297a3e4b424a57"
        )),
    },
    svr2: EnclaveEndpoint {
        host: "svr2.signal.org",
        mr_enclave: MrEnclave::new(&[0; 32]),
    },
    svr3: Svr3Env::new(EnclaveEndpoint {
        host: "svr3.signal.org",
        mr_enclave: MrEnclave::new(&[0; 32]),
    }),
};

pub mod constants {
    pub(crate) const WEB_SOCKET_PATH: &str = "/v1/websocket/";
}
