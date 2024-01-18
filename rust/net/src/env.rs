//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::Duration;

use hex_literal::hex;

use crate::enclave::{Cdsi, EnclaveEndpoint, MrEnclave, Nitro, Sgx};

pub(crate) const WS_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(5);
pub(crate) const WS_MAX_IDLE_TIME: Duration = Duration::from_secs(15);
pub(crate) const WS_MAX_CONNECTION_TIME: Duration = Duration::from_secs(2);

pub struct Env<'a, Svr3> {
    pub cdsi: EnclaveEndpoint<'a, Cdsi>,
    pub svr2: EnclaveEndpoint<'a, Sgx>,
    pub svr3: Svr3,
    pub chat_host: &'a str,
}

pub struct Svr3Env<'a>(EnclaveEndpoint<'a, Sgx>, EnclaveEndpoint<'a, Nitro>);

impl<'a> Svr3Env<'a> {
    #[inline]
    pub fn sgx(&self) -> EnclaveEndpoint<'a, Sgx> {
        self.0
    }

    #[inline]
    pub fn nitro(&self) -> EnclaveEndpoint<'a, Nitro> {
        self.1
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
    svr3: Svr3Env(
        EnclaveEndpoint {
            host: "backend1.svr3.staging.signal.org",
            mr_enclave: MrEnclave::new(&hex!(
                "5db9423ed5a0b0bef374eac3a8251839e1f63ed40a2537415b63656b26912d92"
            )),
        },
        EnclaveEndpoint {
            host: "backend2.svr3.staging.signal.org",
            mr_enclave: MrEnclave::new(b"cc8f7cb1.52b91975.61d0bcb0"),
        },
    ),
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
    svr3: Svr3Env(
        EnclaveEndpoint {
            host: "svr3.signal.org",
            mr_enclave: MrEnclave::new(&[0; 32]),
        },
        EnclaveEndpoint {
            host: "does not exist",
            mr_enclave: MrEnclave::new(&hex!(
                "17e1cb662572d28e0eb5a492ed8df949bc2cfcf3f2098b710e7b637759d6dcb3"
            )),
        },
    ),
};

pub mod constants {
    pub(crate) const WEB_SOCKET_PATH: &str = "/v1/websocket/";
}
