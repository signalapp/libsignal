//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::utils::basic_authorization;
use tungstenite::client::IntoClientRequest;
use tungstenite::handshake::client::Request;

#[derive(Copy, Clone)]
pub struct CdsiRequest<'a> {
    base_url: &'a str,
    mr_enclave: &'a str,
    username: &'a str,
    password: &'a str,
}

impl IntoClientRequest for CdsiRequest<'_> {
    fn into_client_request(self) -> tungstenite::Result<Request> {
        let url = format!(
            "wss://{}/{}/{}/{}",
            &self.base_url, "v1", &self.mr_enclave, "discovery",
        );
        let auth = basic_authorization(self.username, self.password);
        let mut request = url.into_client_request()?;
        let headers = request.headers_mut();
        headers.append(http::header::AUTHORIZATION, auth.parse()?);
        Ok(request)
    }
}

#[derive(PartialEq, Eq)]
pub struct Env<'a> {
    pub chat_host: &'a str,
    pub cdsi_host: &'a str,
    pub cdsi_mr_enclave: &'a str,
}

impl<'a> Env<'a> {
    pub fn cdsi(&'a self, username: &'a str, password: &'a str) -> CdsiRequest {
        CdsiRequest {
            base_url: self.cdsi_host,
            mr_enclave: self.cdsi_mr_enclave,
            username,
            password,
        }
    }
}

pub const STAGING: Env<'static> = Env {
    chat_host: "chat.staging.signal.org",
    cdsi_host: "cdsi.staging.signal.org",
    cdsi_mr_enclave: "0f6fd79cdfdaa5b2e6337f534d3baf999318b0c462a7ac1f41297a3e4b424a57",
};

pub const PROD: Env<'static> = Env {
    chat_host: "chat.signal.org",
    cdsi_host: "cdsi.signal.org",
    cdsi_mr_enclave: "0f6fd79cdfdaa5b2e6337f534d3baf999318b0c462a7ac1f41297a3e4b424a57",
};

pub mod constants {
    pub(crate) const WEB_SOCKET_PATH: &str = "/v1/websocket/";
}
