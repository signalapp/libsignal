//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_core::{DeviceId, LogSafeDisplay};
use libsignal_net_grpc::proto::chat::device::devices_client::DevicesClient;
use libsignal_net_grpc::proto::chat::device::{SetDeviceNameRequest, set_device_name_response};

use crate::api::{Auth, RequestError};
use crate::grpc::{GrpcServiceProvider, GrpcTestCase, log_and_send};
use crate::logging::Redact;

#[derive(displaydoc::Display, Debug)]
/// No device with the provided identifier was found on the account
pub struct DeviceIdNotFoundInAccount;
impl LogSafeDisplay for DeviceIdNotFoundInAccount {}

impl std::fmt::Display for Redact<SetDeviceNameRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(SetDeviceNameRequest { name, id }) = self;
        f.debug_struct("SetDeviceNameRequest")
            .field("name_len", &name.len())
            .field("id", id)
            .finish()
    }
}

impl<T: GrpcServiceProvider> Auth<T> {
    // TODO: should we enforce the size limits on encrypted_name here?
    pub async fn set_device_name(
        &self,
        id: DeviceId,
        encrypted_name: &[u8],
    ) -> Result<(), RequestError<DeviceIdNotFoundInAccount>> {
        let mut client = DevicesClient::new(self.0.service());
        let request = SetDeviceNameRequest {
            name: encrypted_name.to_vec(),
            id: id.into(),
        };
        let desc = Redact(&request).to_string();
        match log_and_send("auth", &desc, || client.set_device_name(request))
            .await?
            .into_inner()
            .response
            .ok_or_else(|| RequestError::Unexpected {
                log_safe: "missing response".to_string(),
            })? {
            set_device_name_response::Response::Success(_empty) => Ok(()),
            set_device_name_response::Response::TargetDeviceNotFound(
                libsignal_net_grpc::proto::chat::errors::NotFound {},
            ) => Err(RequestError::Other(DeviceIdNotFoundInAccount)),
        }
    }
}

// Not cfg(test) so it can be accessed via bridging tests.
// These tests will get pruned via LTO tree shaking.
pub mod test_cases {
    use libsignal_net_grpc::proto::chat::device::SetDeviceNameResponse;

    use super::*;
    pub struct SetDeviceNameArgs {
        pub id: u8,
        pub encrypted_name: Vec<u8>,
    }
    pub enum SetDeviceNameOut {
        Success,
        DeviceNotFound,
    }
    pub fn set_device_name_test_cases() -> Vec<
        GrpcTestCase<
            SetDeviceNameArgs,
            SetDeviceNameRequest,
            SetDeviceNameResponse,
            SetDeviceNameOut,
        >,
    > {
        let method = "/org.signal.chat.device.Devices/SetDeviceName";
        vec![
            GrpcTestCase {
                name: "success".to_string(),
                method: method.to_string(),
                request: SetDeviceNameArgs {
                    id: 3,
                    encrypted_name: b"TestEncryptedDeviceName".to_vec(),
                },
                request_grpc: SetDeviceNameRequest {
                    name: b"TestEncryptedDeviceName".to_vec(),
                    id: 3,
                },
                response_grpc: SetDeviceNameResponse {
                    response: Some(set_device_name_response::Response::Success(
                        Default::default(),
                    )),
                },
                response: SetDeviceNameOut::Success,
            },
            GrpcTestCase {
                name: "no device id".to_string(),
                method: method.to_string(),
                request: SetDeviceNameArgs {
                    id: 3,
                    encrypted_name: b"my name".to_vec(),
                },
                request_grpc: SetDeviceNameRequest {
                    name: b"my name".to_vec(),
                    id: 3,
                },
                response_grpc: SetDeviceNameResponse {
                    response: Some(set_device_name_response::Response::TargetDeviceNotFound(
                        libsignal_net_grpc::proto::chat::errors::NotFound {},
                    )),
                },
                response: SetDeviceNameOut::DeviceNotFound,
            },
        ]
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;

    use super::*;
    use crate::grpc::testutil::run_tests;

    #[test]
    fn test_set_device_name() {
        use test_cases::*;
        run_tests(
            set_device_name_test_cases(),
            |chat: Auth<_>, SetDeviceNameArgs { id, encrypted_name }| async move {
                chat.set_device_name(
                    DeviceId::new(id).expect("valid device id"),
                    encrypted_name.as_slice(),
                )
                .await
            },
            |resp, result| match resp {
                SetDeviceNameOut::Success => assert_matches!(result, Ok(())),
                SetDeviceNameOut::DeviceNotFound => {
                    assert_matches!(result, Err(RequestError::Other(DeviceIdNotFoundInAccount)))
                }
            },
        );
    }
}
