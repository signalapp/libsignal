//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Infallible;

use libsignal_core::{DeviceId, LogSafeDisplay};
use libsignal_net_grpc::proto::chat::device::devices_client::DevicesClient;
use libsignal_net_grpc::proto::chat::device::get_devices_response::LinkedDevice as GrpcLinkedDevice;
use libsignal_net_grpc::proto::chat::device::{
    ClearPushTokenRequest, ClearPushTokenResponse, GetDevicesRequest, RemoveDeviceRequest,
    RemoveDeviceResponse, SetDeviceNameRequest, SetPushTokenRequest, SetPushTokenResponse,
    set_device_name_response, set_push_token_request,
};
use libsignal_protocol::Timestamp;

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

impl std::fmt::Display for Redact<GetDevicesRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(GetDevicesRequest {}) = self;
        f.debug_struct("GetDevicesRequest").finish()
    }
}

impl std::fmt::Display for Redact<SetPushTokenRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(SetPushTokenRequest { token_request }) = self;
        let mut s = f.debug_struct("SetPushTokenRequest");
        match token_request {
            Some(set_push_token_request::TokenRequest::ApnsTokenRequest(
                set_push_token_request::ApnsTokenRequest { apns_token },
            )) => s.field("apns_token_len", &apns_token.len()),
            Some(set_push_token_request::TokenRequest::FcmTokenRequest(
                set_push_token_request::FcmTokenRequest { fcm_token },
            )) => s.field("fcm_token_len", &fcm_token.len()),
            None => s.field("token_request", &None::<()>),
        }
        .finish()
    }
}

impl std::fmt::Display for Redact<ClearPushTokenRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(ClearPushTokenRequest {}) = self;
        f.debug_struct("ClearPushTokenRequest").finish()
    }
}

impl std::fmt::Display for Redact<RemoveDeviceRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(RemoveDeviceRequest { id }) = self;
        f.debug_struct("RemoveDeviceRequest")
            .field("id", id)
            .finish()
    }
}

#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct LinkedDevice {
    /// The identifier for the device within an account.
    pub id: DeviceId,
    /// A sequence of bytes that encodes an encrypted human-readable name for
    /// this device.
    pub encrypted_name: Vec<u8>,
    /// The approximate time, in milliseconds since the epoch, at which this
    /// device last connected to the server.
    pub last_seen: Timestamp,
    /// The registration ID of the given device.
    pub registration_id: u16,
    /// A sequence of bytes that encodes the time,
    /// in milliseconds since the epoch, at which this device was
    /// attached to its parent account.
    pub created_at_ciphertext: Vec<u8>,
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

    /// Remove a linked device from the current account.
    ///
    /// Linked devices may only remove themselves, and primary devices may
    /// remove any device other than themselves; the server rejects anything
    /// else as a programmer error, surfaced as [`RequestError::Unexpected`].
    ///
    /// Removing a device ID that is not on the account also succeeds, so a
    /// caller retrying a removal sees the same result as the original call.
    /// This is not true idempotency, though: device IDs are small and get
    /// reused, so if a new device is linked and assigned `id` between two
    /// calls, the second call removes that new device.
    pub async fn remove_device(&self, id: DeviceId) -> Result<(), RequestError<Infallible>> {
        let mut client = DevicesClient::new(self.0.service());
        let request = RemoveDeviceRequest { id: id.into() };
        let desc = Redact(&request).to_string();
        let RemoveDeviceResponse {} = log_and_send("auth", &desc, || client.remove_device(request))
            .await?
            .into_inner();
        Ok(())
    }

    /// List the devices associated with the current account.
    pub async fn get_devices(&self) -> Result<Vec<LinkedDevice>, RequestError<Infallible>> {
        let mut client = DevicesClient::new(self.0.service());
        let request = GetDevicesRequest {};
        let desc = Redact(&request).to_string();
        log_and_send("auth", &desc, || client.get_devices(request))
            .await?
            .into_inner()
            .devices
            .into_iter()
            .map(
                |GrpcLinkedDevice {
                     id,
                     name,
                     last_seen,
                     registration_id,
                     created_at_ciphertext,
                 }| {
                    Ok(LinkedDevice {
                        id: DeviceId::try_from(id).map_err(|_| RequestError::Unexpected {
                            log_safe: "Invalid device ID".to_string(),
                        })?,
                        encrypted_name: name,
                        last_seen: Timestamp::from_epoch_millis(last_seen),
                        // According to the protobuf, registration IDs should be <=0x3fff, which
                        // fits in a u16.
                        registration_id: u16::try_from(registration_id).map_err(|_| {
                            RequestError::Unexpected {
                                log_safe: "Invalid registration ID".to_string(),
                            }
                        })?,
                        created_at_ciphertext,
                    })
                },
            )
            .collect()
    }

    // These are deliberately two separate methods rather than one method taking a `PushToken` enum
    // that parallels the proto's `oneof` (cf. `crate::api::registration::PushToken`): each platform
    // only ever uses one kind of token, so a per-kind method is simpler at every call site and
    // avoids bridging a one-of-two-strings enum through all three app languages. If a third token
    // kind ever shows up, reconsider.

    /// Sets the APNs device token the server should use to send new message
    /// notifications to the authenticated device.
    ///
    /// `apns_token` must not be empty.
    pub async fn set_push_token_apns(
        &self,
        apns_token: String,
    ) -> Result<(), RequestError<Infallible>> {
        assert!(!apns_token.is_empty(), "APNs token must not be empty");
        self.set_push_token(set_push_token_request::TokenRequest::ApnsTokenRequest(
            set_push_token_request::ApnsTokenRequest { apns_token },
        ))
        .await
    }

    /// Sets the FCM push token the server should use to send new message
    /// notifications to the authenticated device.
    ///
    /// `fcm_token` must not be empty.
    pub async fn set_push_token_fcm(
        &self,
        fcm_token: String,
    ) -> Result<(), RequestError<Infallible>> {
        assert!(!fcm_token.is_empty(), "FCM token must not be empty");
        self.set_push_token(set_push_token_request::TokenRequest::FcmTokenRequest(
            set_push_token_request::FcmTokenRequest { fcm_token },
        ))
        .await
    }

    async fn set_push_token(
        &self,
        token_request: set_push_token_request::TokenRequest,
    ) -> Result<(), RequestError<Infallible>> {
        let mut client = DevicesClient::new(self.0.service());
        let request = SetPushTokenRequest {
            token_request: Some(token_request),
        };
        let desc = Redact(&request).to_string();
        let SetPushTokenResponse {} =
            log_and_send("auth", &desc, || client.set_push_token(request))
                .await?
                .into_inner();
        Ok(())
    }

    /// Remove any push tokens associated with the current device.
    ///
    /// After this call, the server will assume the current device will
    /// periodically poll for new messages.
    pub async fn clear_push_token(&self) -> Result<(), RequestError<Infallible>> {
        let mut client = DevicesClient::new(self.0.service());
        let request = ClearPushTokenRequest {};
        let desc = Redact(&request).to_string();
        let ClearPushTokenResponse {} =
            log_and_send("auth", &desc, || client.clear_push_token(request))
                .await?
                .into_inner();
        Ok(())
    }
}

// Not cfg(test) so it can be accessed via bridging tests.
// These tests will get pruned via LTO tree shaking.
pub mod test_cases {
    use libsignal_net_grpc::proto::chat::device::{GetDevicesResponse, SetDeviceNameResponse};

    use super::*;

    pub type ClearPushTokenArgs = ();
    pub type ClearPushTokenOut = ();
    pub fn clear_push_token_test_cases() -> Vec<
        GrpcTestCase<
            ClearPushTokenArgs,
            ClearPushTokenRequest,
            ClearPushTokenResponse,
            ClearPushTokenOut,
        >,
    > {
        let method = "/org.signal.chat.device.Devices/ClearPushToken";
        vec![GrpcTestCase {
            name: "success".to_string(),
            method: method.to_string(),
            request: (),
            request_grpc: ClearPushTokenRequest {},
            response_grpc: ClearPushTokenResponse {},
            response: (),
        }]
    }

    pub type GetDevicesArgs = ();
    pub struct GetDevicesOut {
        pub devices: Vec<LinkedDevice>,
    }
    pub fn get_devices_test_cases()
    -> Vec<GrpcTestCase<GetDevicesArgs, GetDevicesRequest, GetDevicesResponse, GetDevicesOut>> {
        let method = "/org.signal.chat.device.Devices/GetDevices";
        vec![
            GrpcTestCase {
                name: "zero devices".to_string(),
                method: method.to_string(),
                request: (),
                request_grpc: GetDevicesRequest {},
                response_grpc: GetDevicesResponse { devices: vec![] },
                response: GetDevicesOut { devices: vec![] },
            },
            GrpcTestCase {
                name: "one device".to_string(),
                method: method.to_string(),
                request: (),
                request_grpc: GetDevicesRequest {},
                response_grpc: GetDevicesResponse {
                    devices: vec![GrpcLinkedDevice {
                        id: 17,
                        name: b"device 1".to_vec(),
                        last_seen: 1782484792019,
                        registration_id: 8,
                        created_at_ciphertext: b"shhhhhh".to_vec(),
                    }],
                },
                response: GetDevicesOut {
                    devices: vec![LinkedDevice {
                        id: DeviceId::new(17).expect("valid device id"),
                        encrypted_name: b"device 1".to_vec(),
                        last_seen: Timestamp::from_epoch_millis(1782484792019),
                        registration_id: 8,
                        created_at_ciphertext: b"shhhhhh".to_vec(),
                    }],
                },
            },
            GrpcTestCase {
                name: "two devices".to_string(),
                method: method.to_string(),
                request: (),
                request_grpc: GetDevicesRequest {},
                response_grpc: GetDevicesResponse {
                    devices: vec![
                        GrpcLinkedDevice {
                            id: 17,
                            name: b"device 1".to_vec(),
                            last_seen: 1782484792019,
                            registration_id: 8,
                            created_at_ciphertext: b"shhhhhh".to_vec(),
                        },
                        GrpcLinkedDevice {
                            id: 18,
                            name: b"device 2".to_vec(),
                            last_seen: 21782484792019,
                            registration_id: 9,
                            created_at_ciphertext: b"shhhhhhhhh".to_vec(),
                        },
                    ],
                },
                response: GetDevicesOut {
                    devices: vec![
                        LinkedDevice {
                            id: DeviceId::new(17).expect("valid device id"),
                            encrypted_name: b"device 1".to_vec(),
                            last_seen: Timestamp::from_epoch_millis(1782484792019),
                            registration_id: 8,
                            created_at_ciphertext: b"shhhhhh".to_vec(),
                        },
                        LinkedDevice {
                            id: DeviceId::new(18).expect("valid device id"),
                            encrypted_name: b"device 2".to_vec(),
                            last_seen: Timestamp::from_epoch_millis(21782484792019),
                            registration_id: 9,
                            created_at_ciphertext: b"shhhhhhhhh".to_vec(),
                        },
                    ],
                },
            },
        ]
    }

    pub fn set_push_token_apns_test_cases()
    -> Vec<GrpcTestCase<String, SetPushTokenRequest, SetPushTokenResponse, ()>> {
        let method = "/org.signal.chat.device.Devices/SetPushToken";
        vec![GrpcTestCase {
            name: "success".to_string(),
            method: method.to_string(),
            request: "test-apns-token".to_string(),
            request_grpc: SetPushTokenRequest {
                token_request: Some(set_push_token_request::TokenRequest::ApnsTokenRequest(
                    set_push_token_request::ApnsTokenRequest {
                        apns_token: "test-apns-token".to_string(),
                    },
                )),
            },
            response_grpc: SetPushTokenResponse {},
            response: (),
        }]
    }

    pub fn set_push_token_fcm_test_cases()
    -> Vec<GrpcTestCase<String, SetPushTokenRequest, SetPushTokenResponse, ()>> {
        let method = "/org.signal.chat.device.Devices/SetPushToken";
        vec![GrpcTestCase {
            name: "success".to_string(),
            method: method.to_string(),
            request: "test-fcm-token".to_string(),
            request_grpc: SetPushTokenRequest {
                token_request: Some(set_push_token_request::TokenRequest::FcmTokenRequest(
                    set_push_token_request::FcmTokenRequest {
                        fcm_token: "test-fcm-token".to_string(),
                    },
                )),
            },
            response_grpc: SetPushTokenResponse {},
            response: (),
        }]
    }

    pub struct RemoveDeviceArgs {
        pub id: u8,
    }
    pub enum RemoveDeviceOut {
        Success,
    }
    pub fn remove_device_test_cases() -> Vec<
        GrpcTestCase<RemoveDeviceArgs, RemoveDeviceRequest, RemoveDeviceResponse, RemoveDeviceOut>,
    > {
        let method = "/org.signal.chat.device.Devices/RemoveDevice";
        vec![
            GrpcTestCase {
                name: "success".to_string(),
                method: method.to_string(),
                request: RemoveDeviceArgs { id: 3 },
                request_grpc: RemoveDeviceRequest { id: 3 },
                response_grpc: RemoveDeviceResponse {},
                response: RemoveDeviceOut::Success,
            },
            // The fake server has no account state, so this case can't check
            // that the real server accepts an absent device ID; it only
            // documents that it does, while re-verifying request encoding for a
            // different device ID.
            GrpcTestCase {
                name: "removing an absent device also succeeds".to_string(),
                method: method.to_string(),
                request: RemoveDeviceArgs { id: 100 },
                request_grpc: RemoveDeviceRequest { id: 100 },
                response_grpc: RemoveDeviceResponse {},
                response: RemoveDeviceOut::Success,
            },
        ]
    }

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

    #[test]
    fn test_set_push_token_apns() {
        use test_cases::*;
        run_tests(
            set_push_token_apns_test_cases(),
            |chat: Auth<_>, apns_token: String| async move {
                chat.set_push_token_apns(apns_token).await
            },
            |(), result| assert_matches!(result, Ok(())),
        );
    }

    #[test]
    fn test_set_push_token_fcm() {
        use test_cases::*;
        run_tests(
            set_push_token_fcm_test_cases(),
            |chat: Auth<_>, fcm_token: String| async move { chat.set_push_token_fcm(fcm_token).await },
            |(), result| assert_matches!(result, Ok(())),
        );
    }

    #[test]
    fn test_remove_device() {
        use test_cases::*;
        run_tests(
            remove_device_test_cases(),
            |chat: Auth<_>, RemoveDeviceArgs { id }| async move {
                chat.remove_device(DeviceId::new(id).expect("valid device id"))
                    .await
            },
            |resp, result| match resp {
                RemoveDeviceOut::Success => assert_matches!(result, Ok(())),
            },
        );
    }

    #[test]
    fn test_get_devices() {
        use test_cases::*;
        run_tests(
            get_devices_test_cases(),
            |chat: Auth<_>, ()| async move { chat.get_devices().await },
            |resp, result| assert_eq!(resp.devices, result.expect("success")),
        );
    }

    #[test]
    fn test_clear_push_token() {
        use test_cases::*;
        run_tests(
            clear_push_token_test_cases(),
            |chat: Auth<_>, ()| async move { chat.clear_push_token().await },
            |(), result| assert_matches!(result, Ok(())),
        );
    }
}
