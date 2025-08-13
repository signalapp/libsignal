//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

pub mod proto {
    pub mod chat {
        pub mod common {
            tonic::include_proto!("org.signal.chat.common");
        }
        pub mod account {
            tonic::include_proto!("org.signal.chat.account");
        }
        pub mod device {
            tonic::include_proto!("org.signal.chat.device");
        }
    }
}

impl From<libsignal_core::ServiceId> for proto::chat::common::ServiceIdentifier {
    fn from(value: libsignal_core::ServiceId) -> Self {
        let kind = match value.kind() {
            libsignal_core::ServiceIdKind::Aci => proto::chat::common::IdentityType::Aci,
            libsignal_core::ServiceIdKind::Pni => proto::chat::common::IdentityType::Pni,
        };
        let uuid = value.raw_uuid();
        Self {
            identity_type: kind.into(),
            uuid: uuid.into_bytes().into(),
        }
    }
}

impl From<libsignal_core::Aci> for proto::chat::common::ServiceIdentifier {
    fn from(value: libsignal_core::Aci) -> Self {
        libsignal_core::ServiceId::from(value).into()
    }
}

impl From<libsignal_core::Pni> for proto::chat::common::ServiceIdentifier {
    fn from(value: libsignal_core::Pni) -> Self {
        libsignal_core::ServiceId::from(value).into()
    }
}

impl proto::chat::common::ServiceIdentifier {
    pub fn try_into_service_id(self) -> Option<libsignal_core::ServiceId> {
        let Self {
            identity_type,
            uuid,
        } = self;
        Some(match identity_type.try_into().ok()? {
            proto::chat::common::IdentityType::Aci => {
                libsignal_core::Aci::from_uuid_bytes(uuid.try_into().ok()?).into()
            }
            proto::chat::common::IdentityType::Pni => {
                libsignal_core::Pni::from_uuid_bytes(uuid.try_into().ok()?).into()
            }
            proto::chat::common::IdentityType::Unspecified => return None,
        })
    }
}
