//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![warn(clippy::unwrap_used)]

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
        pub mod errors {
            tonic::include_proto!("org.signal.chat.errors");
        }

        // Not actually a proto, we just make sure to generate our helper file in the same place.
        pub mod services {
            tonic::include_proto!("service_methods");
        }
    }

    // These protos come directly from Google and their doc comments aren't necessarily valid Markdown.
    #[allow(
        clippy::doc_overindented_list_items,
        rustdoc::bare_urls,
        rustdoc::broken_intra_doc_links,
        rustdoc::invalid_html_tags
    )]
    pub mod google {
        pub mod rpc {
            tonic::include_proto!("google.rpc");
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
    pub fn try_as_service_id(&self) -> Option<libsignal_core::ServiceId> {
        let Self {
            identity_type,
            uuid,
        } = self;
        Some(match (*identity_type).try_into().ok()? {
            proto::chat::common::IdentityType::Aci => {
                libsignal_core::Aci::from_uuid_bytes(uuid.as_slice().try_into().ok()?).into()
            }
            proto::chat::common::IdentityType::Pni => {
                libsignal_core::Pni::from_uuid_bytes(uuid.as_slice().try_into().ok()?).into()
            }
            proto::chat::common::IdentityType::Unspecified => return None,
        })
    }
}

// We only need Name support for these few types, so we just do it here instead of adding it during
// the build step using `prost_build::Config::enable_type_names`.
impl prost::Name for proto::google::rpc::ErrorInfo {
    const NAME: &'static str = "ErrorInfo";
    const PACKAGE: &'static str = "google.rpc";

    fn type_url() -> String {
        const_str::concat!(
            "type.googleapis.com/",
            proto::google::rpc::ErrorInfo::PACKAGE,
            proto::google::rpc::ErrorInfo::NAME
        )
        .to_owned()
    }
}

impl prost::Name for proto::google::rpc::BadRequest {
    const NAME: &'static str = "BadRequest";
    const PACKAGE: &'static str = "google.rpc";

    fn type_url() -> String {
        const_str::concat!(
            "type.googleapis.com/",
            proto::google::rpc::BadRequest::PACKAGE,
            proto::google::rpc::BadRequest::NAME
        )
        .to_owned()
    }
}

impl prost::Name for proto::google::rpc::RetryInfo {
    const NAME: &'static str = "RetryInfo";
    const PACKAGE: &'static str = "google.rpc";

    fn type_url() -> String {
        const_str::concat!(
            "type.googleapis.com/",
            proto::google::rpc::RetryInfo::PACKAGE,
            proto::google::rpc::RetryInfo::NAME
        )
        .to_owned()
    }
}
