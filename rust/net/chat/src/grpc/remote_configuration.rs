//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::convert::Infallible;

pub use libsignal_net_grpc::proto::chat::common::{Badge, BadgeSvg};
use libsignal_net_grpc::proto::chat::remote_configuration::get_badges_response::Response as GetBadgesResponseEnum;
use libsignal_net_grpc::proto::chat::remote_configuration::remote_configuration_client::RemoteConfigurationClient;
use libsignal_net_grpc::proto::chat::remote_configuration::{
    Badges as GrpcBadges, GetBadgesRequest, TaggedBadges as TaggedBadgesGrpc,
};

use crate::api::{Auth, RequestError};
use crate::grpc::{GrpcServiceProvider, log_and_send};
use crate::logging::Redact;

#[derive(Clone, Debug, PartialEq)]
pub struct TaggedBadges {
    pub badges: HashMap<String, Badge>,
    pub etag: Vec<u8>,
}

impl std::fmt::Display for Redact<GetBadgesRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Redact(GetBadgesRequest { etag }) = self;
        f.debug_struct("GetBadgesRequest")
            .field("etag.len()", &etag.len())
            .finish()
    }
}

impl<T: GrpcServiceProvider> Auth<T> {
    /// Returns detailed information for all configured badges, keyed by badge ID.
    ///
    /// Badge descriptions may contain localized strings. These are determined based on the Locale
    /// of the `AuthenticatedChatConnection`.
    ///
    /// Callers may cache a badges result for up to 1 day before checking (via
    /// etag) if there are any new updates.
    ///
    /// If the etag is up-to-date, this function will return `None`.
    pub async fn get_badges(
        &self,
        etag: Option<&[u8]>,
    ) -> Result<Option<TaggedBadges>, RequestError<Infallible>> {
        let mut client = RemoteConfigurationClient::new(self.0.service());
        let request = GetBadgesRequest {
            etag: etag.map(|x| x.to_vec()).unwrap_or_default(),
        };
        let desc = Redact(&request).to_string();
        match log_and_send(Self::LOG_TAG, &desc, || client.get_badges(request))
            .await?
            .into_inner()
            .response
            .ok_or_else(|| RequestError::Unexpected {
                log_safe: "Missing response".to_string(),
            })? {
            GetBadgesResponseEnum::TaggedBadges(TaggedBadgesGrpc { badges, etag }) => {
                let GrpcBadges { badges } = badges.ok_or_else(|| RequestError::Unexpected {
                    log_safe: "Missing badges".into(),
                })?;
                Ok(Some(TaggedBadges { badges, etag }))
            }
            GetBadgesResponseEnum::EtagMatched(true | false) => Ok(None),
        }
    }
}

pub mod test_cases {
    use libsignal_net_grpc::proto::chat::remote_configuration::GetBadgesResponse;

    use super::*;
    use crate::grpc::GrpcTestCase;

    pub type GetBadgesArgs = Option<Vec<u8>>;
    pub type GetBadgesOut = Option<TaggedBadges>;

    pub fn get_badges_test_cases()
    -> Vec<GrpcTestCase<GetBadgesArgs, GetBadgesRequest, GetBadgesResponse, GetBadgesOut>> {
        let method = "/org.signal.chat.remoteconfiguration.RemoteConfiguration/GetBadges";
        let badges: HashMap<String, Badge> = HashMap::from_iter([
            (
                "badge0".into(),
                Badge {
                    id: "badge0".into(),
                    category: "other".into(),
                    name: "Badgey McBadgeface".into(),
                    description: "Mushroom! Mushroom!".into(),
                    sprites6: vec![
                        "sprite1".into(),
                        "sprite2".into(),
                        "sprite3".into(),
                        "sprite4".into(),
                        "sprite5".into(),
                        "sprite6".into(),
                    ],
                    svg: "badge.eps".into(),
                    svgs: vec![
                        BadgeSvg {
                            light: "light-0.ps.gz".into(),
                            dark: "dark-0.ai".into(),
                        },
                        BadgeSvg {
                            light: "light-1.pdf".into(),
                            dark: "dark-1.hvif".into(),
                        },
                    ],
                },
            ),
            (
                "badge1".into(),
                Badge {
                    id: "badge1".into(),
                    category: "other1".into(),
                    name: "Badgey McBadgeface1".into(),
                    description: "Mushroom! Mushroom!1".into(),
                    sprites6: vec![
                        "sprite11".into(),
                        "sprite21".into(),
                        "sprite31".into(),
                        "sprite41".into(),
                        "sprite51".into(),
                        "sprite61".into(),
                    ],
                    svg: "badge1.eps".into(),
                    svgs: vec![
                        BadgeSvg {
                            light: "light-01.ps.gz".into(),
                            dark: "dark-01.ai".into(),
                        },
                        BadgeSvg {
                            light: "light-11.pdf".into(),
                            dark: "dark-11.hvif".into(),
                        },
                    ],
                },
            ),
        ]);
        vec![
            GrpcTestCase {
                name: "etag match".into(),
                method: method.into(),
                request: Some(b"Hello! Etag here.".to_vec()),
                request_grpc: GetBadgesRequest {
                    etag: b"Hello! Etag here.".to_vec(),
                },
                response_grpc: GetBadgesResponse {
                    response: Some(GetBadgesResponseEnum::EtagMatched(true)),
                },
                response: None,
            },
            GrpcTestCase {
                name: "no etag".into(),
                method: method.into(),
                request: None,
                request_grpc: Default::default(),
                response_grpc: GetBadgesResponse {
                    response: Some(GetBadgesResponseEnum::TaggedBadges(TaggedBadgesGrpc {
                        badges: Some(GrpcBadges {
                            badges: badges.clone(),
                        }),
                        etag: b"I'm a happy etag!".to_vec(),
                    })),
                },
                response: Some(TaggedBadges {
                    badges: badges.clone(),
                    etag: b"I'm a happy etag!".to_vec(),
                }),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use test_cases::*;

    use super::*;
    use crate::grpc::testutil::run_tests;
    #[test]
    fn test_get_badges() {
        run_tests(
            get_badges_test_cases(),
            |chat: Auth<_>, etag| async move { chat.get_badges(etag.as_deref()).await },
            |out, result| assert_eq!(result.expect("success"), out),
        );
    }
}
