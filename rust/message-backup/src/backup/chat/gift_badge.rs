//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use zkgroup::receipts::ReceiptCredentialPresentation;
use zkgroup::ZkGroupDeserializationFailure;

use crate::backup::serialize;
use crate::proto::backup as proto;

#[derive(serde::Serialize)]
pub struct GiftBadge {
    receipt_credential_presentation: ReceiptCredentialPresentation,
    #[serde(serialize_with = "serialize::enum_as_string")]
    state: proto::gift_badge::State,
}

impl std::fmt::Debug for GiftBadge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GiftBadge")
            .field(
                "receipt_credential_presentation",
                &zkcredential::PrintAsHex(
                    zkgroup::serialize(&self.receipt_credential_presentation).as_slice(),
                ),
            )
            .field("state", &self.state)
            .finish()
    }
}

#[cfg(test)]
impl PartialEq for GiftBadge {
    fn eq(&self, other: &Self) -> bool {
        zkgroup::serialize(&self.receipt_credential_presentation)
            == zkgroup::serialize(&other.receipt_credential_presentation)
            && self.state == other.state
    }
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq))]
pub enum GiftBadgeError {
    /// receipt credential presentation failed to deserialize
    InvalidReceiptCredentialPresentation,
}

impl TryFrom<proto::GiftBadge> for GiftBadge {
    type Error = GiftBadgeError;

    fn try_from(value: proto::GiftBadge) -> Result<Self, Self::Error> {
        let proto::GiftBadge {
            receiptCredentialPresentation,
            state,
            special_fields: _,
        } = value;

        let receipt_credential_presentation = zkgroup::deserialize(&receiptCredentialPresentation)
            .map_err(|_: ZkGroupDeserializationFailure| {
                GiftBadgeError::InvalidReceiptCredentialPresentation
            })?;

        use proto::gift_badge::State;
        let state = match state.enum_value_or_default() {
            s @ (State::UNOPENED | State::OPENED | State::REDEEMED | State::FAILED) => s,
        };

        Ok(Self {
            receipt_credential_presentation,
            state,
        })
    }
}

#[cfg(test)]
mod test {
    use zkgroup::RANDOMNESS_LEN;

    use super::*;

    impl proto::GiftBadge {
        fn test_data_presentation() -> ReceiptCredentialPresentation {
            const RANDOMNESS: [u8; RANDOMNESS_LEN] = [33; 32];

            let server_params = zkgroup::ServerSecretParams::generate(RANDOMNESS);
            let server_public_params = server_params.get_public_params();
            let request_context = &server_public_params
                .create_receipt_credential_request_context(RANDOMNESS, [59; 16]);
            let request = request_context.get_request();
            let response = server_params.issue_receipt_credential(
                RANDOMNESS,
                &request,
                zkgroup::Timestamp::from_epoch_seconds(123456789),
                6,
            );
            let credential = server_public_params
                .receive_receipt_credential(request_context, &response)
                .expect("valid request");
            server_public_params.create_receipt_credential_presentation(RANDOMNESS, &credential)
        }

        fn test_data() -> Self {
            Self {
                receiptCredentialPresentation: zkgroup::serialize(&Self::test_data_presentation()),
                state: proto::gift_badge::State::REDEEMED.into(),
                special_fields: Default::default(),
            }
        }
    }

    #[test]
    fn valid_gift_badge() {
        assert_eq!(
            proto::GiftBadge::test_data().try_into(),
            Ok(GiftBadge {
                receipt_credential_presentation: proto::GiftBadge::test_data_presentation(),
                state: proto::gift_badge::State::REDEEMED,
            })
        );
    }

    #[test]
    fn invalid_presentation() {
        let mut badge = proto::GiftBadge::test_data();
        badge.receiptCredentialPresentation = vec![];

        assert_eq!(
            GiftBadge::try_from(badge),
            Err(GiftBadgeError::InvalidReceiptCredentialPresentation)
        );
    }
}
