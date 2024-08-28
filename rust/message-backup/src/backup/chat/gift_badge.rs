//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use zkgroup::receipts::ReceiptCredentialPresentation;
use zkgroup::ZkGroupDeserializationFailure;

use crate::proto::backup as proto;

#[derive(serde::Serialize)]
#[allow(clippy::large_enum_variant)] // The container is a BoxedValue already.
pub enum GiftBadge {
    Valid {
        receipt_credential_presentation: ReceiptCredentialPresentation,
        state: GiftBadgeState,
    },
    Failed,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, serde::Serialize)]
pub enum GiftBadgeState {
    Unopened,
    Opened,
    Redeemed,
}

impl std::fmt::Debug for GiftBadge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid {
                receipt_credential_presentation,
                state,
            } => f
                .debug_struct("Valid")
                .field(
                    "receipt_credential_presentation",
                    &zkcredential::PrintAsHex(
                        zkgroup::serialize(&receipt_credential_presentation).as_slice(),
                    ),
                )
                .field("state", state)
                .finish(),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

#[cfg(test)]
impl PartialEq for GiftBadge {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Failed, Self::Failed) => true,
            (
                Self::Valid {
                    receipt_credential_presentation: lhs_presentation,
                    state: lhs_state,
                },
                Self::Valid {
                    receipt_credential_presentation: rhs_presentation,
                    state: rhs_state,
                },
            ) => {
                zkgroup::serialize(&lhs_presentation) == zkgroup::serialize(&rhs_presentation)
                    && lhs_state == rhs_state
            }
            (_, _) => false,
        }
    }
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq))]
pub enum GiftBadgeError {
    /// receipt credential presentation failed to deserialize
    InvalidReceiptCredentialPresentation,
    /// state was FAILED but presentation was non-empty
    FailedStateWithNonEmptyPresentation,
}

impl TryFrom<proto::GiftBadge> for GiftBadge {
    type Error = GiftBadgeError;

    fn try_from(value: proto::GiftBadge) -> Result<Self, Self::Error> {
        let proto::GiftBadge {
            receiptCredentialPresentation,
            state,
            special_fields: _,
        } = value;

        use proto::gift_badge::State;
        let state = match state.enum_value_or_default() {
            State::UNOPENED => GiftBadgeState::Unopened,
            State::OPENED => GiftBadgeState::Opened,
            State::REDEEMED => GiftBadgeState::Redeemed,
            State::FAILED => {
                if !receiptCredentialPresentation.is_empty() {
                    return Err(GiftBadgeError::FailedStateWithNonEmptyPresentation);
                }
                return Ok(GiftBadge::Failed);
            }
        };

        let receipt_credential_presentation = zkgroup::deserialize(&receiptCredentialPresentation)
            .map_err(|_: ZkGroupDeserializationFailure| {
                GiftBadgeError::InvalidReceiptCredentialPresentation
            })?;

        Ok(Self::Valid {
            receipt_credential_presentation,
            state,
        })
    }
}

#[cfg(test)]
mod test {
    use test_case::test_case;
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
            Ok(GiftBadge::Valid {
                receipt_credential_presentation: proto::GiftBadge::test_data_presentation(),
                state: GiftBadgeState::Redeemed,
            })
        );
    }

    #[test_case(|x| x.receiptCredentialPresentation = vec![] => Err(GiftBadgeError::InvalidReceiptCredentialPresentation); "invalid presentation")]
    #[test_case(|x| x.state = proto::gift_badge::State::FAILED.into() => Err(GiftBadgeError::FailedStateWithNonEmptyPresentation); "FAILED with presentation")]
    #[test_case(|x| {
        x.state = proto::gift_badge::State::FAILED.into();
        x.receiptCredentialPresentation = vec![];
    } => Ok(()); "FAILED with no presentation")]
    fn gift_badge(modifier: impl FnOnce(&mut proto::GiftBadge)) -> Result<(), GiftBadgeError> {
        let mut gift_badge = proto::GiftBadge::test_data();
        modifier(&mut gift_badge);
        GiftBadge::try_from(gift_badge).map(|_| ())
    }
}
