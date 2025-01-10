//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Display;

use crate::backup::time::{ReportUnusualTimestamp, Timestamp, TimestampError};
use crate::backup::{serialize, TryFromWith, TryIntoWith};
use crate::proto::backup as proto;

#[derive(Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct PaymentNotification {
    pub amount: Option<MobAmount>,
    pub fee: Option<MobAmount>,
    pub note: Option<String>,
    pub details: Option<TransactionDetails>,
}

#[derive(Clone, Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum TransactionDetails {
    Transaction(Box<Transaction>),
    FailedTransaction(FailedTransaction),
}

#[derive(Clone, Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Transaction {
    #[serde(serialize_with = "serialize::enum_as_string")]
    pub status: proto::payment_notification::transaction_details::transaction::Status,
    pub identification: Option<Identification>,
    pub timestamp: Option<Timestamp>,
    pub block_timestamp: Option<Timestamp>,
    pub block_index: Option<u64>,
    #[serde(serialize_with = "serialize::optional_hex")]
    pub transaction: Option<Vec<u8>>,
    #[serde(serialize_with = "serialize::optional_hex")]
    pub receipt: Option<Vec<u8>>,
}

/// Wrapper around an arbitrary-precision decimal number
#[derive(Clone, Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
#[serde(transparent)]
pub struct MobAmount(String);

#[derive(Clone, Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub enum Identification {
    #[serde(serialize_with = "serialize::list_of_hex")]
    Sent { key_images: Vec<Vec<u8>> },
    #[serde(serialize_with = "serialize::list_of_hex")]
    Received { public_keys: Vec<Vec<u8>> },
}

#[derive(Clone, Debug, serde::Serialize)]
#[cfg_attr(test, derive(PartialEq))]
#[serde(transparent)]
pub struct FailedTransaction {
    #[serde(serialize_with = "serialize::enum_as_string")]
    pub reason: proto::payment_notification::transaction_details::failed_transaction::FailureReason,
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum PaymentError {
    /// "amountMob" was not parsable
    InvalidAmount,
    /// "fee" was not parsable
    InvalidFee,
    /// TransactionDetails.payment is a oneof but has no value
    NoTransactionDetailsPayment,
    /// transaction details: {0}
    Transaction(#[from] TransactionError),
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub enum TransactionError {
    /// MobileCoinTxoIdentification has neither keyImages nor publicKey values
    EmptyIdentification,
    /// MobileCoinTxoIdentification has keyImages and publicKey values
    IdentificationContainsBoth,
    /// {0}
    InvalidTimestamp(#[from] TimestampError),
}

impl<C: ReportUnusualTimestamp> TryFromWith<proto::PaymentNotification, C> for PaymentNotification {
    type Error = PaymentError;

    fn try_from_with(value: proto::PaymentNotification, context: &C) -> Result<Self, Self::Error> {
        let proto::PaymentNotification {
            amountMob,
            feeMob,
            note,
            transactionDetails,
            special_fields: _,
        } = value;

        let amount = amountMob
            .map(MobAmount::try_from)
            .transpose()
            .map_err(|ParseError| PaymentError::InvalidAmount)?;

        let fee = feeMob
            .map(MobAmount::try_from)
            .transpose()
            .map_err(|ParseError| PaymentError::InvalidFee)?;

        let details = transactionDetails
            .into_option()
            .map(
                |proto::payment_notification::TransactionDetails {
                     payment,
                     special_fields: _,
                 }| {
                    use proto::payment_notification::transaction_details::Payment;
                    match payment.ok_or(PaymentError::NoTransactionDetailsPayment)? {
                        Payment::Transaction(transaction) => transaction
                            .try_into_with(context)
                            .map(|t| TransactionDetails::Transaction(Box::new(t))),
                        Payment::FailedTransaction(failed) => {
                            failed.try_into().map(TransactionDetails::FailedTransaction)
                        }
                    }
                    .map_err(PaymentError::from)
                },
            )
            .transpose()?;

        Ok(Self {
            amount,
            fee,
            note,
            details,
        })
    }
}

impl<C: ReportUnusualTimestamp>
    TryFromWith<proto::payment_notification::transaction_details::Transaction, C> for Transaction
{
    type Error = TransactionError;

    fn try_from_with(
        value: proto::payment_notification::transaction_details::Transaction,
        context: &C,
    ) -> Result<Self, Self::Error> {
        use proto::payment_notification::transaction_details::transaction::Status;
        use proto::payment_notification::transaction_details::{
            MobileCoinTxoIdentification, Transaction as TransactionProto,
        };

        let TransactionProto {
            status,
            mobileCoinIdentification,
            timestamp,
            blockIndex,
            blockTimestamp,
            transaction,
            receipt,
            special_fields: _,
        } = value;

        let status = match status.enum_value_or_default() {
            // Pass the value through but fail compilation if a new variant is added.
            s @ (Status::INITIAL | Status::SUBMITTED | Status::SUCCESSFUL) => s,
        };

        let identification = mobileCoinIdentification
            .into_option()
            .map(
                |MobileCoinTxoIdentification {
                     keyImages,
                     publicKey,
                     special_fields: _,
                 }| {
                    Ok(match (keyImages.is_empty(), publicKey.is_empty()) {
                        (true, true) => return Err(TransactionError::EmptyIdentification),
                        (false, true) => Identification::Sent {
                            key_images: keyImages,
                        },
                        (true, false) => Identification::Received {
                            public_keys: publicKey,
                        },
                        (false, false) => return Err(TransactionError::IdentificationContainsBoth),
                    })
                },
            )
            .transpose()?;

        let timestamp = timestamp
            .map(|t| Timestamp::from_millis(t, "Transaction.timestamp", context))
            .transpose()?;
        let block_timestamp = blockTimestamp
            .map(|t| Timestamp::from_millis(t, "Transaction.blockTimestamp", context))
            .transpose()?;

        Ok(Self {
            status,
            identification,
            timestamp,
            block_index: blockIndex,
            block_timestamp,
            transaction,
            receipt,
        })
    }
}

impl TryFrom<proto::payment_notification::transaction_details::FailedTransaction>
    for FailedTransaction
{
    type Error = TransactionError;

    fn try_from(
        value: proto::payment_notification::transaction_details::FailedTransaction,
    ) -> Result<Self, Self::Error> {
        use proto::payment_notification::transaction_details::failed_transaction::FailureReason;
        use proto::payment_notification::transaction_details::FailedTransaction as FailedTransactionProto;

        let FailedTransactionProto {
            reason,
            special_fields: _,
        } = value;

        let reason = match reason.enum_value_or_default() {
            r @ (FailureReason::GENERIC
            | FailureReason::NETWORK
            | FailureReason::INSUFFICIENT_FUNDS) => r,
        };

        Ok(Self { reason })
    }
}

#[derive(Copy, Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ParseError;

impl TryFrom<String> for MobAmount {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let (integral, fractional) = s.split_once('.').unwrap_or((&s, ""));
        if integral.is_empty() && fractional.is_empty() {
            return Err(ParseError);
        }

        for c in integral.chars().chain(fractional.chars()) {
            if !c.is_ascii_digit() {
                return Err(ParseError);
            }
        }
        Ok(Self(s))
    }
}

impl Display for MobAmount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use test_case::test_case;

    use super::*;
    use crate::backup::testutil::TestContext;
    use crate::backup::time::testutil::MillisecondsSinceEpoch;

    impl FromStr for MobAmount {
        type Err = ParseError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            Self::try_from(s.to_string())
        }
    }

    impl proto::PaymentNotification {
        const TEST_NOTE: &'static str = "note";

        pub(crate) fn test_data() -> Self {
            Self {
                amountMob: Some("123".to_string()),
                feeMob: Some("0".to_string()),
                note: Some(Self::TEST_NOTE.to_string()),
                transactionDetails: None.into(),
                special_fields: Default::default(),
            }
        }
    }

    #[test]
    fn valid_payment_notification() {
        assert_eq!(
            proto::PaymentNotification::test_data().try_into_with(&TestContext::default()),
            Ok(PaymentNotification {
                amount: Some("123".parse().unwrap()),
                fee: Some("0".parse().unwrap()),
                note: Some(proto::PaymentNotification::TEST_NOTE.to_string()),
                details: None,
            })
        );
    }

    #[test_case(|x| x.amountMob = Some("abc".to_string()) => Err(PaymentError::InvalidAmount); "invalid amount")]
    #[test_case(|x| x.feeMob = Some("0.five".to_string()) => Err(PaymentError::InvalidFee); "invalid fee")]
    #[test_case(|x| x.amountMob = None => Ok(()); "no amount")]
    #[test_case(|x| x.feeMob = None => Ok(()); "no fee")]
    fn payment_notification(
        modifier: fn(&mut proto::PaymentNotification),
    ) -> Result<(), PaymentError> {
        let mut notification = proto::PaymentNotification::test_data();
        modifier(&mut notification);
        notification
            .try_into_with(&TestContext::default())
            .map(|_: PaymentNotification| ())
    }

    impl proto::payment_notification::transaction_details::Transaction {
        fn test_data() -> Self {
            Self {
                mobileCoinIdentification: Some(proto::payment_notification::transaction_details::MobileCoinTxoIdentification::test_data()).into(),
                timestamp: Some(MillisecondsSinceEpoch::TEST_VALUE.0),
                blockIndex:Some(123),
                blockTimestamp: Some(MillisecondsSinceEpoch::TEST_VALUE.0),
                ..Default::default()
            }
        }
    }

    impl proto::payment_notification::transaction_details::MobileCoinTxoIdentification {
        fn test_data() -> Self {
            Self {
                publicKey: vec![],
                keyImages: vec![b"key".to_vec()],
                special_fields: Default::default(),
            }
        }
    }

    impl Identification {
        fn from_proto_test_data() -> Self {
            Self::Sent {
                key_images: vec![b"key".to_vec()],
            }
        }
    }

    #[test]
    fn valid_transaction() {
        assert_eq!(
            proto::payment_notification::transaction_details::Transaction::test_data()
                .try_into_with(&TestContext::default()),
            Ok(Transaction {
                status:
                    proto::payment_notification::transaction_details::transaction::Status::INITIAL,
                identification: Some(Identification::from_proto_test_data()),
                timestamp: Some(Timestamp::test_value()),
                block_timestamp: Some(Timestamp::test_value()),
                block_index: Some(123),
                transaction: None,
                receipt: None,
            })
        )
    }

    #[test_case(
        |x| x.timestamp = Some(MillisecondsSinceEpoch::FAR_FUTURE.0) =>
        Err(TransactionError::InvalidTimestamp(TimestampError("Transaction.timestamp", MillisecondsSinceEpoch::FAR_FUTURE.0)));
        "invalid timestamp"
    )]
    #[test_case(
        |x| x.blockTimestamp = Some(MillisecondsSinceEpoch::FAR_FUTURE.0) =>
        Err(TransactionError::InvalidTimestamp(TimestampError("Transaction.blockTimestamp", MillisecondsSinceEpoch::FAR_FUTURE.0)));
        "invalid blockTimestamp"
    )]
    fn transaction(
        modifier: fn(&mut proto::payment_notification::transaction_details::Transaction),
    ) -> Result<(), TransactionError> {
        let mut transaction =
            proto::payment_notification::transaction_details::Transaction::test_data();
        modifier(&mut transaction);
        Transaction::try_from_with(transaction, &TestContext::default()).map(|_| ())
    }

    fn both(
        ident: &mut proto::payment_notification::transaction_details::MobileCoinTxoIdentification,
    ) {
        ident.keyImages = vec![vec![1, 2, 3]];
        ident.publicKey = vec![vec![1, 2, 3]];
    }
    fn neither(
        ident: &mut proto::payment_notification::transaction_details::MobileCoinTxoIdentification,
    ) {
        ident.keyImages.clear();
        ident.publicKey.clear();
    }

    #[test_case(neither, TransactionError::EmptyIdentification)]
    #[test_case(both, TransactionError::IdentificationContainsBoth)]
    fn invalid_transaction_identification(
        modifier: fn(
            &mut proto::payment_notification::transaction_details::MobileCoinTxoIdentification,
        ),
        expected_err: TransactionError,
    ) {
        let mut transaction =
            proto::payment_notification::transaction_details::Transaction::test_data();
        modifier(transaction.mobileCoinIdentification.as_mut().unwrap());
        assert_eq!(
            Transaction::try_from_with(transaction, &TestContext::default()),
            Err(expected_err)
        );
    }

    #[test_case("12", Ok(()); "no decimal")]
    #[test_case("0.5551895", Ok(()); "zero integral")]
    #[test_case(".5551895", Ok(()); "no integral")]
    #[test_case("", Err(ParseError); "empty")]
    #[test_case(".", Err(ParseError); "decimal point")]
    #[test_case("123.", Ok(()); "trailing decimal point")]
    #[test_case("a.5551895", Err(ParseError); "invalid integral")]
    #[test_case("123.abc", Err(ParseError); "invalid decimal")]
    fn parse_mob_amount(input: &str, expected: Result<(), ParseError>) {
        let expected = expected.map(|()| input);
        let parsed = MobAmount::from_str(input);
        let result = parsed.clone().map(|m| m.to_string());

        assert_eq!(result.as_deref(), expected.as_deref(), "{parsed:?}")
    }
}
