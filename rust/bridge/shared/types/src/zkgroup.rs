//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use ::zkgroup;
use partial_default::PartialDefault;
use serde::Deserialize;
use zkgroup::groups::*;
use zkgroup::profiles::*;
use zkgroup::receipts::*;
pub use zkgroup::Timestamp;
use zkgroup::*;

use crate::support::*;
use crate::*;

/// Checks that `bytes` can be deserialized as a `T` using our standard bincode settings.
pub fn validate_serialization<'a, T: Deserialize<'a> + PartialDefault>(
    bytes: &'a [u8],
) -> Result<(), ZkGroupDeserializationFailure> {
    zkgroup::deserialize::<T>(bytes).map(|_| ())
}

/// Implements [`FixedLengthBincodeSerializable`] for a ZKGroup serializable type.
///
/// `bridge_as_fixed_length_serializable!(FooBar)` generates
/// `impl FixedLengthBincodeSerializable for FooBar`, using `[u8; FOO_BAR_LEN]` as the associated
/// array type.
///
/// To be used with [`bridge_fixed_length_serializable_fns`].
macro_rules! bridge_as_fixed_length_serializable {
    ($typ:ident) => {
        ::paste::paste! {
            // Declare a marker type for TypeScript, the same as bridge_as_handle.
            // (This is harmless for the other bridges.)
            #[doc = "ts: interface " $typ " { readonly __type: unique symbol; }"]
            impl FixedLengthBincodeSerializable for $typ {
                type Array = [u8; [<$typ:snake:upper _LEN>]];
            }
        }
    };
}

/// Defines functions for types that implement [`FixedLengthBincodeSerializable`].
///
/// `bridge_fixed_length_serializable_fns!(FooBar)` generates
/// `#[bridge_fn] fn FooBar_CheckValidContents`, which checks that the type can be deserialized.
#[macro_export]
macro_rules! bridge_fixed_length_serializable_fns {
    ($typ:ident) => {
        ::paste::paste! {
            #[bridge_fn]
            fn [<$typ _CheckValidContents>](
                buffer: &[u8]
            ) -> Result<(), ZkGroupDeserializationFailure> {
                if buffer.len() != <$typ as FixedLengthBincodeSerializable>::Array::LEN {
                    return Err(ZkGroupDeserializationFailure::new::<$typ>())
                }
                $crate::zkgroup::validate_serialization::<$typ>(buffer)
            }
        }
    };
}

/// Bridges a ZKGroup serializable type via [`FixedLengthBincodeSerializable`].
///
/// `bridge_serializable_handle_fns!(FooBar)` generates
/// - `#[bridge_fn] fn FooBar_Deserialize` for deserializing into a `FooBar`, and
/// - `#[bridge_fn] fn FooBar_Serialize` for serializing a `FooBar` again.
#[macro_export]
macro_rules! bridge_serializable_handle_fns {
    ($typ:ident) => {
        $crate::bridge_handle_fns!($typ, clone = false);
        ::paste::paste! {
            #[bridge_fn]
            fn [<$typ _Deserialize>](
                buffer: &[u8]
            ) -> Result<$typ, ZkGroupDeserializationFailure> {
                zkgroup::deserialize(buffer)
            }
            #[bridge_fn]
            fn [<$typ _Serialize>](
                handle: & $typ,
            ) -> Vec<u8> {
                zkgroup::serialize(handle)
            }
        }
    };
}

bridge_as_fixed_length_serializable!(ExpiringProfileKeyCredential);
bridge_as_fixed_length_serializable!(ExpiringProfileKeyCredentialResponse);
bridge_as_fixed_length_serializable!(GroupMasterKey);
bridge_as_fixed_length_serializable!(GroupPublicParams);
bridge_as_fixed_length_serializable!(GroupSecretParams);
bridge_as_fixed_length_serializable!(ProfileKey);
bridge_as_fixed_length_serializable!(ProfileKeyCiphertext);
bridge_as_fixed_length_serializable!(ProfileKeyCommitment);
bridge_as_fixed_length_serializable!(ProfileKeyCredentialRequest);
bridge_as_fixed_length_serializable!(ProfileKeyCredentialRequestContext);
bridge_as_fixed_length_serializable!(ReceiptCredential);
bridge_as_fixed_length_serializable!(ReceiptCredentialPresentation);
bridge_as_fixed_length_serializable!(ReceiptCredentialRequest);
bridge_as_fixed_length_serializable!(ReceiptCredentialRequestContext);
bridge_as_fixed_length_serializable!(ReceiptCredentialResponse);
bridge_as_fixed_length_serializable!(UuidCiphertext);

bridge_as_handle!(ServerPublicParams);
bridge_as_handle!(ServerSecretParams);
