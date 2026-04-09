//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::borrow::Cow;

use async_trait::async_trait;
use displaydoc::Display;
use rand::Rng;

use super::{AllowRateLimitChallenges, RequestError, UploadForm};

pub struct BackupAuth<'a> {
    credential: Cow<'a, zkgroup::backups::BackupAuthCredential>,
    server_keys: Cow<'a, zkgroup::generic_server_params::GenericServerPublicParams>,
    signing_key: Cow<'a, libsignal_core::curve::PrivateKey>,
}

pub(crate) struct BackupAuthPresentation {
    pub(crate) serialized_presentation: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

impl<'a> BackupAuth<'a> {
    // TODO: adjust this to whatever is most convenient for bridging.
    pub fn new(
        credential: &'a zkgroup::backups::BackupAuthCredential,
        server_keys: &'a zkgroup::generic_server_params::GenericServerPublicParams,
        signing_key: &'a libsignal_core::curve::PrivateKey,
    ) -> Self {
        Self {
            credential: Cow::Borrowed(credential),
            server_keys: Cow::Borrowed(server_keys),
            signing_key: Cow::Borrowed(signing_key),
        }
    }

    pub(crate) fn present<E>(
        &self,
        rng: &mut dyn rand::CryptoRng,
    ) -> Result<BackupAuthPresentation, RequestError<E>> {
        let presentation = self.credential.present(&self.server_keys, rng.random());
        let serialized_presentation = zkgroup::serialize(&presentation);
        let signature = self
            .signing_key
            .calculate_signature(&serialized_presentation, rng)
            .map_err(|e| RequestError::Unexpected {
                log_safe: format!("invalid signing key for BackupAuth: {e}"),
            })?;
        Ok(BackupAuthPresentation {
            serialized_presentation,
            signature: signature.into(),
        })
    }
}

#[derive(Debug, Display)]
pub enum GetUploadFormFailure {
    /// The upload form credential was rejected
    Unauthorized,
    /// The provided uploadLength is larger than the maximum supported upload size.
    UploadTooLarge,
}

/// High-level chat-server APIs for backups
///
/// ### Generic?
///
/// The type parameter `T` is a marker to distinguish blanket impls that would otherwise overlap.
/// Any concrete type will only impl this trait in one way; anywhere that needs to use
/// UnauthenticatedChatApi generically should accept an arbitrary `T` here.
#[async_trait]
pub trait UnauthenticatedChatApi<T> {
    // Not intended to be overridden.
    const ALLOW_RATE_LIMIT_CHALLENGES: AllowRateLimitChallenges = AllowRateLimitChallenges::No;

    async fn get_upload_form(
        &self,
        auth: &BackupAuth,
        upload_size: u64,
        rng: &mut (dyn rand::CryptoRng + Send),
    ) -> Result<UploadForm, RequestError<GetUploadFormFailure>>;

    async fn get_media_upload_form(
        &self,
        auth: &BackupAuth,
        upload_size: u64,
        rng: &mut (dyn rand::CryptoRng + Send),
    ) -> Result<UploadForm, RequestError<GetUploadFormFailure>>;
}

#[cfg(test)]
pub(crate) mod testutil {
    use data_encoding_macro::base64;

    use super::*;

    impl BackupAuth<'static> {
        pub(crate) fn generate_for_testing(
            credential_type: zkgroup::backups::BackupCredentialType,
            rng: &mut dyn rand::CryptoRng,
        ) -> Self {
            let server_keys =
                zkgroup::generic_server_params::GenericServerSecretParams::generate(rng.random());
            let server_public = server_keys.get_public_params();

            let aep = libsignal_account_keys::AccountEntropyPool::generate(rng);
            let backup_key =
                libsignal_account_keys::BackupKey::derive_from_account_entropy_pool(&aep);
            let aci: libsignal_core::Aci = uuid::Builder::from_random_bytes(rng.random())
                .into_uuid()
                .into();

            let context =
                zkgroup::backups::BackupAuthCredentialRequestContext::new(&backup_key, aci);
            let request = context.get_request();
            let redemption_time = zkgroup::Timestamp::from_epoch_seconds(1771545600); // 2026-02-20 00:00
            let response = request.issue(
                redemption_time,
                zkgroup::backups::BackupLevel::Paid,
                credential_type,
                &server_keys,
                rng.random(),
            );
            let credential = context
                .receive(response, &server_public, redemption_time)
                .expect("valid");

            let signing_key = libsignal_core::curve::KeyPair::generate(rng);

            Self {
                credential: Cow::Owned(credential),
                server_keys: Cow::Owned(server_public),
                signing_key: Cow::Owned(signing_key.private_key),
            }
        }

        /// The expected presentation from calling [`Self::generate_for_testing`] for a `Media`
        /// credential and then using it for a backups API.
        ///
        /// Both calls should use (independent) instances of [`super::testutil::fixed_seed_test_rng`].
        pub(crate) const EXPECTED_PRESENTATION: &[u8] = &base64!(
            "AMkAAAAAAAAAAgAAAAAAAAAApJdpAAAAAIoiVNK2DtZIRFCtQxRiSokkSiQEKrUm86QgMg+qyZZjLuJipcWuggZt6au2i4MOhslTP4qafDZUYWZnKdX7zV4MKW1+FqHVi9kns3+gGaHRCrUEqKcTBzZj/C79ZRJObwIAAAAAAAAA7vpvGr5uokinX1GRCgDr5au1ajuE2naAsAUXPXXpxTyKZo+S3m3OdyDUusIM3sIyUFwM1OeMtmHLgDcuGAqKdYAAAAAAAAAAcqkJSxGNgTB4ERB7Qcg8tp+IZnEhGxCzuvY3KqrjgwA1LniEMcZCO9kjcSL2Q5JS5yZYrv7Kkn0p3hY4vIrKBlgb0zycYLKRrUj+ndkHKJtWV/2xC42jehDUc1P2ufIEJfu4ScD+sUt9fgAV7uDsKI/ktXnhUPT7/ZxtCCp88gEU4nTfVFvK9jOhY6HRLRf/"
        );

        /// The expected signature from calling [`Self::generate_for_testing`] for a `Media`
        /// credential and then using it for a backups API.
        ///
        /// Both calls should use (independent) instances of [`super::testutil::fixed_seed_test_rng`].
        pub(crate) const EXPECTED_SIGNATURE: &[u8] = &base64!(
            "TUmhLTMN7LLUOphZiAF8WZekmWzYDWlDiqNm3LirWwcSotw+yUd+MOizCpwVD+Wp9dLHjqU00xUwm+KnxtiKiA=="
        );

        // The base-64 encoded properties of
        // BackupAuth::generate_for_testing(
        //     zkgroup::backups::BackupCredentialType::Media,
        //     &mut fixed_seed_test_rng(),
        // )
        pub(crate) const TEST_SIGNING_KEY: &[u8] =
            &base64!("KMhdmPEusAwoT3C2LzIbmGX6z+3HMbhgbrXmUwRfGF0=");
        pub(crate) const TEST_SERVER_KEYS: &[u8] = &base64!(
            "AIRCHmMrkZXZ9ZuwKJkA0GeMOaDSdVsU26AghADhY3l5XBYwf0UCtm2tvvYsbnPgh9uIUyERm0Wg3v7pFtg+OEfsM6fwjdBFqAgfeqs1pT9nwp2Wp6oGdAfCTrGcqraXJoyAiwAh3vogu7ltucNKh25zKiOkIeIEJNrjbx2eEwkFnqLYuk/noxaOi2Zl7R5d7+vn0Me0d2AZhu0Uuk1vpTIuYf+X4UJXV/N5TYYxwOe/OQHu4zZmdaPjtPN1EHFJC5ALV+8BY9dN5ddS7iTL1uq1ksURAA9hAZzC9/aTr7J7"
        );
        pub(crate) const TEST_CREDENTIAL: &[u8] = &base64!(
            "AACkl2kAAAAAyQAAAAAAAAACAAAAAAAAAMUH8mZNP0qDpXFbK2e3dKL04Zw1UhyJ5ab+RlRLhAYELu5/fvwOhxzvxcnNGpqppkGOWc7SSN0kEU0MMIslejR+FDPRx0BWeRTeMmr2ngFVaHUjmazUmgCAPkr0BuLjShTidN9UW8r2M6FjodEtF/8="
        );
    }
}

#[cfg(test)]
mod test {
    use base64::prelude::*;

    use super::*;
    use crate::api::testutil::fixed_seed_test_rng;

    #[test]
    fn expected_presentation_and_signature() {
        let auth = BackupAuth::generate_for_testing(
            zkgroup::backups::BackupCredentialType::Media,
            &mut fixed_seed_test_rng(),
        );
        assert_eq!(
            BASE64_STANDARD.encode(BackupAuth::TEST_SIGNING_KEY),
            BASE64_STANDARD.encode(auth.signing_key.serialize()),
        );
        assert_eq!(
            BASE64_STANDARD.encode(BackupAuth::TEST_SERVER_KEYS),
            BASE64_STANDARD.encode(zkgroup::serialize(&auth.server_keys)),
        );
        assert_eq!(
            BASE64_STANDARD.encode(BackupAuth::TEST_CREDENTIAL),
            BASE64_STANDARD.encode(zkgroup::serialize(&auth.credential)),
        );
        let presentation = auth
            .present::<std::convert::Infallible>(&mut fixed_seed_test_rng())
            .expect("valid");
        assert_eq!(
            presentation.serialized_presentation,
            BackupAuth::EXPECTED_PRESENTATION
        );
        assert_eq!(presentation.signature, BackupAuth::EXPECTED_SIGNATURE);
    }
}
