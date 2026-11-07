//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use aes_gcm::aead::Aead;
use aes_gcm::aes::cipher::Array;
use aes_gcm::{AeadInOut, Aes256Gcm, KeyInit, aead};
use libsignal_core::Aci;
use libsignal_net_grpc::proto::chat::profile::get_profile_response::Response as GetProfileResponseEnum;
use libsignal_net_grpc::proto::chat::profile::set_profile_response::Response as SetProfileResponseEnum;
use libsignal_net_grpc::proto::chat::profile::set_profile_v1_request::AvatarChange;
use libsignal_net_grpc::proto::chat::profile::{
    AccountInfo, LegacyProfileResult as ProfilesV1GrpcResult, PlaintextProfileData,
    ProfileResult as ProfilesV2GrpcResult, SetProfileRequest, SetProfileV1Request,
};
use libsignal_protocol::IdentityKey;
use prost::Message;
use rand::CryptoRng;
use sha2::Digest;
use zkgroup::profiles::{ProfileKey, ProfileKeyVersion};

use super::{
    CdnUrl, FetchedProfile, PROFILE_ETAG_LEN, PaymentAddress, Profile, ProfileDataHash,
    ProfileDecodeError, ProfileEtag, ProfileValidationError,
};

// These constants are from the protobuf.
const V1_NAME_ALLOWED_SIZES: &[usize] = &[81, 285];
const V1_ABOUT_EMOJI_ALLOWED_SIZES: &[usize] = &[0, 60];
const V1_ABOUT_ALLOWED_SIZES: &[usize] = &[0, 156, 282, 540];
const V1_PHONE_NUMBER_SHARING_ALLOWED_SIZES: &[usize] = &[29];
const PROFILE_VERSION_ALLOWED_SIZE: usize = 32;
const PROFILE_DATA_MAX_SIZE: usize = 1486;
const EXPECTED_CURRENT_DATA_HASH_ALLOWED_SIZES: &[usize] = &[0, 32];
const EXPECTED_CURRENT_VERSION_ALLOWED_SIZES: &[usize] = &[0, 32];
const PAYMENT_ADDRESS_MAX_ALLOWED_SIZE: usize = 582;
const PAYMENT_ADDRESS_ALLOWED_SIZES: &[usize] = &[0, PAYMENT_ADDRESS_MAX_ALLOWED_SIZE];
const COMMITMENT_ALLOWED_SIZES: &[usize] = &[97];

#[test]
fn allowed_size_slices_are_sorted() {
    for slice in [
        V1_NAME_ALLOWED_SIZES,
        V1_ABOUT_ALLOWED_SIZES,
        V1_ABOUT_EMOJI_ALLOWED_SIZES,
        V1_PHONE_NUMBER_SHARING_ALLOWED_SIZES,
        EXPECTED_CURRENT_DATA_HASH_ALLOWED_SIZES,
        EXPECTED_CURRENT_VERSION_ALLOWED_SIZES,
        PAYMENT_ADDRESS_ALLOWED_SIZES,
        COMMITMENT_ALLOWED_SIZES,
    ] {
        let mut buf = slice.to_vec();
        buf.sort_unstable();
        assert_eq!(buf.as_slice(), slice);
    }
}

#[derive(derive_more::From, Debug, PartialEq, Eq)]
pub(super) enum Error {
    ProfileDecodeError(ProfileDecodeError),
    Unexpected { log_safe: String },
}

impl FetchedProfile {
    /// Make a [`FetchedProfile`] out of:
    ///
    /// 1. The decrypted [`Profile`], which this function will validate.
    /// 2. The server-provided [`AccountInfo`] protobuf
    /// 3. The [`ProfileEtag`]
    /// 4. The v2 profile data hash
    fn new(
        account_info: &AccountInfo,
        etag: Option<ProfileEtag>,
        profile: Profile,
        v2_data_hash: Option<ProfileDataHash>,
    ) -> Result<FetchedProfile, Error> {
        if let Err(e) = profile.validate() {
            return Err(ProfileDecodeError::IncomingProfileValidationFailed(e).into());
        }
        Ok(FetchedProfile {
            profile,
            etag,
            v2_data_hash,
            identity_key: IdentityKey::decode(&account_info.identity_key).map_err(|_| {
                Error::Unexpected {
                    log_safe: "Cannot decode identity key".into(),
                }
            })?,
            unidentified_access_key_fingerprint: if account_info
                .unidentified_access_key_fingerprint
                .is_empty()
            {
                None
            } else {
                Some(
                    account_info
                        .unidentified_access_key_fingerprint
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::Unexpected {
                            log_safe: format!(
                                "Unexpected UAK fingerprint length: {}",
                                account_info.unidentified_access_key_fingerprint.len()
                            ),
                        })?,
                )
            },
            unrestricted_unidentified_access: account_info.unrestricted_unidentified_access,
        })
    }
}

pub(super) mod v2 {
    use super::*;

    const AAD_PROFILE_DATA: &[u8] = b"20261020_ProfilesV2_ProfileData";
    pub(super) fn unpadded_encrypt_profile_data(
        key: &Aes256Gcm,
        rng: &mut dyn CryptoRng,
        plaintext: Vec<u8>,
    ) -> Vec<u8> {
        let mut in_out = plaintext;
        // TODO: when we upgrade to rand 0.10, use Nonce::generate_from_rng()
        let mut nonce = aes_gcm::Nonce::default();
        rng.fill_bytes(&mut nonce);
        key.encrypt_in_place(&nonce, AAD_PROFILE_DATA, &mut in_out)
            .expect("vec allocation cannot fail");
        in_out.extend_from_slice(&nonce);
        in_out
    }
    pub(super) fn encrypt_profile_data(
        key: &Aes256Gcm,
        rng: &mut dyn CryptoRng,
        mut plaintext: Vec<u8>,
    ) -> Vec<u8> {
        padding::pad_in_place(&mut plaintext);
        unpadded_encrypt_profile_data(key, rng, plaintext)
    }
    fn decrypt_profile_data(
        key: &Aes256Gcm,
        mut in_out: Vec<u8>,
    ) -> Result<Vec<u8>, ProfileDecodeError> {
        let Some((_, nonce)) = in_out.split_last_chunk() else {
            return Err(ProfileDecodeError::ProfileV2DataTooSmallForNonce { len: in_out.len() });
        };
        let nonce = Array(*nonce);
        in_out.truncate(in_out.len() - nonce.len());
        key.decrypt_in_place(&nonce, AAD_PROFILE_DATA, &mut in_out)
            .map_err(|_| ProfileDecodeError::ProfileV2DataFailedDecryption)?;
        padding::unpad(in_out)
    }

    pub(crate) fn decrypt_profile(
        profile_key: &ProfileKey,
        profile_result: ProfilesV2GrpcResult,
    ) -> Result<FetchedProfile, Error> {
        let Some(account_info) = profile_result.account_info.as_ref() else {
            return Err(Error::Unexpected {
                log_safe: "missing account info".into(),
            });
        };
        let etag = if let Ok(etag) = ProfileEtag::try_from(profile_result.etag.as_slice()) {
            if etag == compute_profile_etag(&profile_result) {
                Some(etag)
            } else {
                log::warn!("Incorrect server-sent profile etag");
                None
            }
        } else {
            if profile_result.etag.len() != PROFILE_ETAG_LEN {
                log::warn!("Unexpected profile etag size {}", profile_result.etag.len());
            }
            None
        };
        let key = Aes256Gcm::new(&Array(profile_key.bytes));
        let v2_data_hash = sha2::Sha256::digest(&profile_result.data).0;
        let data = decrypt_profile_data(&key, profile_result.data)?;
        let payment_address =
            super::v1::decrypt_payment_address(&key, &profile_result.payment_address)?;
        let PlaintextProfileData {
            given_name,
            family_name,
            about,
            about_emoji,
            avatar_url,
            phone_number_sharing,
        } = PlaintextProfileData::decode(data.as_slice())
            .map_err(|_| ProfileDecodeError::ProfileV2InvalidProtobuf)?;
        let profile = Profile {
            given_name,
            family_name,
            about,
            about_emoji,
            avatar: if avatar_url.is_empty() {
                None
            } else {
                Some(CdnUrl::try_from(avatar_url).map_err(ProfileDecodeError::InvalidAvatarUrl)?)
            },
            phone_number_sharing,
            payment_address,
            badge_ids: account_info.badge_ids.clone(),
        };
        FetchedProfile::new(account_info, etag, profile, Some(v2_data_hash))
    }

    mod padding {
        //! PKCS#7
        use super::*;

        const BLOCK_SIZE: usize = 255;
        pub(super) fn pad_in_place(buf: &mut Vec<u8>) {
            let to_pad = BLOCK_SIZE - (buf.len() % BLOCK_SIZE);
            debug_assert_ne!(to_pad, 0);
            let padding_byte = u8::try_from(to_pad).expect("fits in u8");
            let new_len = to_pad + buf.len();
            debug_assert!(new_len.is_multiple_of(BLOCK_SIZE));
            buf.resize(new_len, padding_byte);
        }
        pub(super) fn unpad(mut buf: Vec<u8>) -> Result<Vec<u8>, ProfileDecodeError> {
            let Some(&padding_size) = buf.last() else {
                return Err(
                    ProfileDecodeError::ProfileV2DataEmptyProfileBufferCannotContainPadding,
                );
            };
            if padding_size == 0 {
                return Err(ProfileDecodeError::ProfileV2BufferZeroPadding);
            }
            let Some(orig_len) = buf.len().checked_sub(usize::from(padding_size)) else {
                return Err(ProfileDecodeError::ProfileV2DataTooSmallForClaimedPadding {
                    buffer_size: buf.len(),
                    padding_size,
                });
            };
            if buf[orig_len..].iter().any(|byte| *byte != padding_size) {
                return Err(ProfileDecodeError::ProfileV2DataInvalidPaddingByte { padding_size });
            }
            buf.truncate(orig_len);
            Ok(buf)
        }

        #[test]
        fn padding_roundtrip() {
            use rand::{RngCore, SeedableRng};
            let mut seed = 0;
            for orig_size in 0..=(BLOCK_SIZE * 3) {
                for _trial in 0..3 {
                    seed += 1;
                    let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
                    let mut orig = vec![0; orig_size];
                    rng.fill_bytes(&mut orig);
                    let mut buf = orig.clone();
                    pad_in_place(&mut buf);
                    assert!(buf.len() > orig.len());
                    assert_eq!(unpad(buf).expect("unpadding succeeds"), orig);
                }
            }
        }
    }

    use libcrux_sha3::portable::incremental::{CShake, CShake256, left_encode, right_encode};
    /// TupleHash256
    ///
    /// See <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf>, page 13
    struct TupleHash {
        inner: CShake256,
    }
    impl TupleHash {
        fn new(customization: &[u8]) -> Self {
            Self {
                inner: CShake256::new_cshake(b"TupleHash", customization),
            }
        }
        fn add(&mut self, field: &[u8]) {
            let mut buffer = Default::default();
            self.inner
                .absorb_cshake(left_encode(field.len() * 8, &mut buffer));
            self.inner.absorb_cshake(field);
        }
        fn output(mut self, dst: &mut [u8]) {
            let mut buffer = Default::default();
            self.inner
                .absorb_final_cshake(right_encode(dst.len() * 8, &mut buffer));
            self.inner.squeeze_cshake(dst);
        }
    }

    #[test]
    fn test_tuple_hash() {
        use base64::prelude::*;
        let test_cases: &'static [(&'static [&'static [u8]], &'static [u8])] = &[
            (&[], b"bwKpMcT0WpxvNw=="),
            (&[b"A"], b"JN88ggYlJ+5Jsg=="),
            (&[b"A", b"B"], b"hY2n/SF70MyUWg=="),
        ];
        for (i, (inputs, expected_output)) in test_cases.iter().enumerate() {
            let mut h = TupleHash::new(ETAG_DOMAIN);
            for input in inputs.iter() {
                h.add(input);
            }
            let mut out = ProfileEtag::default();
            h.output(&mut out);
            assert_eq!(
                out.to_vec(),
                BASE64_STANDARD
                    .decode(expected_output)
                    .expect("valid base64"),
                "Test case {i}"
            );
        }
    }

    const ETAG_DOMAIN: &[u8] = b"ProfileETag/v1";
    /// What etag should the server have generated for this protobuf result?
    // Public for test
    pub(super) fn compute_profile_etag(
        ProfilesV2GrpcResult {
            data,
            payment_address,
            account_info,
            etag: _,
        }: &ProfilesV2GrpcResult,
    ) -> ProfileEtag {
        // This function must be kept in sync with the server's ProfileGrpcHelper.etag() function
        let mut h = TupleHash::new(ETAG_DOMAIN);
        h.add(data);
        h.add(payment_address);
        const DEFAULT_ACCOUNT_INFO: &AccountInfo = &AccountInfo {
            identity_key: Vec::new(),
            unidentified_access_key_fingerprint: Vec::new(),
            unrestricted_unidentified_access: false,
            badge_ids: Vec::new(),
        };
        let AccountInfo {
            identity_key,
            unidentified_access_key_fingerprint,
            unrestricted_unidentified_access,
            badge_ids,
        } = account_info.as_ref().unwrap_or(DEFAULT_ACCOUNT_INFO);
        h.add(identity_key);
        h.add(unidentified_access_key_fingerprint);
        h.add(&[*unrestricted_unidentified_access as u8]);
        h.add(
            &u32::try_from(badge_ids.len())
                .expect("u32 badges")
                .to_be_bytes(),
        );
        let mut sorted_badges: Vec<_> = badge_ids.iter().map(|id| id.as_bytes()).collect();
        sorted_badges.sort_unstable();
        for badge in sorted_badges {
            h.add(badge);
        }
        let mut out = ProfileEtag::default();
        h.output(&mut out);
        out
    }
    #[test]
    fn etag_test_vectors() {
        use base64::prelude::*;
        // See Server's ProfileGrpcHelperTest:etagTestVectors()
        for (mut protobuf, output_hash) in [
            // empty
            (
                ProfilesV2GrpcResult {
                    account_info: Some(Default::default()),
                    ..Default::default()
                },
                b"6NXrB3FC907RoA==",
            ),
            // all fields set
            (
                ProfilesV2GrpcResult {
                    data: b"profile-data".into(),
                    payment_address: b"payment-address".into(),
                    account_info: Some(AccountInfo {
                        identity_key: b"identity-key".into(),
                        unidentified_access_key_fingerprint: b"uak-checksum".into(),
                        unrestricted_unidentified_access: true,
                        badge_ids: vec!["badge-a".into(), "badge-b".into()],
                    }),
                    etag: Vec::new(),
                },
                b"zrvx5cC+UDrLzQ==",
            ),
            // badge id order doesn't matter
            (
                ProfilesV2GrpcResult {
                    account_info: Some(AccountInfo {
                        badge_ids: vec!["badgeZ".into(), "badgeQ".into(), "badgeQQ".into()],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                b"AS2DN9M/IapIgA==",
            ),
            (
                ProfilesV2GrpcResult {
                    account_info: Some(AccountInfo {
                        badge_ids: vec!["badgeQQ".into(), "badgeQ".into(), "badgeZ".into()],
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                b"AS2DN9M/IapIgA==",
            ),
            // Data Only
            (
                ProfilesV2GrpcResult {
                    data: vec![171, 205, 225, 35],
                    ..Default::default()
                },
                b"ZKDfIrGEKT1+Sw==",
            ),
            // Payment Address Only
            (
                ProfilesV2GrpcResult {
                    payment_address: vec![171, 205, 225, 35],
                    ..Default::default()
                },
                b"5CWKoXAq1/cuAg==",
            ),
        ] {
            for etag in [b"" as &[u8], b"etag"] {
                protobuf.etag = etag.into();
                let output_hash = BASE64_STANDARD.decode(output_hash).expect("valid base64");
                assert_eq!(compute_profile_etag(&protobuf).to_vec(), output_hash);
            }
        }
    }
}

pub(super) mod v1 {
    use super::*;
    pub(super) const ENCRYPTION_OVERHEAD: usize = 28;

    pub(super) fn decrypt_payment_address(
        key: &Aes256Gcm,
        data: &[u8],
    ) -> Result<Option<PaymentAddress>, Error> {
        if data.is_empty() {
            return Ok(None);
        }
        Ok(Some(decrypt_with_length(key, Field::PaymentAddress, data)?).filter(|x| !x.is_empty()))
    }

    pub(super) fn encrypt_payment_address(
        key: &Aes256Gcm,
        rng: &mut dyn CryptoRng,
        data: &PaymentAddress,
    ) -> Vec<u8> {
        encrypt_with_length(key, rng, PAYMENT_ADDRESS_MAX_ALLOWED_SIZE, data)
    }

    pub(crate) fn decrypt_profile(
        profile_key: &ProfileKey,
        profile_result: &ProfilesV1GrpcResult,
    ) -> Result<FetchedProfile, Error> {
        let Some(account_info) = profile_result.account_info.as_ref() else {
            return Err(Error::Unexpected {
                log_safe: "missing account info".into(),
            });
        };
        let key = Aes256Gcm::new(&Array(profile_key.bytes));
        let full_name = decrypt_string(&key, Field::Name, &profile_result.name)?;
        let (given_name, family_name) = full_name.split_once('\0').unwrap_or((&full_name, ""));
        let profile = Profile {
            given_name: given_name.to_string(),
            family_name: family_name.to_string(),
            about: decrypt_string(&key, Field::About, &profile_result.about)?,
            about_emoji: decrypt_string(&key, Field::AboutEmoji, &profile_result.about_emoji)?,
            avatar: if profile_result.avatar.is_empty() {
                None
            } else {
                Some(
                    CdnUrl::try_from(format!("{}{}", CdnUrl::CDN0, profile_result.avatar))
                        .expect("this string has a valid prefix by construction"),
                )
            },
            phone_number_sharing: decrypt_boolean(
                &key,
                Field::PhoneNumberSharing,
                &profile_result.phone_number_sharing,
            )?,
            payment_address: decrypt_payment_address(&key, &profile_result.payment_address)?,
            badge_ids: account_info.badge_ids.clone(),
        };
        FetchedProfile::new(account_info, None, profile, None)
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Field {
        PhoneNumberSharing,
        Name,
        About,
        AboutEmoji,
        PaymentAddress,
    }

    /// Encrypt the input, zero padding it (at the end) so the final ciphertext will be
    /// `padded_length` bytes.
    ///
    /// `padded_length` must therefore be at least `ENCRYPTION_OVERHEAD`
    ///
    /// Note that some clients treat `padded_length` as the amount of padding of the plaintext.
    pub(super) fn padded_encrypt(
        key: &Aes256Gcm,
        rng: &mut dyn CryptoRng,
        padded_length: usize,
        input: &[u8],
    ) -> Vec<u8> {
        let padded_minus_overhead = padded_length - ENCRYPTION_OVERHEAD;
        assert!(
            input.len() <= padded_minus_overhead,
            "{} <= {padded_minus_overhead}",
            input.len()
        );
        let mut buf = input.to_vec();
        buf.resize(padded_minus_overhead, 0);
        // TODO: when we upgrade to rand 0.10, use Nonce::generate_from_rng()
        let mut nonce = aes_gcm::Nonce::default();
        rng.fill_bytes(&mut nonce);
        key.encrypt_in_place(&nonce, b"", &mut buf)
            .expect("vec resize cannot fail");
        buf.splice(0..0, nonce);
        assert_eq!(buf.len(), padded_length);
        buf
    }
    fn decrypt_keeping_padding(
        key: &Aes256Gcm,
        field: Field,
        input: &[u8],
    ) -> Result<Vec<u8>, ProfileDecodeError> {
        // Note that an empty input is _unauthenticated_, because the server will return an empty
        // ciphertext for fields that haven't been set.
        if input.is_empty() {
            return Ok(Vec::new());
        }
        let Some((nonce, ciphertext)) = input.split_first_chunk() else {
            return Err(ProfileDecodeError::ProfileV1FieldTooSmallForNonce {
                field,
                len: input.len(),
            });
        };
        key.decrypt(&Array(*nonce), ciphertext)
            .map_err(|aead::Error| ProfileDecodeError::ProfileV1FieldFailedDecryption { field })
    }

    /// `padded_length_buckets` must be sorted in ascending order
    pub(super) fn padded_encrypt_string(
        key: &Aes256Gcm,
        rng: &mut dyn CryptoRng,
        padded_length_buckets: &[usize],
        input: &str,
    ) -> Vec<u8> {
        let padded_length = padded_length_buckets
            .iter()
            .copied()
            .find(|&padded_length| padded_length >= input.len() + ENCRYPTION_OVERHEAD)
            .unwrap_or(input.len() + ENCRYPTION_OVERHEAD);
        padded_encrypt(key, rng, padded_length, input.as_bytes())
    }

    /// Assumes all trailing zero bytes are padding.
    fn decrypt_string(
        key: &Aes256Gcm,
        field: Field,
        input: &[u8],
    ) -> Result<String, ProfileDecodeError> {
        let mut plaintext = decrypt_keeping_padding(key, field, input)?;
        while let Some(0) = plaintext.last().copied() {
            plaintext.pop();
        }
        String::from_utf8(plaintext)
            .map_err(|_| ProfileDecodeError::ProfileV1FieldInvalidUtf8 { field })
    }

    pub(super) fn encrypt_boolean(
        key: &Aes256Gcm,
        rng: &mut dyn CryptoRng,
        input: bool,
    ) -> Vec<u8> {
        padded_encrypt(key, rng, 1 + ENCRYPTION_OVERHEAD, &[input as u8])
    }

    fn decrypt_boolean(
        key: &Aes256Gcm,
        field: Field,
        input: &[u8],
    ) -> Result<bool, ProfileDecodeError> {
        let raw = decrypt_keeping_padding(key, field, input)?;
        match raw.as_slice() {
            [0] => Ok(false),
            [1] => Ok(true),
            _ => Err(ProfileDecodeError::ProfileV1FieldInvalidBoolean { field }),
        }
    }

    /// Encrypt and pad a value, prepending a 4-byte LE length
    ///
    /// Note that `padded_length` must take the extra 4-byte length into account.
    pub(super) fn encrypt_with_length(
        key: &Aes256Gcm,
        rng: &mut dyn CryptoRng,
        padded_length: usize,
        input: &[u8],
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + input.len());
        buf.extend_from_slice(
            &u32::try_from(input.len())
                .expect("input.len() shouldn't exceed a u32")
                .to_le_bytes(),
        );
        buf.extend_from_slice(input);
        padded_encrypt(key, rng, padded_length, &buf)
    }

    fn decrypt_with_length(
        key: &Aes256Gcm,
        field: Field,
        input: &[u8],
    ) -> Result<Vec<u8>, ProfileDecodeError> {
        let raw = decrypt_keeping_padding(key, field, input)?;
        let Some((len, raw)) = raw.split_first_chunk::<4>() else {
            return Err(ProfileDecodeError::ProfileV1FieldTooShortToIncludeLength { field });
        };
        let len = u32::from_le_bytes(*len);
        let len = usize::try_from(len).expect("u32 -> usize shouldn't fail");
        let Some(body) = raw.get(0..len) else {
            return Err(ProfileDecodeError::ProfileV1FieldTooShortForLength {
                field,
                claimed: len,
                len: raw.len(),
            });
        };
        Ok(body.to_vec())
    }
}

pub(super) fn build_set_profile_request(
    rng: &mut dyn CryptoRng,
    aci: Aci,
    profile_key: &ProfileKey,
    profile: Profile,
    expected_current_data_hash: Option<ProfileDataHash>,
    expected_current_profile_key_version: Option<&ProfileKeyVersion>,
) -> (SetProfileRequest, ProfileDataHash) {
    let new_profile_key_version = profile_key.get_profile_key_version(aci);
    let key = Aes256Gcm::new(&Array(profile_key.bytes));
    let Profile {
        given_name,
        family_name,
        about,
        about_emoji,
        avatar,
        phone_number_sharing,
        payment_address,
        badge_ids,
    } = profile;
    let plaintext = PlaintextProfileData {
        given_name,
        family_name,
        about,
        about_emoji,
        avatar_url: avatar.map(|url| url.into()).unwrap_or_default(),
        phone_number_sharing,
    };
    let data = plaintext.encode_to_vec();
    let data = v2::encrypt_profile_data(&key, rng, data);
    let data_hash = sha2::Sha256::digest(&data);
    let request = SetProfileRequest {
        version: new_profile_key_version.as_ref().to_vec(),
        data,
        expected_current_data_hash: expected_current_data_hash
            .map(|x| x.to_vec())
            .unwrap_or_default(),
        expected_current_version: expected_current_profile_key_version
            .map(|x| x.as_ref().to_vec())
            .unwrap_or_default(),
        payment_address: payment_address
            .map(|payment_address| {
                // We use the same payment address for profiles v1 and profiles v2, so we always
                // use profiles v1 encryption for backwards compatibility.
                v1::encrypt_payment_address(&key, rng, &payment_address)
            })
            .unwrap_or_default(),
        badge_ids,
        commitment: zkgroup::serialize(&profile_key.get_commitment(aci)),
        v1_request: Some(SetProfileV1Request {
            name: {
                let mut name_str = plaintext.given_name;
                if !plaintext.family_name.is_empty() {
                    name_str.push('\0');
                    name_str.push_str(&plaintext.family_name);
                }
                v1::padded_encrypt_string(&key, rng, V1_NAME_ALLOWED_SIZES, &name_str)
            },
            avatar_change: if plaintext.avatar_url.is_empty() {
                AvatarChange::Clear
            } else {
                AvatarChange::Unchanged
            }
            .into(),
            about_emoji: v1::padded_encrypt_string(
                &key,
                rng,
                V1_ABOUT_EMOJI_ALLOWED_SIZES,
                &plaintext.about_emoji,
            ),
            about: v1::padded_encrypt_string(&key, rng, V1_ABOUT_ALLOWED_SIZES, &plaintext.about),
            phone_number_sharing: v1::encrypt_boolean(&key, rng, phone_number_sharing),
        }),
    };
    (request, data_hash.0)
}

pub(super) mod test_cases {
    use libsignal_net_grpc::proto::chat::profile::{
        GetProfileRequest, GetProfileResponse, SetProfileResponse, SetProfileResult,
    };
    use rand::SeedableRng;
    use strum::VariantArray;

    use super::*;
    use crate::grpc::GrpcTestCase;
    use crate::grpc::profiles::{AuthProfileGetError, ProfileFieldWithMaxLength, SetProfileError};

    /// The requirements from profile.proto
    fn validate_protobuf_set_profile_request(request: &SetProfileRequest) {
        assert_eq!(request.version.len(), PROFILE_VERSION_ALLOWED_SIZE);
        assert!(!request.data.is_empty());
        assert!(request.data.len() <= PROFILE_DATA_MAX_SIZE);
        assert!(
            EXPECTED_CURRENT_DATA_HASH_ALLOWED_SIZES
                .contains(&request.expected_current_data_hash.len())
        );
        assert!(
            EXPECTED_CURRENT_VERSION_ALLOWED_SIZES
                .contains(&request.expected_current_version.len())
        );
        assert!(PAYMENT_ADDRESS_ALLOWED_SIZES.contains(&request.payment_address.len()));
        assert!(COMMITMENT_ALLOWED_SIZES.contains(&request.commitment.len()));
        let v1_request = request.v1_request.as_ref().expect("missing v1 request");
        assert!(
            V1_NAME_ALLOWED_SIZES.contains(&v1_request.name.len()),
            "{} isn't an allowed name size",
            v1_request.name.len()
        );
        assert!(V1_ABOUT_EMOJI_ALLOWED_SIZES.contains(&v1_request.about_emoji.len()));
        assert!(V1_ABOUT_ALLOWED_SIZES.contains(&v1_request.about.len()));
        assert!(
            V1_PHONE_NUMBER_SHARING_ALLOWED_SIZES.contains(&v1_request.phone_number_sharing.len())
        );
    }

    pub(crate) fn seeded_rng(seed: u64) -> impl CryptoRng {
        // This should match the determinstic Rng from bridge/shared/types/src/crypto.rs
        rand_chacha::ChaCha20Rng::seed_from_u64(seed)
    }

    fn identity_key_from_seed(seed: u64) -> IdentityKey {
        // The constant is just a random number
        IdentityKey::new(
            libsignal_core::curve::KeyPair::generate(&mut seeded_rng(
                seed.wrapping_mul(0x7bfde3d372fa524a),
            ))
            .public_key,
        )
    }

    #[derive(Clone)]
    pub struct SetProfileArgs {
        pub rng_seed: u64,
        pub aci: Aci,
        pub profile_key: ProfileKey,
        pub profile: Profile,
        pub expected_current_data_hash: Option<ProfileDataHash>,
        pub expected_current_profile_key_version: Option<ProfileKeyVersion>,
    }
    pub enum SetProfileOut {
        Success(ProfileDataHash),
        Failure(SetProfileError),
    }
    pub type SetProfileTestCases =
        Vec<GrpcTestCase<SetProfileArgs, SetProfileRequest, SetProfileResponse, SetProfileOut>>;
    pub struct GetProfileArgs {
        pub aci: Aci,
        pub profile_key: ProfileKey,
        pub etag: Option<ProfileEtag>,
    }
    #[allow(clippy::large_enum_variant)] // This is just for testing
    pub enum GetProfileOut {
        Success(Option<FetchedProfile>),
        Failure(AuthProfileGetError),
    }
    pub type GetProfileTestCases =
        Vec<GrpcTestCase<GetProfileArgs, GetProfileRequest, GetProfileResponse, GetProfileOut>>;

    #[derive(Clone)]
    struct ProfileEncryptionRoundtripTest {
        seed: u64,
        aci: Aci,
        profile_key: ProfileKey,
        correct_fetched_profile: FetchedProfile,
        set_profile_request: SetProfileRequest,
        v1_result: ProfilesV1GrpcResult,
        v2_result: ProfilesV2GrpcResult,
        profile_hash: ProfileDataHash,
    }
    impl ProfileEncryptionRoundtripTest {
        /// Avatar must be a CDN0 url (so long as we support profiles v1).
        /// Input `etag` and `v2_data_hash` are ignored
        fn new(
            seed: u64,
            aci: Aci,
            profile_key: ProfileKey,
            mut correct_fetched_profile: FetchedProfile,
        ) -> Self {
            let FetchedProfile {
                profile,
                etag: _,
                v2_data_hash: _,
                identity_key,
                unidentified_access_key_fingerprint,
                unrestricted_unidentified_access,
            } = &correct_fetched_profile;
            if let Some(avatar_url) = profile.avatar.as_ref() {
                // So long as we're supporting profiles v1, avatars must live in CDN0
                assert!(
                    avatar_url.as_ref().starts_with(CdnUrl::CDN0),
                    "{avatar_url:?}"
                );
            }
            let mut rng = seeded_rng(seed);
            let (req, profile_hash) =
                build_set_profile_request(&mut rng, aci, &profile_key, profile.clone(), None, None);
            let account_info = AccountInfo {
                identity_key: identity_key.serialize().to_vec(),
                unidentified_access_key_fingerprint: unidentified_access_key_fingerprint
                    .map(|x| x.to_vec())
                    .unwrap_or_default(),
                unrestricted_unidentified_access: *unrestricted_unidentified_access,
                badge_ids: profile.badge_ids.clone(),
            };
            let mut v2_result = ProfilesV2GrpcResult {
                data: req.data.clone(),
                payment_address: req.payment_address.clone(),
                account_info: Some(account_info.clone()),
                etag: Default::default(),
            };
            let etag = v2::compute_profile_etag(&v2_result);
            v2_result.etag = etag.to_vec();
            let v1_req = req.v1_request.as_ref().expect("v1 request");
            let v1_result = ProfilesV1GrpcResult {
                name: v1_req.name.clone(),
                about: v1_req.about.clone(),
                about_emoji: v1_req.about_emoji.clone(),
                avatar: profile
                    .avatar
                    .as_ref()
                    .map(|avatar| {
                        avatar
                            .as_ref()
                            .strip_prefix(CdnUrl::CDN0)
                            .expect("we validated that the avatar is on CDN0")
                            .to_string()
                    })
                    .unwrap_or_default(),
                phone_number_sharing: v1_req.phone_number_sharing.clone(),
                payment_address: req.payment_address.clone(),
                account_info: Some(account_info.clone()),
            };
            validate_protobuf_set_profile_request(&req);
            correct_fetched_profile.etag = Some(etag);
            correct_fetched_profile.v2_data_hash = Some(sha2::Sha256::digest(&req.data).0);
            Self {
                seed,
                aci,
                profile_key,
                correct_fetched_profile,
                set_profile_request: req,
                v1_result,
                v2_result,
                profile_hash,
            }
        }
    }

    pub fn get_profile_test_cases() -> GetProfileTestCases {
        let method = "/org.signal.chat.profile.Profile/GetProfile";
        let mut cases = GetProfileTestCases::new();
        for (i, mut test) in roundtrip_test_cases().into_iter().enumerate() {
            let version = test
                .profile_key
                .get_profile_key_version(test.aci)
                .bytes
                .to_vec();
            cases.push(GrpcTestCase {
                name: format!("Roundtrip Test case #{i}, v2 response"),
                method: method.into(),
                request: GetProfileArgs {
                    aci: test.aci,
                    profile_key: test.profile_key,
                    etag: None,
                },
                request_grpc: GetProfileRequest {
                    account_identifier: Some(test.aci.into()),
                    version: version.clone(),
                    etag: Vec::new(),
                },
                response_grpc: GetProfileResponse {
                    response: Some(GetProfileResponseEnum::Profile(test.v2_result.clone())),
                },
                response: GetProfileOut::Success(Some(test.correct_fetched_profile.clone())),
            });
            cases.push(GrpcTestCase {
                name: format!("Roundtrip Test case #{i}, v2 response, etag mismatch"),
                method: method.into(),
                request: GetProfileArgs {
                    aci: test.aci,
                    profile_key: test.profile_key,
                    etag: None,
                },
                request_grpc: GetProfileRequest {
                    account_identifier: Some(test.aci.into()),
                    version: version.clone(),
                    etag: Vec::new(),
                },
                response_grpc: GetProfileResponse {
                    response: Some(GetProfileResponseEnum::Profile(ProfilesV2GrpcResult {
                        etag: test
                            .v2_result
                            .etag
                            .iter()
                            .copied()
                            .map(|byte| !byte)
                            .collect(),
                        ..test.v2_result.clone()
                    })),
                },
                response: GetProfileOut::Success(Some(FetchedProfile {
                    etag: None,
                    ..test.correct_fetched_profile.clone()
                })),
            }); // For the v1 test, clear out the v2-specific fields.
            test.correct_fetched_profile.etag = None;
            test.correct_fetched_profile.v2_data_hash = None;
            cases.push(GrpcTestCase {
                name: format!("Roundtrip Test case #{i}, v1 response"),
                method: method.into(),
                request: GetProfileArgs {
                    aci: test.aci,
                    profile_key: test.profile_key,
                    etag: None,
                },
                request_grpc: GetProfileRequest {
                    account_identifier: Some(test.aci.into()),
                    version: version.clone(),
                    etag: Vec::new(),
                },
                response_grpc: GetProfileResponse {
                    response: Some(GetProfileResponseEnum::LegacyProfile(
                        test.v1_result.clone(),
                    )),
                },
                response: GetProfileOut::Success(Some(test.correct_fetched_profile.clone())),
            });
            test.v1_result
                .name
                .iter_mut()
                .for_each(|byte| *byte = !*byte);
            cases.push(GrpcTestCase {
                name: format!("Roundtrip Test case #{i}, v1 response, invalid mac"),
                method: method.into(),
                request: GetProfileArgs {
                    aci: test.aci,
                    profile_key: test.profile_key,
                    etag: None,
                },
                request_grpc: GetProfileRequest {
                    account_identifier: Some(test.aci.into()),
                    version,
                    etag: Vec::new(),
                },
                response_grpc: GetProfileResponse {
                    response: Some(GetProfileResponseEnum::LegacyProfile(test.v1_result)),
                },
                response: GetProfileOut::Failure(AuthProfileGetError::ProfileDecodeError {
                    log_safe: ProfileDecodeError::ProfileV1FieldFailedDecryption {
                        field: v1::Field::Name,
                    }
                    .to_string(),
                }),
            });
        }
        let aci = Aci::from_uuid_bytes([0x1; 16]);
        let profile_key = ProfileKey { bytes: [0x2; 32] };
        let etag = [0x4; 10];
        let version = profile_key.get_profile_key_version(aci).bytes.to_vec();
        cases.push(GrpcTestCase {
            name: "Etag match".into(),
            method: method.into(),
            request: GetProfileArgs {
                aci,
                profile_key,
                etag: Some(etag),
            },
            request_grpc: GetProfileRequest {
                account_identifier: Some(aci.into()),
                version: version.clone(),
                etag: etag.to_vec(),
            },
            response_grpc: GetProfileResponse {
                response: Some(GetProfileResponseEnum::EtagMatched(true)),
            },
            response: GetProfileOut::Success(None),
        });
        cases.push(GrpcTestCase {
            name: "Profile not found".into(),
            method: method.into(),
            request: GetProfileArgs {
                aci,
                profile_key,
                etag: Some(etag),
            },
            request_grpc: GetProfileRequest {
                account_identifier: Some(aci.into()),
                version: version.clone(),
                etag: etag.to_vec(),
            },
            response_grpc: GetProfileResponse {
                response: Some(GetProfileResponseEnum::NotFound(Default::default())),
            },
            response: GetProfileOut::Failure(AuthProfileGetError::ProfileNotFound),
        });
        cases
    }
    pub fn set_profile_test_cases() -> SetProfileTestCases {
        let method = "/org.signal.chat.profile.Profile/SetProfile";
        let mut cases = SetProfileTestCases::new();
        for (i, mut test) in roundtrip_test_cases().into_iter().enumerate() {
            cases.push(GrpcTestCase {
                name: format!("Successful set #{i}, no hashes"),
                method: method.into(),
                request: SetProfileArgs {
                    rng_seed: test.seed,
                    aci: test.aci,
                    profile_key: test.profile_key,
                    profile: test.correct_fetched_profile.profile.clone(),
                    expected_current_data_hash: None,
                    expected_current_profile_key_version: None,
                },
                request_grpc: test.set_profile_request.clone(),
                response_grpc: SetProfileResponse {
                    response: Some(SetProfileResponseEnum::Result(SetProfileResult {
                        v1_avatar_upload_form: None,
                    })),
                },
                response: SetProfileOut::Success(test.profile_hash),
            });
            let expected_current_data_hash = [0xa; 32];
            let expected_current_profile_key_version = ProfileKeyVersion { bytes: [0xb; 32] };
            test.set_profile_request.expected_current_data_hash =
                expected_current_data_hash.to_vec();
            test.set_profile_request.expected_current_version =
                expected_current_profile_key_version.bytes.to_vec();
            cases.push(GrpcTestCase {
                name: format!("Successful set #{i}, with hashes"),
                method: method.into(),
                request: SetProfileArgs {
                    rng_seed: test.seed,
                    aci: test.aci,
                    profile_key: test.profile_key,
                    profile: test.correct_fetched_profile.profile.clone(),
                    expected_current_data_hash: Some(expected_current_data_hash),
                    expected_current_profile_key_version: Some(
                        expected_current_profile_key_version,
                    ),
                },
                request_grpc: test.set_profile_request,
                response_grpc: SetProfileResponse {
                    response: Some(SetProfileResponseEnum::Result(SetProfileResult {
                        v1_avatar_upload_form: None,
                    })),
                },
                response: SetProfileOut::Success(test.profile_hash),
            });
        }
        let aci = Aci::from_uuid_bytes([0x4; 16]);
        let profile_key = ProfileKey { bytes: [0x73; 32] };
        cases.push(GrpcTestCase {
            name: "given name empty error".into(),
            method: method.into(),
            request: SetProfileArgs {
                rng_seed: 12,
                aci,
                profile_key,
                profile: Profile::default(),
                expected_current_data_hash: None,
                expected_current_profile_key_version: None,
            },
            request_grpc: Default::default(),
            response_grpc: Default::default(),
            response: SetProfileOut::Failure(SetProfileError::InvalidProfile(
                ProfileValidationError::GivenNameEmpty,
            )),
        });
        for &field in ProfileFieldWithMaxLength::VARIANTS {
            let mut profile = Profile {
                given_name: "x".into(),
                ..Default::default()
            };
            let len = field.max_length() + 1;
            let mut body = "L".repeat(len);
            match field {
                ProfileFieldWithMaxLength::GivenName => profile.given_name = body,
                ProfileFieldWithMaxLength::FamilyName => profile.family_name = body,
                ProfileFieldWithMaxLength::About => profile.about = body,
                ProfileFieldWithMaxLength::AboutEmoji => profile.about_emoji = body,
                ProfileFieldWithMaxLength::Avatar => {
                    body = format!("{}{body}", CdnUrl::CDN0);
                    body.truncate(len);
                    profile.avatar = Some(CdnUrl::try_from(body).expect("valid"))
                }
                ProfileFieldWithMaxLength::PaymentAddress => {
                    profile.payment_address = Some(body.into_bytes())
                }
            }
            cases.push(GrpcTestCase {
                name: format!("profile validation error: field {field:?} too long"),
                method: method.into(),
                request: SetProfileArgs {
                    rng_seed: 721,
                    aci,
                    profile_key,
                    profile,
                    expected_current_data_hash: None,
                    expected_current_profile_key_version: None,
                },
                request_grpc: Default::default(),
                response_grpc: Default::default(),
                response: SetProfileOut::Failure(SetProfileError::InvalidProfile(
                    ProfileValidationError::FieldTooLong {
                        field,
                        len,
                        max_len: field.max_length(),
                    },
                )),
            });
        }
        {
            let mut test = roundtrip_test_cases().into_iter().next().expect("nonempty");
            let expected_current_data_hash = [0xa; 32];
            let expected_current_profile_key_version = ProfileKeyVersion { bytes: [0xb; 32] };
            test.set_profile_request.expected_current_data_hash =
                expected_current_data_hash.to_vec();
            test.set_profile_request.expected_current_version =
                expected_current_profile_key_version.bytes.to_vec();
            let request = SetProfileArgs {
                rng_seed: test.seed,
                aci: test.aci,
                profile_key: test.profile_key,
                profile: test.correct_fetched_profile.profile.clone(),
                expected_current_data_hash: Some(expected_current_data_hash),
                expected_current_profile_key_version: Some(expected_current_profile_key_version),
            };
            cases.push(GrpcTestCase {
                name: "ExpectedDataWriteConflict".into(),
                method: method.into(),
                request: request.clone(),
                request_grpc: test.set_profile_request.clone(),
                response_grpc: SetProfileResponse {
                    response: Some(SetProfileResponseEnum::ExpectedDataWriteConflict(
                        libsignal_net_grpc::proto::chat::errors::FailedPrecondition {
                            description: "".into(),
                        },
                    )),
                },
                response: SetProfileOut::Failure(SetProfileError::ExpectedDataWriteConflict),
            });
            let current_profile_version = ProfileKeyVersion { bytes: [0x6; _] };
            cases.push(GrpcTestCase {
                name: "ExpectedVersionWriteConflict".into(),
                method: method.into(),
                request: request.clone(),
                request_grpc: test.set_profile_request.clone(),
                response_grpc: SetProfileResponse {
                    response: Some(SetProfileResponseEnum::ExpectedVersionWriteConflict(
                        libsignal_net_grpc::proto::chat::profile::ExpectedVersionConflict {
                            current_profile_version: current_profile_version.bytes.to_vec(),
                        },
                    )),
                },
                response: SetProfileOut::Failure(SetProfileError::ExpectedVersionWriteConflict {
                    current_profile_version: Some(current_profile_version),
                }),
            });
            cases.push(GrpcTestCase {
                name: "ExpectedVersionWriteConflict, correct version is none".into(),
                method: method.into(),
                request: request.clone(),
                request_grpc: test.set_profile_request.clone(),
                response_grpc: SetProfileResponse {
                    response: Some(SetProfileResponseEnum::ExpectedVersionWriteConflict(
                        libsignal_net_grpc::proto::chat::profile::ExpectedVersionConflict {
                            current_profile_version: Vec::new(),
                        },
                    )),
                },
                response: SetProfileOut::Failure(SetProfileError::ExpectedVersionWriteConflict {
                    current_profile_version: None,
                }),
            });
            cases.push(GrpcTestCase {
                name: "PaymentsForbiddenInRegion".into(),
                method: method.into(),
                request: request.clone(),
                request_grpc: test.set_profile_request.clone(),
                response_grpc: SetProfileResponse {
                    response: Some(SetProfileResponseEnum::PaymentsForbiddenInRegion(
                        libsignal_net_grpc::proto::chat::profile::PaymentsForbiddenInRegion {},
                    )),
                },
                response: SetProfileOut::Failure(SetProfileError::PaymentsForbiddenInRegion),
            });
        }
        for case in &cases {
            // If the test results in invalid profile, then no grpc request is ever actually made.
            if !matches!(
                case.response,
                SetProfileOut::Failure(SetProfileError::InvalidProfile(_))
            ) {
                validate_protobuf_set_profile_request(&case.request_grpc);
            }
        }
        cases
    }

    fn roundtrip_test_cases() -> Vec<ProfileEncryptionRoundtripTest> {
        use crate::grpc::profiles::ProfileFieldWithMaxLength::*;
        vec![
            // All fields at max length
            ProfileEncryptionRoundtripTest::new(
                1,
                Aci::from_uuid_bytes([2; 16]),
                ProfileKey { bytes: [3; 32] },
                FetchedProfile {
                    profile: Profile {
                        given_name: "n".repeat(GivenName.max_length()),
                        family_name: "N".repeat(FamilyName.max_length()),
                        about: "a".repeat(About.max_length()),
                        about_emoji: "A".repeat(AboutEmoji.max_length()),
                        avatar: Some(
                            CdnUrl::try_from(format!(
                                "{}{}",
                                CdnUrl::CDN0,
                                "U".repeat(Avatar.max_length() - CdnUrl::CDN0.len())
                            ))
                            .expect("valid url"),
                        ),
                        phone_number_sharing: true,
                        payment_address: Some(vec![b'p'; PaymentAddress.max_length()]),
                        badge_ids: vec![
                            "honor".into(),
                            "shame".into(),
                            "badger".into(),
                            "verisimilitude".into(),
                        ],
                    },
                    etag: None,         // Set by new()
                    v2_data_hash: None, // set by new()
                    identity_key: identity_key_from_seed(5),
                    unidentified_access_key_fingerprint: Some([4; 32]),
                    unrestricted_unidentified_access: true,
                },
            ),
            // Short
            ProfileEncryptionRoundtripTest::new(
                1,
                Aci::from_uuid_bytes([2; 16]),
                ProfileKey { bytes: [3; 32] },
                FetchedProfile {
                    profile: Profile {
                        given_name: "x".into(),
                        family_name: String::new(),
                        about: String::new(),
                        about_emoji: String::new(),
                        avatar: None,
                        phone_number_sharing: false,
                        payment_address: None,
                        badge_ids: Vec::new(),
                    },
                    etag: None,         // Set by new()
                    v2_data_hash: None, // set by new()
                    identity_key: identity_key_from_seed(5),
                    unidentified_access_key_fingerprint: Some([4; 32]),
                    unrestricted_unidentified_access: false,
                },
            ),
        ]
    }

    #[cfg(test)]
    mod tests {
        use base64::prelude::*;

        use super::*;
        use crate::grpc::profiles::InvalidCdnUrl;

        #[test]
        fn successful_roundtrip() {
            for mut test in roundtrip_test_cases() {
                assert_eq!(
                    v2::decrypt_profile(&test.profile_key, test.v2_result.clone())
                        .expect("success"),
                    test.correct_fetched_profile
                );
                // Clear out the v2-specific fields for the v1 test
                test.correct_fetched_profile.etag = None;
                test.correct_fetched_profile.v2_data_hash = None;
                assert_eq!(
                    v1::decrypt_profile(&test.profile_key, &test.v1_result).expect("success"),
                    test.correct_fetched_profile
                );
            }
        }

        /// Make sure that we can decrypt v1 profile data from android
        #[test]
        fn android_test_vector() {
            fn b64(x: &str) -> Vec<u8> {
                BASE64_STANDARD.decode(x).expect("valid base64")
            }
            let profile_key = ProfileKey { bytes: [b'x'; _] };
            let _aci = Aci::parse_from_service_id_string("e1d2aa14-dba6-4fbb-8ad2-48a9dfff9bb7")
                .expect("valid id");
            let test_vector = ProfilesV1GrpcResult {
                name: b64(
                    "2ju1ucPeoYjCi2dS3LNgiBtVWDDUNpYecpMSFzutCYG0NRulOR03pRRIJV/bEHg2Id/EmDPn5AzDt\
                    j3TwkyqKc7PybaGtWf0Cc7rEIG7S93D",
                ),
                about: b64(
                    "ZnqlcqecDXuebipj80dmVZA/byNiJocUCtyeYaidmEwue9/HDa7iQzKw+YR0A9xM1XFYSkKhcicRG\
                    FlMDDfcDEQnQ3H+mfzYnmN6i5zYyQJtwXWul5m1IuuNvTiQ5U5BwbkdcyVgEKcbyETwrdQUFPbkpIy\
                    jgarf0ykr42ijJCRs7bauV8WWUwYvv+DbtWK9xQ1acJBWoZ80JEvg",
                ),
                about_emoji: b64(
                    "rdtKzEEFKMLpJAxXj/6MhRdyPLwVUy3lsMZVhxW4nF0oAOIF4h42ZdVl7ikINEuUhZIzO5w19lCEL\
                    R40",
                ),
                avatar: String::new(),
                phone_number_sharing: b64("NWQoEO2KjN7Etux9ZaiUWZ8ZXP11Bsej93BC204="),
                payment_address: b64(
                    "WYbTOrzjp13MrBDuTJOx3cPgfNe7wGoDVkLzR2u6t1l8T3AUioAhlt9MtKK/meDPc3oVOiP+6YyuZ\
                    ADNp5xwGAt/0d+Y3gz+BPyBBCAyxRrjUVQ+Pfy3kySE8Ty+par7t9NW1Nd98TOlDPVlzQcCenNoaab\
                    3fsCx/IjHE4Scxq2l4qc7cIOucjBV2/z4XOw1QDhW/+2HbtgOU8aiHdfYJ55ux3EUWmFgnTsycH/RW\
                    FD8qzZLfor3lJe6eVulUtTXS4rCK7GJIS9Lsmh7XLU9KxQ82QfDuSqcf8JvEr9RK0tbFmppu1tPIZ6\
                    zbA047ctBYybys1ulSnPZiukl+3xs+NqMn+4ruPG+6CQl6N1nx73wR9tYeaT884Exj2uJqQSXm9XTr\
                    BgaUL9SBWwz4kK/sz3EyUnw5LLVPnqpT7XE+3Jp7QmPmGb/ojwduNWF0xQMjJlGxnjgwZr3VvHgpW6\
                    CIJ7I3oIVQ4NfPmKKBb+yFLXpG03cp5fpObjO0RxU2MhwuammYJeBvGR37BmdpkJgeNnypAwvKJXZV\
                    hJxIko9EwHdqv41/UDgE4z7zfuvYKLegxXPheaPn+qolfvMgDca9LWNwKQT8IbQGIPsnV5ssYUYXpz\
                    cT/O02yTuLnZWBf3nq+XNF1C53qfSPDzS97InlsHvWR9/oEJsOigzB04aMcYaZIQjjuSJkW7PLjDrV\
                    rNlUxxFh0/tj79YcL2KELcmWyo1RpPAuFKcL8Fo8by3/u+EkrOQmyjJ5zV+Mi0BGKxiFnaD6pdf",
                ),
                account_info: Some(AccountInfo {
                    identity_key: identity_key_from_seed(73).serialize().into_vec(),
                    unidentified_access_key_fingerprint: vec![64; 32],
                    unrestricted_unidentified_access: false,
                    badge_ids: Vec::new(),
                }),
            };
            assert_eq!(
                v1::decrypt_profile(&profile_key, &test_vector)
                    .expect("Decodes successfully")
                    .profile,
                Profile {
                    given_name: "Name".into(),
                    family_name: "Family".into(),
                    about: "About".into(),
                    about_emoji: "X".into(),
                    avatar: None,
                    phone_number_sharing: true,
                    payment_address: Some(vec![0xff; 15]),
                    badge_ids: Vec::new(),
                }
            );
        }

        #[test]
        fn profile_v2_test_vector() {
            // NOTE: don't change this test vector unless you have a good reason! We use this test
            // vector to ensure that we can continue to decrypt/decode v2 profiles encrypted with older
            // versions of this code.
            let identity_key = identity_key_from_seed(74293);
            let unidentified_access_key_fingerprint = [0xd; 32];
            let badge_ids = Vec::new();
            let profile_key = ProfileKey { bytes: [0x23; _] };
            let test_vector: ProfilesV2GrpcResult = ProfilesV2GrpcResult {
                data: BASE64_STANDARD.decode(
                    "hcQ0RCoIlqP5a0y16rDNjLjnRAZPAgwhD6c/SIQugJqTrolglyklKP81tBJt9bvcNnm/njzZO/Bxa\
                    3tehFZ/xBGRzL5NoYNieOq2Py+lF5iultIBE9itPSko/tWMkwc6vC8jz7aXBSibJ/t0S2yc2hsv38N\
                    /IYd6RReaFk+sZSGpsqPy1j2l8NcMt2/mHt4TMwHPwtHpRO6MVriyHVT+19939J6L9CoZ1ex5ADTsx\
                    KuIMi+5RZIMkoPZ7U+jNudLWT7M9xAYKkvrLiEOY9GmxEuG8xDONvCdvhDAPJuK3MqCjMB739vTekP\
                    y6bMqtByCyuJAVp2pEoo0n8kAkBZxDRy7+YrRv5E2hAHOr1y+bFY44veT7gchG8XSgg=="
                ).expect("valid"),
                payment_address: BASE64_STANDARD.decode(
                    "VzaW2lA3ODh5R9wj7i38lDEBpPOo+cJqnAlnyIRPQnPndkhYbRiPUDS9FatBSsyKTW//JNGDH1vYy\
                    cUkLGsXkGi3WQ17XBtYJbYoy+YsBqUPPnIvUUR3ePGPTJ3EHNYdbpWyQ6LtBbP0H7UuyTRhqtV3oB3\
                    m1sO9kYe1dYd8YCRSftvpMQSZ2+34V50tN+C1VvLavEAN4OUBwvN3FhscbNJ97S4n2emQ4gRKkTwCO\
                    nWYYnlHJJB8pf0IRh2fAO1JCHjqQl2Pwq6tsPjkgfae91PUM1Au3ldOXjBSkwrf+HjeY6RUNvfsTDw\
                    +MdW9qM2RGUkn5y2mnN2WHoMh5FjuqPLorXj9sHO6Ye1Krb1hbO9zjFz5HeDGqXw8f/R0dAxv4Ohyj\
                    k0D0M0ts9CahWmgrrnOB6QjgloLPNmTfUMMiMmRgvpyzZSQOQyUaxYKY0lAvN85HW0N0w2Yvjjjm5/\
                    1PEHIxL1ygjIUcNoCZuFHL25u1CZ0MX9oXvnl/VyFJeXTu154LDs09DGhUYxtmHM7lxHgLr5jMMl33\
                    HQDrTEVZnq6N0X3kkDnvgScjGqAVaAP1vD4CDdUoRjyLj7O88lBuzLwJToSQC9g6S7xi/H8Yk0odEt\
                    fgDNC8802Y6OnT13LsOdV/lds0s+GZzi5uz2i5sEZcCy8mKlR0oOLr8Psi7pW2ai16W+E+iMwvffrI\
                    +jQBqKmuiyr5Syt8Pvx3OwWzjeOh46y3PlQ6dLpHM90ws63IIDmlJNtoJxzX+/9l9EbMmMA0/gi"
                ).expect("valid"),
                account_info: Some(AccountInfo {
                    identity_key: identity_key.serialize().to_vec(),
                    unidentified_access_key_fingerprint: unidentified_access_key_fingerprint
                        .to_vec(),
                    unrestricted_unidentified_access: false,
                    badge_ids: badge_ids.clone(),
                }),
                etag: Vec::new(),
            };
            let profile = Profile {
                given_name: "Fnu".into(),
                family_name: "Lnu".into(),
                about: "A bout".into(),
                about_emoji: "Y".into(),
                avatar: Some(CdnUrl(format!("{}abcd", CdnUrl::CDN0))),
                phone_number_sharing: true,
                payment_address: Some(vec![0xec; 128]),
                badge_ids,
            };
            let true_profile = FetchedProfile {
                profile,
                etag: None,
                v2_data_hash: Some(sha2::Sha256::digest(&test_vector.data).0),
                identity_key,
                unidentified_access_key_fingerprint: Some(unidentified_access_key_fingerprint),
                unrestricted_unidentified_access: false,
            };
            assert_eq!(
                true_profile,
                v2::decrypt_profile(&profile_key, test_vector).expect("can decrypt")
            );
        }

        fn a_roundtrip_test() -> ProfileEncryptionRoundtripTest {
            let mut out = ProfileEncryptionRoundtripTest::new(
                1237,
                Aci::from_uuid_bytes([0x8; _]),
                ProfileKey { bytes: [0x9; _] },
                FetchedProfile {
                    profile: Profile {
                        given_name: "a name".into(),
                        family_name: "family name".into(),
                        about: "A bout".into(),
                        about_emoji: "X".into(),
                        avatar: Some(
                            CdnUrl::try_from(format!("{}abc", CdnUrl::CDN0)).expect("valid url"),
                        ),
                        phone_number_sharing: true,
                        payment_address: Some(vec![4]),
                        badge_ids: Vec::new(),
                    },
                    etag: None,         // Set by new()
                    v2_data_hash: None, // set by new()
                    identity_key: identity_key_from_seed(8427),
                    unidentified_access_key_fingerprint: None,
                    unrestricted_unidentified_access: false,
                },
            );
            out.v2_result.etag.clear();
            out
        }

        #[test]
        fn test_profile_decode_invalid_profile() {
            // NOTE: individual profile decode errors are tested via GrpcTestCase above (since
            // clients can dispatch on them, when set_profile() is called). This test only aims to
            // ensure that the profile validation logic is called.
            let mut test = ProfileEncryptionRoundtripTest::new(
                1237,
                Aci::from_uuid_bytes([0x8; _]),
                ProfileKey { bytes: [0x9; _] },
                FetchedProfile {
                    profile: Profile::default(),
                    etag: None,         // Set by new()
                    v2_data_hash: None, // set by new()
                    identity_key: identity_key_from_seed(8427),
                    unidentified_access_key_fingerprint: None,
                    unrestricted_unidentified_access: false,
                },
            );
            test.v2_result.etag.clear();
            assert_eq!(
                v1::decrypt_profile(&test.profile_key, &test.v1_result).expect_err("failure"),
                Error::ProfileDecodeError(ProfileDecodeError::IncomingProfileValidationFailed(
                    ProfileValidationError::GivenNameEmpty
                ))
            );
            assert_eq!(
                v2::decrypt_profile(&test.profile_key, test.v2_result).expect_err("failure"),
                Error::ProfileDecodeError(ProfileDecodeError::IncomingProfileValidationFailed(
                    ProfileValidationError::GivenNameEmpty
                ))
            );
        }

        #[test]
        fn test_profile_decode_invalid_protobuf() {
            let mut test = a_roundtrip_test();
            test.v2_result.data = v2::encrypt_profile_data(
                &Aes256Gcm::new(&Array(test.profile_key.bytes)),
                &mut seeded_rng(3141),
                vec![0xff; 13],
            );
            assert_eq!(
                v2::decrypt_profile(&test.profile_key, test.v2_result).expect_err("failure"),
                Error::ProfileDecodeError(ProfileDecodeError::ProfileV2InvalidProtobuf)
            );
        }

        #[test]
        fn test_profile_decode_invalid_cdn_url() {
            // We only test v2 profiles, since v1 profiles can't be invalid (by construction)
            let mut test = a_roundtrip_test();
            test.v2_result.data = v2::encrypt_profile_data(
                &Aes256Gcm::new(&Array(test.profile_key.bytes)),
                &mut seeded_rng(3141),
                PlaintextProfileData {
                    given_name: "non-empty".into(),
                    avatar_url: "https://example.com/not-a-signal-cdn.png".into(),
                    ..Default::default()
                }
                .encode_to_vec(),
            );
            assert_eq!(
                v2::decrypt_profile(&test.profile_key, test.v2_result).expect_err("failure"),
                Error::ProfileDecodeError(ProfileDecodeError::InvalidAvatarUrl(InvalidCdnUrl))
            );
        }

        #[test]
        fn test_profile_decode_empty_encrypted_profile() {
            let mut test = a_roundtrip_test();
            let key = Aes256Gcm::new(&Array(test.profile_key.bytes));
            test.v2_result.data =
                v2::unpadded_encrypt_profile_data(&key, &mut seeded_rng(74423), vec![]);
            assert_eq!(
                v2::decrypt_profile(&test.profile_key, test.v2_result).expect_err("failure"),
                Error::ProfileDecodeError(
                    ProfileDecodeError::ProfileV2DataEmptyProfileBufferCannotContainPadding
                )
            );
        }

        #[test]
        fn test_profile_decode_zero_padded() {
            let mut test = a_roundtrip_test();
            let key = Aes256Gcm::new(&Array(test.profile_key.bytes));
            test.v2_result.data =
                v2::unpadded_encrypt_profile_data(&key, &mut seeded_rng(74423), vec![1, 2, 3, 0]);
            assert_eq!(
                v2::decrypt_profile(&test.profile_key, test.v2_result).expect_err("failure"),
                Error::ProfileDecodeError(ProfileDecodeError::ProfileV2BufferZeroPadding)
            );
        }

        #[test]
        fn test_profile_decode_padding_too_big() {
            let mut test = a_roundtrip_test();
            let key = Aes256Gcm::new(&Array(test.profile_key.bytes));
            test.v2_result.data =
                v2::unpadded_encrypt_profile_data(&key, &mut seeded_rng(74423), vec![1, 2, 3, 255]);
            assert_eq!(
                v2::decrypt_profile(&test.profile_key, test.v2_result).expect_err("failure"),
                Error::ProfileDecodeError(
                    ProfileDecodeError::ProfileV2DataTooSmallForClaimedPadding {
                        buffer_size: 4,
                        padding_size: 255,
                    }
                )
            );
        }

        #[test]
        fn test_profile_decode_invalid_padding_byte() {
            let mut test = a_roundtrip_test();
            let key = Aes256Gcm::new(&Array(test.profile_key.bytes));
            test.v2_result.data =
                v2::unpadded_encrypt_profile_data(&key, &mut seeded_rng(74423), vec![1, 2, 255, 2]);
            assert_eq!(
                v2::decrypt_profile(&test.profile_key, test.v2_result).expect_err("failure"),
                Error::ProfileDecodeError(ProfileDecodeError::ProfileV2DataInvalidPaddingByte {
                    padding_size: 2,
                })
            );
        }

        #[test]
        fn test_profile_decode_too_small_for_nonce() {
            let mut test = a_roundtrip_test();
            test.v2_result.data = vec![1, 2, 3];
            assert_eq!(
                v2::decrypt_profile(&test.profile_key, test.v2_result).expect_err("failure"),
                Error::ProfileDecodeError(ProfileDecodeError::ProfileV2DataTooSmallForNonce {
                    len: 3
                })
            );
        }

        #[test]
        fn test_profile_decode_failed_decryption() {
            let mut test = a_roundtrip_test();
            test.v2_result
                .data
                .iter_mut()
                .for_each(|byte| *byte = !*byte);
            assert_eq!(
                v2::decrypt_profile(&test.profile_key, test.v2_result).expect_err("failure"),
                Error::ProfileDecodeError(ProfileDecodeError::ProfileV2DataFailedDecryption)
            );
        }

        impl v1::Field {
            const ALL: &[v1::Field] = &[
                v1::Field::PhoneNumberSharing,
                v1::Field::Name,
                v1::Field::About,
                v1::Field::AboutEmoji,
                v1::Field::PaymentAddress,
            ];
            fn get_mut<'a>(
                &self,
                ProfilesV1GrpcResult {
                    name,
                    about,
                    about_emoji,
                    avatar: _,
                    phone_number_sharing,
                    payment_address,
                    account_info: _,
                }: &'a mut ProfilesV1GrpcResult,
            ) -> &'a mut Vec<u8> {
                match self {
                    v1::Field::PhoneNumberSharing => phone_number_sharing,
                    v1::Field::Name => name,
                    v1::Field::About => about,
                    v1::Field::AboutEmoji => about_emoji,
                    v1::Field::PaymentAddress => payment_address,
                }
            }
        }

        // NOTE: payment_address is always {en,de}crypted using v1-style crypto, even for v2
        // profiles
        #[test]
        fn test_profile_decode_v1_failed_decryption() {
            for &field in v1::Field::ALL {
                let mut test = a_roundtrip_test();
                field
                    .get_mut(&mut test.v1_result)
                    .iter_mut()
                    .for_each(|byte| *byte = !*byte);
                assert_eq!(
                    v1::decrypt_profile(&test.profile_key, &test.v1_result).expect_err("failure"),
                    Error::ProfileDecodeError(ProfileDecodeError::ProfileV1FieldFailedDecryption {
                        field
                    })
                );
            }
        }

        #[test]
        fn test_profile_decode_v1_invalid_utf8() {
            use v1::Field::*;
            for (field, sizes) in [
                (Name, V1_NAME_ALLOWED_SIZES),
                (About, V1_ABOUT_ALLOWED_SIZES),
                (AboutEmoji, V1_ABOUT_EMOJI_ALLOWED_SIZES),
            ] {
                let mut test = a_roundtrip_test();
                let key = Aes256Gcm::new(&Array(test.profile_key.bytes));
                *field.get_mut(&mut test.v1_result) = v1::padded_encrypt(
                    &key,
                    &mut seeded_rng(7123),
                    *sizes.last().expect("non-empty"),
                    &[255],
                );
                assert_eq!(
                    v1::decrypt_profile(&test.profile_key, &test.v1_result).expect_err("failure"),
                    Error::ProfileDecodeError(ProfileDecodeError::ProfileV1FieldInvalidUtf8 {
                        field
                    })
                );
            }
        }
        #[test]
        fn test_profile_decode_v1_invalid_boolean() {
            let field = v1::Field::PhoneNumberSharing;
            let mut test = a_roundtrip_test();
            let key = Aes256Gcm::new(&Array(test.profile_key.bytes));
            *field.get_mut(&mut test.v1_result) = v1::padded_encrypt(
                &key,
                &mut seeded_rng(7123),
                1 + v1::ENCRYPTION_OVERHEAD,
                &[255],
            );
            assert_eq!(
                v1::decrypt_profile(&test.profile_key, &test.v1_result).expect_err("failure"),
                Error::ProfileDecodeError(ProfileDecodeError::ProfileV1FieldInvalidBoolean {
                    field
                })
            );
        }
        #[test]
        fn test_profile_decode_v1_field_too_short_for_length() {
            let field = v1::Field::PaymentAddress;
            let mut test = a_roundtrip_test();
            let key = Aes256Gcm::new(&Array(test.profile_key.bytes));
            *field.get_mut(&mut test.v1_result) = v1::padded_encrypt(
                &key,
                &mut seeded_rng(7123),
                1 + v1::ENCRYPTION_OVERHEAD,
                &[255],
            );
            assert_eq!(
                v1::decrypt_profile(&test.profile_key, &test.v1_result).expect_err("failure"),
                Error::ProfileDecodeError(
                    ProfileDecodeError::ProfileV1FieldTooShortToIncludeLength { field }
                )
            );
            test.v2_result.payment_address = test.v1_result.payment_address;
            assert_eq!(
                v2::decrypt_profile(&test.profile_key, test.v2_result).expect_err("failure"),
                Error::ProfileDecodeError(
                    ProfileDecodeError::ProfileV1FieldTooShortToIncludeLength { field }
                )
            );
        }
        #[test]
        fn test_profile_decode_v1_field_too_short_for_claimed_length() {
            let field = v1::Field::PaymentAddress;
            let mut test = a_roundtrip_test();
            let key = Aes256Gcm::new(&Array(test.profile_key.bytes));
            *field.get_mut(&mut test.v1_result) = v1::padded_encrypt(
                &key,
                &mut seeded_rng(7123),
                4 + v1::ENCRYPTION_OVERHEAD,
                &1024_u32.to_le_bytes(),
            );
            assert_eq!(
                v1::decrypt_profile(&test.profile_key, &test.v1_result).expect_err("failure"),
                Error::ProfileDecodeError(ProfileDecodeError::ProfileV1FieldTooShortForLength {
                    field,
                    len: 0,
                    claimed: 1024
                })
            );
            test.v2_result.payment_address = test.v1_result.payment_address;
            assert_eq!(
                v2::decrypt_profile(&test.profile_key, test.v2_result).expect_err("failure"),
                Error::ProfileDecodeError(ProfileDecodeError::ProfileV1FieldTooShortForLength {
                    field,
                    len: 0,
                    claimed: 1024
                })
            );
        }
    }
}
