//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::{Debug, Display, Formatter};
use std::ops::{Add, Range, RangeInclusive};
use std::str::FromStr;
use std::sync::LazyLock;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use poksho::args::{PointArgs, ScalarArgs};
use poksho::{PokshoError, Statement};
use rand::Rng;
use sha2::{Digest, Sha512};

use crate::constants::{
    BASE_POINTS, CANDIDATES_PER_RANGE, DISCRIMINATOR_RANGES, MAX_NICKNAME_LENGTH,
};
use crate::error::{ProofVerificationFailure, UsernameError};

static PROOF_STATEMENT: LazyLock<Statement> = LazyLock::new(|| {
    let mut st = Statement::new();
    st.add(
        "username_hash",
        &[
            ("username_sha_scalar", "G1"),
            ("nickname_scalar", "G2"),
            ("discriminator_scalar", "G3"),
        ],
    );
    st
});

#[derive(PartialEq)]
pub struct Username {
    nickname: String,
    discriminator: u64,
    scalars: Vec<Scalar>,
}

impl Display for Username {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{:02}", self.nickname, self.discriminator)
    }
}

impl Debug for Username {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Username")
            .field("nickname", &self.nickname)
            .field("discriminator", &self.discriminator)
            .finish()
    }
}

#[derive(Debug)]
pub struct NicknameLimits(RangeInclusive<usize>);

impl Default for NicknameLimits {
    fn default() -> Self {
        NicknameLimits::new(3, 32)
    }
}

impl NicknameLimits {
    pub fn new(min_len: usize, max_len: usize) -> Self {
        assert!(
            max_len <= MAX_NICKNAME_LENGTH,
            "Long nicknames are not supported. The maximum supported length is {}",
            MAX_NICKNAME_LENGTH
        );
        assert!(
            min_len < max_len,
            "Invalid nickname size limits: {}..{}",
            min_len,
            max_len
        );
        NicknameLimits(min_len..=max_len)
    }

    pub fn validate(&self, n: usize) -> Result<(), UsernameError> {
        if &n < self.0.start() {
            return Err(UsernameError::NicknameTooShort);
        }
        if &n > self.0.end() {
            return Err(UsernameError::NicknameTooLong);
        }
        Ok(())
    }
}

impl Username {
    pub fn new(s: &str) -> Result<Self, UsernameError> {
        let (nickname, discriminator) =
            s.rsplit_once('.').ok_or(UsernameError::MissingSeparator)?;
        Self::from_parts_without_soft_limit(nickname, discriminator)
    }

    pub fn from_parts(
        nickname: &str,
        discriminator: &str,
        limits: NicknameLimits,
    ) -> Result<Self, UsernameError> {
        // This should perform the same set of checks as validate_nickname.
        let result = Self::from_parts_without_soft_limit(nickname, discriminator)?;

        // We've already checked the hard limit. Now check the soft limit.
        assert!(
            nickname.is_ascii(),
            "using the UTF-8 length is only correct when all valid nicknames are ASCII"
        );
        limits.validate(nickname.len())?;

        Ok(result)
    }

    fn from_parts_without_soft_limit(
        nickname: &str,
        discriminator: &str,
    ) -> Result<Self, UsernameError> {
        validate_prefix(nickname)?;
        let discriminator = validate_discriminator(discriminator)?;
        let scalars = make_scalars(&nickname.to_ascii_lowercase(), discriminator)?;
        Ok(Self {
            nickname: nickname.to_string(),
            discriminator,
            scalars,
        })
    }

    pub fn hash(&self) -> [u8; 32] {
        *Self::hash_from_scalars(&self.scalars).compress().as_bytes()
    }

    pub fn proof(&self, randomness: &[u8; 32]) -> Result<Vec<u8>, UsernameError> {
        let hash = Self::hash_from_scalars(&self.scalars);
        let scalar_args = Self::make_scalar_args(&self.scalars);
        let point_args = Self::make_point_args(hash);
        let message = *hash.compress().as_bytes();
        PROOF_STATEMENT
            .prove(&scalar_args, &point_args, &message, randomness)
            .map_err(|e| panic!("Failed to create proof. Cause: PokshoError::{:?}", e))
    }

    pub fn verify_proof(proof: &[u8], hash: [u8; 32]) -> Result<(), ProofVerificationFailure> {
        let hash_point = CompressedRistretto(hash)
            .decompress()
            .ok_or(ProofVerificationFailure)?;
        let point_args = Self::make_point_args(hash_point);
        PROOF_STATEMENT
            .verify_proof(proof, &point_args, &hash)
            .map_err(|e| match e {
                PokshoError::VerificationFailure => ProofVerificationFailure,
                _ => panic!("Unexpected verification error PokshoError::{:?}", e),
            })
    }

    pub fn candidates_from<R: Rng>(
        rng: &mut R,
        nickname: &str,
        limits: NicknameLimits,
    ) -> Result<Vec<String>, UsernameError> {
        validate_nickname(nickname, &limits)?;
        let candidates = random_discriminators(rng, &CANDIDATES_PER_RANGE, &DISCRIMINATOR_RANGES)
            .unwrap()
            .iter()
            .map(|d| Self::format_parts(nickname, d))
            .collect();
        Ok(candidates)
    }

    fn format_parts(nickname: &str, discriminator: impl std::fmt::Display) -> String {
        format!("{nickname}.{discriminator:0>2}")
    }

    fn hash_from_scalars(scalars: &[Scalar]) -> RistrettoPoint {
        BASE_POINTS
            .iter()
            .zip(scalars)
            .map(|(point, scalar)| point * scalar)
            .reduce(RistrettoPoint::add)
            .unwrap()
    }

    fn make_scalar_args(scalars: &[Scalar]) -> ScalarArgs {
        let mut args = ScalarArgs::new();
        for (scalar, name) in scalars.iter().zip([
            "username_sha_scalar",
            "nickname_scalar",
            "discriminator_scalar",
        ]) {
            args.add(name, *scalar);
        }
        args
    }

    fn make_point_args(lhs: RistrettoPoint) -> PointArgs {
        let mut args = PointArgs::new();
        for (idx, point) in BASE_POINTS.iter().enumerate() {
            let name = format!("G{}", idx + 1);
            args.add(name, *point);
        }
        args.add("username_hash", lhs);
        args
    }
}

fn username_sha_scalar(nickname: &str, discriminator: u64) -> Result<Scalar, UsernameError> {
    let mut hash = Sha512::new();
    hash.update(nickname.as_bytes());
    hash.update([0x00]);
    hash.update(discriminator.to_be_bytes());
    Ok(Scalar::from_hash(hash))
}

fn nickname_scalar(nickname: &str) -> Result<Scalar, UsernameError> {
    assert!(
        !nickname.is_empty(),
        "should be checked before calling nickname_scalar",
    );
    let bytes: Vec<u8> = nickname
        .chars()
        .map(char_to_byte)
        .collect::<Option<_>>()
        .ok_or(UsernameError::BadNicknameCharacter)?;
    if bytes.len() > MAX_NICKNAME_LENGTH {
        return Err(UsernameError::NicknameTooLong);
    }
    Ok(to_base_37_scalar(&bytes))
}

fn discriminator_scalar(discriminator: u64) -> Result<Scalar, UsernameError> {
    Ok(Scalar::from(discriminator))
}

fn make_scalars(nickname: &str, discriminator: u64) -> Result<Vec<Scalar>, UsernameError> {
    Ok(vec![
        username_sha_scalar(nickname, discriminator)?,
        nickname_scalar(nickname)?,
        discriminator_scalar(discriminator)?,
    ])
}

// The mapping is only defined for the characters matching [_0-9a-z]
fn char_to_byte(c: char) -> Option<u8> {
    match c {
        '_' => Some(1),
        'a'..='z' => Some(c as u8 - b'a' + 2),
        '0'..='9' => Some(c as u8 - b'0' + 28),
        _ => None,
    }
}

fn to_base_37_scalar(bytes: &[u8]) -> Scalar {
    assert!(
        bytes.len() <= MAX_NICKNAME_LENGTH,
        "may not fit in a Scalar"
    );

    let thirty_seven = Scalar::from(37u8);
    let mut scalar = Scalar::ZERO;
    for b in bytes.iter().skip(1).rev() {
        scalar *= thirty_seven;
        scalar += Scalar::from(*b);
    }
    scalar *= Scalar::from(27u8);
    scalar += Scalar::from(bytes[0]);
    scalar
}

fn validate_discriminator<T: FromStr<Err = std::num::ParseIntError> + PartialOrd + From<u8>>(
    discriminator: &str,
) -> Result<T, UsernameError> {
    if discriminator.is_empty() {
        return Err(UsernameError::DiscriminatorCannotBeEmpty);
    }
    let first_ascii_char = discriminator.as_bytes()[0];
    if !first_ascii_char.is_ascii_digit() {
        // "+123" is allowed by Rust u*::from_str, but not by us.
        return Err(UsernameError::BadDiscriminatorCharacter);
    }

    let n = T::from_str(discriminator).map_err(|e| match e.kind() {
        std::num::IntErrorKind::Empty => unreachable!("checked above"),
        std::num::IntErrorKind::InvalidDigit => UsernameError::BadDiscriminatorCharacter,
        std::num::IntErrorKind::PosOverflow => UsernameError::DiscriminatorTooLarge,
        std::num::IntErrorKind::NegOverflow => UsernameError::DiscriminatorTooLarge,
        std::num::IntErrorKind::Zero => UsernameError::DiscriminatorCannotBeZero,
        _ => {
            // Don't log the error, it might contain information about the user.
            log::warn!("unknown ParseIntError: {:?}", e.kind());
            UsernameError::BadDiscriminatorCharacter
        }
    })?;

    if n == T::from(0) {
        return Err(UsernameError::DiscriminatorCannotBeZero);
    }

    match discriminator.len() {
        0 => unreachable!("checked above"),
        1 => Err(UsernameError::DiscriminatorCannotBeSingleDigit),
        2 => Ok(n),
        _ if (b'1'..=b'9').contains(&first_ascii_char) => Ok(n),
        _ => Err(UsernameError::DiscriminatorCannotHaveLeadingZeros),
    }
}

fn validate_nickname(nickname: &str, limits: &NicknameLimits) -> Result<(), UsernameError> {
    // This should perform the same set of checks as Username::from_parts.
    validate_prefix(nickname)?;
    let maybe_bytes: Option<Vec<_>> = nickname
        .to_ascii_lowercase()
        .chars()
        .map(char_to_byte)
        .collect();

    let bytes = maybe_bytes.ok_or(UsernameError::BadNicknameCharacter)?;
    limits.validate(bytes.len())
}

fn validate_prefix(s: &str) -> Result<(), UsernameError> {
    match s.chars().next() {
        None => Err(UsernameError::NicknameCannotBeEmpty),
        Some(ch) if ch.is_ascii_digit() => Err(UsernameError::NicknameCannotStartWithDigit),
        _ => Ok(()),
    }
}

fn random_discriminators<R: Rng>(
    rng: &mut R,
    count_per_range: &[usize],
    ranges: &[Range<usize>],
) -> Result<Vec<usize>, UsernameError> {
    assert!(count_per_range.len() <= ranges.len(), "Not enough ranges");
    let total_count: usize = count_per_range.iter().sum();
    let mut results = Vec::with_capacity(total_count);
    for (n, range) in count_per_range.iter().zip(ranges) {
        results.extend(gen_range(rng, range, *n));
    }
    Ok(results)
}

fn gen_range<'a, R: Rng>(
    rng: &mut R,
    range: &'a Range<usize>,
    amount: usize,
) -> impl Iterator<Item = usize> + 'a {
    let length = range.end - range.start;
    let indices = rand::seq::index::sample(rng, length, amount);
    indices.into_iter().map(move |i| range.start + i)
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;

    use super::*;

    const NICKNAME_PATTERN: &str = "[_a-z][_a-z0-9]{2,31}";
    const DISCRIMINATOR_MAX: u64 = 1_000_000_000_u64;

    #[test]
    fn valid_nickname_scalar() {
        // the results should be 1 + 27*27 + 37*27*37^1 + 1*27*37^2 = 74656
        let nickname = "_z9_";
        assert_eq!(Scalar::from(74656_u32), nickname_scalar(nickname).unwrap());
    }

    #[test]
    fn valid_usernames() {
        for username in ["He110.01", "usr.999999999", "_identifier.42", "LOUD.700"] {
            let parsed = Username::new(username).unwrap();
            _ = parsed.hash();
            // Note that parsing is case-preserving even though username hashes are
            // case-insensitive.
            assert_eq!(parsed.to_string(), username);
        }
    }

    #[test]
    fn no_discriminator() {
        assert_eq!(
            Username::new("no_discriminator").expect_err("not a valid username"),
            UsernameError::MissingSeparator
        );
    }

    #[test]
    fn invalid_nicknames() {
        for (nickname, expected_error) in [
            ("", UsernameError::NicknameCannotBeEmpty),
            ("ab🦀d", UsernameError::BadNicknameCharacter),
            ("s p a c e s", UsernameError::BadNicknameCharacter),
            ("0start", UsernameError::NicknameCannotStartWithDigit),
            (
                "nickname_too_big7890123456789012345678901234567890",
                UsernameError::NicknameTooLong,
            ),
        ] {
            assert_eq!(
                Username::from_parts(nickname, "42", NicknameLimits::default())
                    .expect_err("unexpected success for nickname '{nickname}'"),
                expected_error,
                "wrong error for nickname '{nickname}'"
            );

            Username::new(&Username::format_parts(nickname, 42))
                .expect_err("unexpected success for nickname '{nickname}'");
        }
    }

    #[test]
    fn nicknames_exceeding_soft_limits() {
        Username::from_parts("abcd", "42", NicknameLimits::default()).expect("valid");
        assert_eq!(
            Username::from_parts("abcd", "42", NicknameLimits::new(2, 3)).expect_err("too long"),
            UsernameError::NicknameTooLong
        );
        assert_eq!(
            Username::from_parts("abcd", "42", NicknameLimits::new(5, 10)).expect_err("too short"),
            UsernameError::NicknameTooShort
        );
    }

    #[test]
    fn invalid_discriminators() {
        for (discriminator, expected_error) in [
            ("", UsernameError::DiscriminatorCannotBeEmpty),
            ("0", UsernameError::DiscriminatorCannotBeZero),
            ("00", UsernameError::DiscriminatorCannotBeZero),
            ("001", UsernameError::DiscriminatorCannotHaveLeadingZeros),
            ("0123", UsernameError::DiscriminatorCannotHaveLeadingZeros),
            ("1", UsernameError::DiscriminatorCannotBeSingleDigit),
            ("+1", UsernameError::BadDiscriminatorCharacter),
            ("-1", UsernameError::BadDiscriminatorCharacter),
            ("+01", UsernameError::BadDiscriminatorCharacter),
            ("-01", UsernameError::BadDiscriminatorCharacter),
            ("+123", UsernameError::BadDiscriminatorCharacter),
            ("-123", UsernameError::BadDiscriminatorCharacter),
            (
                "123456789012345678901234567890",
                UsernameError::DiscriminatorTooLarge,
            ),
            ("a1", UsernameError::BadDiscriminatorCharacter),
        ] {
            assert_eq!(
                Username::from_parts("ehren", discriminator, NicknameLimits::default())
                    .expect_err("unexpected success for discriminator '{discriminator}'"),
                expected_error,
                "wrong error for discriminator '{discriminator}'"
            );

            Username::new(&format!("ehren.{discriminator}"))
                .expect_err("unexpected success for discriminator '{discriminator}'");
        }
    }

    #[test]
    fn valid_characters_mapping() {
        let all_valid: Option<Vec<_>> = "_abcdefghijklmnopqrstuvwxyz0123456789"
            .chars()
            .map(char_to_byte)
            .collect();
        let unwrapped = all_valid.expect("char_to_byte defined for all valid characters");
        let sorted = {
            let mut xs = unwrapped.clone();
            xs.sort();
            xs
        };
        assert_eq!(sorted, unwrapped);
    }

    #[test]
    fn valid_nicknames_should_produce_scalar() {
        proptest!(|(nickname in NICKNAME_PATTERN)| {
            nickname_scalar(&nickname).unwrap();
        });
    }

    #[test]
    fn valid_usernames_should_produce_scalar() {
        proptest!(|(nickname in NICKNAME_PATTERN, discriminator in 1..DISCRIMINATOR_MAX)| {
            username_sha_scalar(&nickname, discriminator).unwrap();
        });
    }

    #[test]
    fn discriminator_scalar_is_defined_on_range() {
        proptest!(|(n in 1..DISCRIMINATOR_MAX)| {
            discriminator_scalar(n).unwrap();
        });
    }

    #[test]
    fn valid_usernames_proof_and_verify() {
        proptest!(|(nickname in NICKNAME_PATTERN, discriminator in 1..DISCRIMINATOR_MAX)| {
            let username = Username::new(&Username::format_parts(&nickname, discriminator)).unwrap();
            let hash = username.hash();
            let randomness = std::array::from_fn(|i| (i + 1).try_into().unwrap());
            let proof = username.proof(&randomness).unwrap();
            Username::verify_proof(&proof, hash).unwrap();
        });
    }

    #[test]
    fn many_random_makes_valid_usernames() {
        let mut rng = rand::thread_rng();
        let randomness = std::array::from_fn(|i| (i + 1).try_into().unwrap());
        let nickname = "_SiGNA1";
        let candidates = Username::candidates_from(&mut rng, nickname, Default::default()).unwrap();
        for c in &candidates {
            assert!(c.starts_with(nickname));
            let username = Username::new(c).unwrap();
            let hash = username.hash();
            let proof = username.proof(&randomness).unwrap();
            Username::verify_proof(&proof, hash).unwrap();
        }
    }

    #[test]
    fn generate_discriminators() {
        let mut rng = rand::thread_rng();
        let ds = random_discriminators(&mut rng, &[4, 3, 2, 1], &DISCRIMINATOR_RANGES).unwrap();
        assert!(DISCRIMINATOR_RANGES[0].contains(&ds[0]));
        assert!(DISCRIMINATOR_RANGES[0].contains(&ds[1]));
        assert!(DISCRIMINATOR_RANGES[0].contains(&ds[2]));
        assert!(DISCRIMINATOR_RANGES[0].contains(&ds[3]));
        assert!(DISCRIMINATOR_RANGES[1].contains(&ds[4]));
        assert!(DISCRIMINATOR_RANGES[1].contains(&ds[5]));
        assert!(DISCRIMINATOR_RANGES[1].contains(&ds[6]));
        assert!(DISCRIMINATOR_RANGES[2].contains(&ds[7]));
        assert!(DISCRIMINATOR_RANGES[2].contains(&ds[8]));
        assert!(DISCRIMINATOR_RANGES[3].contains(&ds[9]));
    }

    #[test]
    #[should_panic]
    fn too_few_ranges() {
        let mut rng = rand::thread_rng();
        let counts: Vec<usize> = (0usize..DISCRIMINATOR_RANGES.len() + 1).collect();
        let _ = random_discriminators(&mut rng, &counts, &DISCRIMINATOR_RANGES);
    }

    #[test]
    fn nickname_limits() {
        NicknameLimits::default(); // should not panic
        NicknameLimits::new(0, 42).validate(13).unwrap();
    }

    #[test]
    #[should_panic]
    fn invalid_nickname_limits() {
        let _ = NicknameLimits::new(42, 0);
    }
}
