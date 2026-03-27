//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::sync::Arc;

use strum::{EnumCount, IntoEnumIterator};

/// Signal's Remote Config provides an interface for clients to access feature flags and configuration values for
/// progressive rollouts and emergency rollbacks.
///
/// The Remote Config API returns data structured as follows:
///
/// ```json
/// {
///     key: { 'isEnabled': bool, 'value': String | null }
/// }
/// ...
/// ```
///
/// Clients preprocess this data before it reaches us:
/// - Keys that do not start with `"[platform].libsignal."` are discarded.
/// - The prefix `"[platform].libsignal."` is stripped from the remaining keys.
/// - Entries with `'isEnabled': false` are discarded.
/// - For enabled entries, `null` values are replaced by an empty string.
///
/// After preprocessing, the resulting data is passed to us as a `HashMap<String, Arc<str>>`.
///
/// ## Build Variants
///
/// Beta builds look for keys with a `.beta` suffix first, falling back to the regular key:
/// - Beta: tries `"chatPermessageDeflate.beta"`, falls back to `"chatPermessageDeflate"`
/// - Production: only uses `"chatPermessageDeflate"`
///
/// ## Important notes
///
/// - The presence of a key directly indicates the configuration is enabled.
/// - A configuration value may be an empty string if no explicit value is provided.
///
/// Due to this preprocessing, we **cannot support default values**:
/// - We cannot distinguish between keys that the server intentionally excludes (which could imply a default value)
///   and keys explicitly disabled by the server (excluded during preprocessing).
///
/// This struct provides methods to conveniently determine if a configuration is enabled and to access its associated value.
pub struct RemoteConfig<Key = RemoteConfigKey> {
    inner: HashMap<Key, Arc<str>>,
}

/// Build variant for remote config key selection.
///
/// - `Production`: Use for release builds. Only uses base remote config keys without suffixes.
/// - `Beta`: Use for all other builds (nightly, alpha, internal, public betas). Prefers
///   keys with a `.beta` suffix, falling back to base keys if the suffixed key is not present.
#[repr(u8)]
#[derive(Copy, Clone, derive_more::TryFrom)]
#[try_from(repr)]
pub enum BuildVariant {
    Production = 0,
    Beta = 1,
}

pub trait HasRawKey {
    fn raw(&self) -> &'static str;
}

macro_rules! define_keys {
    (
        $(#[$m:meta])*
        $v:vis enum RemoteConfigKey {
            $(
                $(#[$attrs:meta])*
                $name:ident => $key:expr $(,)?
            )*
        }
    ) => {
        $(#[$m])*
        $v enum RemoteConfigKey {
            $($(#[$attrs])* $name,)*
        }

        impl RemoteConfigKey {
            #[doc = concat!("ts: `export const NetRemoteConfigKeys = [", $("'", $key, "', "),* ,"] as const;`")]
            pub const KEYS: &[&str] = &[$($key),*];
            #[cfg(test)]
            const IDENTITIER_KEY_PAIRS: &[(&str, &str)] = &[
                $((stringify!($name), $key)),*
            ];
        }

        impl HasRawKey for RemoteConfigKey {
            fn raw(&self) -> &'static str {
                match self {
                    $(Self::$name => $key,)*
                }
            }
        }
    };
}

define_keys! {
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, strum::EnumCount, strum::EnumIter)]
pub enum RemoteConfigKey {
    /// How long to wait for a response to a chat request before checking whether the connection is
    /// still active.
    ChatRequestConnectionCheckTimeoutMilliseconds => "chatRequestConnectionCheckTimeoutMillis",
    /// If set, unauth chat connections will connect over H2.
    UseH2ForUnauthChat => "useH2ForUnauthChat",
    /// If set, auth chat connections will connect over H2.
    UseH2ForAuthChat => "useH2ForAuthChat",

    // Typed API keys, based on gRPC request names.
    // These should all start with "grpc." and optionally end with ".{digit}"
    AccountsAnonymousLookupUsernameHash => "grpc.AccountsAnonymousLookupUsernameHash",
    AccountsAnonymousLookupUsernameLink => "grpc.AccountsAnonymousLookupUsernameLink.2",
    AccountsAnonymousCheckAccountExistence => "grpc.AccountsAnonymousCheckAccountExistence.2",
    MessagesAnonymousSendMultiRecipientMessage => "grpc.MessagesAnonymousSendMultiRecipientMessage.2",
    AttachmentsGetUploadForm => "grpc.AttachmentsGetUploadForm",
}
}

pub enum RemoteConfigValue {
    Disabled,
    Enabled(Arc<str>),
}

impl RemoteConfigKey {
    pub fn as_grpc_request_name(&self) -> Option<&'static str> {
        Self::raw_as_grpc_request_name(self.raw())
    }

    /// Given a remote config raw key as input, derive the corresponding gRPC request name if it is
    /// a gRPC key (starts with `"grpc."`).
    ///
    /// This function expects input to be of the form `"grpc.SomeRequestName"` or
    /// `"grpc.SomeRequestName.123`. Behavior on other strings beginning with `"grpc."` is
    /// unspecified.
    fn raw_as_grpc_request_name(raw: &'static str) -> Option<&'static str> {
        let grpc_key_maybe_with_suffix = raw.strip_prefix("grpc.")?;

        // Walk backwards, attempting to match a suffix of the form ".123".
        let mut grpc_key_without_trailing_version = grpc_key_maybe_with_suffix.as_bytes();
        while let Some((last, all_but_last)) = grpc_key_without_trailing_version.split_last() {
            if *last == b'.' {
                // We've successfully stripped the suffix. Reslice to preserve str-ness.
                // We know this is a safe place to slice because (a) ASCII bytes always represent
                // ASCII in UTF-8, and (b) in practice our remote config keys are always ASCII
                // anyway.
                return Some(&grpc_key_maybe_with_suffix[..all_but_last.len()]);
            }
            if !last.is_ascii_digit() {
                // Whoops, this is a message name that may happen to end in digits. Don't strip
                // anything after all.
                return Some(grpc_key_maybe_with_suffix);
            }
            grpc_key_without_trailing_version = all_but_last;
        }

        // This is a message name made up entirely of digits? Weird, but most consistent to allow it.
        Some(grpc_key_maybe_with_suffix)
    }
}

impl std::fmt::Display for RemoteConfigKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.raw())
    }
}

impl<Key> RemoteConfig<Key>
where
    Key: EnumCount + IntoEnumIterator + PartialEq + Eq + std::hash::Hash + HasRawKey,
{
    pub fn new(input_map: HashMap<String, Arc<str>>, build_variant: BuildVariant) -> Self {
        let mut inner = HashMap::with_capacity(Key::COUNT);
        for key in Key::iter() {
            let value = match build_variant {
                BuildVariant::Beta => {
                    let beta_key = format!("{}.beta", key.raw());
                    input_map
                        .get(&beta_key)
                        .or_else(|| input_map.get(key.raw()))
                }
                BuildVariant::Production => input_map.get(key.raw()),
            };
            if let Some(v) = value {
                inner.insert(key, v.clone());
            }
        }
        Self { inner }
    }

    pub fn get(&self, key: Key) -> RemoteConfigValue {
        self.inner
            .get(&key)
            .map(|s| RemoteConfigValue::Enabled(s.clone()))
            .unwrap_or(RemoteConfigValue::Disabled)
    }

    pub fn is_enabled(&self, key: Key) -> bool {
        match self.get(key) {
            RemoteConfigValue::Disabled => false,
            RemoteConfigValue::Enabled(_) => true,
        }
    }

    pub fn iter_enabled(&self) -> impl Iterator<Item = (&Key, &Arc<str>)> {
        self.inner.iter()
    }
}

impl RemoteConfigValue {
    pub fn as_option(&self) -> Option<&'_ str> {
        match self {
            RemoteConfigValue::Disabled => None,
            RemoteConfigValue::Enabled(value) => Some(value),
        }
    }
}

#[cfg(test)]
// `define_keys` produces some things that end up not used, silence that.
#[expect(dead_code)]
mod tests {
    use std::collections::HashSet;

    use itertools::Itertools as _;
    use test_case::test_case;

    use super::*;

    define_keys! {
        #[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, strum::EnumCount, strum::EnumIter)]
        pub enum RemoteConfigKey {
            TestKey => "testKey",
            TestGrpcKeyWithSuffix => "grpc.testGrpcKey.2013",
        }
    }

    #[test]
    fn beta_prefers_beta_key_then_base() {
        let m = HashMap::from_iter([
            ("testKey".to_string(), Arc::from("base")),
            ("testKey.beta".to_string(), Arc::from("beta")),
            ("grpc.testGrpcKey.2013".to_string(), Arc::from("base")),
            ("grpc.testGrpcKey.2013.beta".to_string(), Arc::from("beta")),
        ]);

        let prod = RemoteConfig::new(m.clone(), BuildVariant::Production);
        let beta = RemoteConfig::new(m, BuildVariant::Beta);

        assert_eq!(prod.get(RemoteConfigKey::TestKey).as_option(), Some("base"));
        assert_eq!(beta.get(RemoteConfigKey::TestKey).as_option(), Some("beta"));

        // Either way, should show as enabled.
        assert!(prod.is_enabled(RemoteConfigKey::TestKey));
        assert!(beta.is_enabled(RemoteConfigKey::TestKey));

        // The gRPC key transform should never see the ".beta"
        let prod_grpc_keys = prod
            .iter_enabled()
            .filter_map(|(k, _v)| super::RemoteConfigKey::raw_as_grpc_request_name(k.raw()))
            .collect_vec();
        assert_eq!(prod_grpc_keys, &["testGrpcKey"]);
        let beta_grpc_keys = beta
            .iter_enabled()
            .filter_map(|(k, _v)| super::RemoteConfigKey::raw_as_grpc_request_name(k.raw()))
            .collect_vec();
        assert_eq!(beta_grpc_keys, &["testGrpcKey"]);
    }

    #[test]
    fn beta_falls_back_to_base_when_beta_key_missing() {
        let m = HashMap::from_iter([("testKey".to_string(), Arc::from("base"))]);

        let beta = RemoteConfig::new(m, BuildVariant::Beta);
        assert_eq!(beta.get(RemoteConfigKey::TestKey).as_option(), Some("base"));

        assert!(beta.is_enabled(RemoteConfigKey::TestKey));
    }

    #[test]
    fn production_ignores_beta_keys() {
        let m = HashMap::from_iter([("testKey.beta".to_string(), Arc::from("beta"))]);

        let prod = RemoteConfig::new(m, BuildVariant::Production);
        assert_eq!(prod.get(RemoteConfigKey::TestKey).as_option(), None);

        assert!(!prod.is_enabled(RemoteConfigKey::TestKey));
    }

    #[test]
    fn grpc_keys_are_from_some_grpc_service() {
        use libsignal_net_grpc::proto::chat::services;
        // Add new services as they become relevant.
        let all_known_grpc_keys: HashSet<&str> = std::iter::empty()
            .chain(services::AccountsAnonymous::iter().map(|x| x.into()))
            .chain(services::Attachments::iter().map(|x| x.into()))
            .chain(services::KeysAnonymous::iter().map(|x| x.into()))
            .chain(services::MessagesAnonymous::iter().map(|x| x.into()))
            .collect();

        for key in super::RemoteConfigKey::KEYS
            .iter()
            .copied()
            .filter_map(super::RemoteConfigKey::raw_as_grpc_request_name)
        {
            assert!(
                all_known_grpc_keys.contains(key),
                "unexpected gRPC key grpc.{key} (known keys:\n\t{}\n)",
                all_known_grpc_keys.into_iter().sorted().join("\n\t")
            );
        }
        for (ident, key) in super::RemoteConfigKey::IDENTITIER_KEY_PAIRS {
            if let Some(grpc_name) = super::RemoteConfigKey::raw_as_grpc_request_name(key) {
                assert_eq!(*ident, grpc_name);
            }
        }
    }

    #[test_case("" => None)]
    #[test_case("notGrpc" => None)]
    #[test_case("grpc" => None)]
    #[test_case("grpc.abc" => Some("abc"))]
    #[test_case("grpc.abc.123" => Some("abc"))]
    #[test_case("grpc.abc123" => Some("abc123"))]
    #[test_case("grpc.abc123.456" => Some("abc123"))]
    // Known weird behavior we won't subject ourselves to in practice.
    #[test_case("grpc.trailingDot." => Some("trailingDot"))]
    #[test_case("grpc.doubleDot..123" => Some("doubleDot."))]
    #[test_case("grpc.@b$0lute Garbage^^.123" => Some("@b$0lute Garbage^^"))]
    #[test_case("grpc.123" => Some("123"))]
    #[test_case("grpc.123.456" => Some("123"))]
    fn grpc_key_transform(input: &'static str) -> Option<&'static str> {
        super::RemoteConfigKey::raw_as_grpc_request_name(input)
    }
}
