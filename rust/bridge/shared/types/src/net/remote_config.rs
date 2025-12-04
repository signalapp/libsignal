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
pub struct RemoteConfig {
    inner: HashMap<RemoteConfigKey, Arc<str>>,
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
            #[doc = concat!("ts: export const NetRemoteConfigKeys = [", $("'", $key, "', "),* ,"] as const;")]
            pub const KEYS: &[&str] = &[$($key),*];

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
    /// Determines whether a chat websocket connection attempts to negotiate permessage-deflate support.
    EnableChatPermessageDeflate => "chatPermessageDeflate",
    /// Whether to disable the Nagle algorithm (sets TCP_NODELAY).
    DisableNagleAlgorithm => "disableNagleAlgorithm",
}
}

pub enum RemoteConfigValue {
    Disabled,
    Enabled(Arc<str>),
}

impl std::fmt::Display for RemoteConfigKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.raw())
    }
}

impl RemoteConfig {
    pub fn new(input_map: HashMap<String, Arc<str>>, build_variant: BuildVariant) -> Self {
        let mut inner = HashMap::with_capacity(RemoteConfigKey::COUNT);
        for key in RemoteConfigKey::iter() {
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

    pub fn get(&self, key: RemoteConfigKey) -> RemoteConfigValue {
        self.inner
            .get(&key)
            .map(|s| RemoteConfigValue::Enabled(s.clone()))
            .unwrap_or(RemoteConfigValue::Disabled)
    }

    pub fn is_enabled(&self, key: RemoteConfigKey) -> bool {
        match self.get(key) {
            RemoteConfigValue::Disabled => false,
            RemoteConfigValue::Enabled(_) => true,
        }
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
mod tests {
    use super::*;

    #[test]
    fn beta_prefers_beta_key_then_base() {
        let m = HashMap::from_iter([
            ("chatPermessageDeflate".to_string(), Arc::from("base")),
            ("chatPermessageDeflate.beta".to_string(), Arc::from("beta")),
        ]);

        let prod = RemoteConfig::new(m.clone(), BuildVariant::Production);
        let beta = RemoteConfig::new(m, BuildVariant::Beta);

        assert_eq!(
            prod.get(RemoteConfigKey::EnableChatPermessageDeflate)
                .as_option(),
            Some("base")
        );
        assert_eq!(
            beta.get(RemoteConfigKey::EnableChatPermessageDeflate)
                .as_option(),
            Some("beta")
        );

        // Either way, should show as enabled.
        assert!(prod.is_enabled(RemoteConfigKey::EnableChatPermessageDeflate));
        assert!(beta.is_enabled(RemoteConfigKey::EnableChatPermessageDeflate));
    }

    #[test]
    fn beta_falls_back_to_base_when_beta_key_missing() {
        let m = HashMap::from_iter([("chatPermessageDeflate".to_string(), Arc::from("base"))]);

        let beta = RemoteConfig::new(m, BuildVariant::Beta);
        assert_eq!(
            beta.get(RemoteConfigKey::EnableChatPermessageDeflate)
                .as_option(),
            Some("base")
        );

        assert!(beta.is_enabled(RemoteConfigKey::EnableChatPermessageDeflate));
    }

    #[test]
    fn production_ignores_beta_keys() {
        let m = HashMap::from_iter([("chatPermessageDeflate.beta".to_string(), Arc::from("beta"))]);

        let prod = RemoteConfig::new(m, BuildVariant::Production);
        assert_eq!(
            prod.get(RemoteConfigKey::EnableChatPermessageDeflate)
                .as_option(),
            None
        );

        assert!(!prod.is_enabled(RemoteConfigKey::EnableChatPermessageDeflate));
    }
}
