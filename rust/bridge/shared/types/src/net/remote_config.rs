//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::sync::Arc;

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
/// After preprocessing, the resulting data is passed to us as a `HashMap<String, String>` called `raw_map`.
///
/// **Important notes:**
/// - The presence of a key in `raw_map` directly indicates the configuration is enabled.
/// - A configuration value may be an empty string if no explicit value is provided.
///
/// Due to this preprocessing, we **cannot support default values**:
/// - We cannot distinguish between keys that the server intentionally excludes (which could imply a default value)
///   and keys explicitly disabled by the server (excluded during preprocessing).
///
/// This struct provides methods to conveniently determine if a configuration is enabled and to access its associated value.
pub struct RemoteConfig {
    raw_map: HashMap<String, Arc<str>>,
}

#[derive(Copy, Clone)]
pub enum RemoteConfigKey {
    /// How long to wait for a response to a chat request before checking whether the connection is
    /// still active.
    ChatRequestConnectionCheckTimeoutMilliseconds,
    /// Whether or not to enforce the hardcoded minimum TLS versions for Chat and CDSI endpoints.
    // TODO: Remove after enforcement has been enabled in production long enough without reported
    // issues.
    EnforceMinimumTls,
    /// If enabled, tries to connect via Noise Direct after establishing an authenticated chat connection.
    ShadowAuthChatWithNoiseDirect,
    /// If enabled, tries to connect via Noise Direct after establishing an unauthenticated chat connection.
    ShadowUnauthChatWithNoiseDirect,
}

pub enum RemoteConfigValue {
    Disabled,
    Enabled(Arc<str>),
}

impl RemoteConfigKey {
    fn raw(&self) -> &'static str {
        match self {
            Self::ChatRequestConnectionCheckTimeoutMilliseconds => {
                "chatRequestConnectionCheckTimeoutMillis"
            }
            Self::EnforceMinimumTls => "enforceMinimumTls",
            Self::ShadowAuthChatWithNoiseDirect => "shadowAuthChatWithNoise",
            Self::ShadowUnauthChatWithNoiseDirect => "shadowUnauthChatWithNoise",
        }
    }
}

impl std::fmt::Display for RemoteConfigKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.raw())
    }
}

impl RemoteConfig {
    pub fn new(raw_map: HashMap<String, Arc<str>>) -> Self {
        Self { raw_map }
    }

    pub fn get(&self, key: RemoteConfigKey) -> RemoteConfigValue {
        self.raw_map
            .get(key.raw())
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
