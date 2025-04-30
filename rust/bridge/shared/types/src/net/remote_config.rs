use std::collections::HashMap;

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
    raw_map: HashMap<String, String>,
}
struct RemoteConfigKey {
    raw_key: &'static str,
}

#[derive(Copy, Clone)]
pub enum RemoteConfigKeys {
    /// Whether or not to enforce the hardcoded minimum TLS versions for Chat and CDSI endpoints.
    EnforceMinimumTls,
}

pub enum RemoteConfigValue {
    Disabled,
    Enabled(String),
}

impl From<RemoteConfigKeys> for RemoteConfigKey {
    fn from(key: RemoteConfigKeys) -> Self {
        match key {
            // TODO: Remove after enforcement has been enabled in production long enough
            //   without reported issues.
            RemoteConfigKeys::EnforceMinimumTls => RemoteConfigKey {
                raw_key: "enforceMinimumTls",
            },
        }
    }
}

impl RemoteConfig {
    pub fn new(raw_map: HashMap<String, String>) -> Self {
        Self { raw_map }
    }

    pub fn get(&self, key: RemoteConfigKeys) -> RemoteConfigValue {
        let key: RemoteConfigKey = key.into();
        self.raw_map
            .get(key.raw_key)
            .map(|s| RemoteConfigValue::Enabled(s.to_string()))
            .unwrap_or(RemoteConfigValue::Disabled)
    }

    pub fn is_enabled(&self, key: RemoteConfigKeys) -> bool {
        match self.get(key) {
            RemoteConfigValue::Disabled => false,
            RemoteConfigValue::Enabled(_) => true,
        }
    }
}
