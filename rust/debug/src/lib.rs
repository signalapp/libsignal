//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
//! Some debugging utilities for libsignal.
//!
//! This will compile out _completely_ if the `libsignal-debug/enabled` feature is not turned on.
//!
//! To use this library:
//!
//! ```
//! use libsignal_debug::trace_block;
//!
//! let _guard = trace_block!("my thing to trace");
//! // An entry of the given name to trace will be logged. It will be marked as in-progress until
//! // _guard gets dropped.
//! ```

use std::ffi::CStr;

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "enabled")] {
        // This string is checked in build_jni.sh
        #[used]
        static _DEBUG_IS_ENABLED: &str = "LIBSIGNAL-DEBUG IS ENABLED";
        cfg_if! {
            if #[cfg(target_os = "android")] {
                mod android;
                use android as backend;
            } else {
                mod null;
                use null as backend;
            }
        }
    } else {
        mod null;
        use null as backend;
    }
}

pub const BACKEND: &str = backend::NAME;
pub struct TraceSectionGuard {
    _guard: backend::TraceSectionGuard,
}

pub struct Section {
    #[allow(unused)]
    pub(crate) name: &'static CStr,
}
impl Section {
    #[doc(hidden)]
    pub const fn from_cstr(name: &'static CStr) -> Self {
        Self { name }
    }
    #[doc(hidden)]
    pub fn enter(&self) -> TraceSectionGuard {
        TraceSectionGuard {
            _guard: backend::TraceSectionGuard::from_section(self),
        }
    }
}

/// Construct a trace guard which will trace a section until it's dropped.
///
/// These should be dropped in the same order that they're created.
#[macro_export]
macro_rules! trace_block {
    ($name:expr) => {
        const {
            $crate::Section::from_cstr({
                let Ok(name) = std::ffi::CStr::from_bytes_with_nul(
                    concat!(module_path!(), "::", $name, "\0",).as_bytes(),
                ) else {
                    panic!("missing null terminator")
                };
                name
            })
        }
        .enter()
    };
}
