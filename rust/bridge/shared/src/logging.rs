//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::ffi::{CStr, c_void};
use std::fmt::Formatter;

use backtrace::Backtrace;

/// An implementation of [`log::Log::enabled`] suitable for production Signal apps.
///
/// Apps may apply additional logging filters on top of what libsignal reports.
pub fn log_enabled_in_apps(metadata: &log::Metadata) -> bool {
    let target = metadata.target();
    if target.is_empty() {
        return false;
    }

    let check = |crate_name: &str| {
        // Accept both "crate_name" and "crate_name::something".
        target
            .strip_prefix(crate_name)
            .is_some_and(|remainder| remainder.is_empty() || remainder.starts_with("::"))
    };

    // Use a manual jump table to reduce the number of checks we perform on each log message.
    // (The compiler can optimize some switches on strings, but it's hard to convince it to do
    // something smart for checking prefixes *and* exact matches.)
    match target.as_bytes()[0] {
        // libsignal naming patterns:
        b'l' => target.starts_with("libsignal_"),
        b's' => target.starts_with("signal_") || check("spqr"),

        // Other libsignal crates:
        b'a' => check("attest"),
        b'd' => check("device_transfer"),
        b'p' => check("poksho"),
        b'u' => check("usernames"),
        b'z' => check("zkgroup") || check("zkcredential"),

        // mediasan crates (only show warnings and errors):
        b'm' if check("mediasan_common") || check("mp4san") => metadata.level() <= log::Level::Warn,
        b'w' if check("webpsan") => metadata.level() <= log::Level::Warn,

        // Otherwise...
        _ => false,
    }
}

#[derive(Default)]
struct DlAddrInfo<'a> {
    module_base_address: Option<*mut c_void>,
    image_name: Option<&'a str>,
}
fn dladdr<T>(ip: *mut c_void, cb: impl FnOnce(DlAddrInfo) -> T) -> T {
    #[cfg(unix)]
    {
        if ip.is_null() {
            return cb(Default::default());
        }
        unsafe {
            let mut info: libc::Dl_info = std::mem::zeroed();
            let rc = libc::dladdr(ip, &mut info);
            if rc != 0 {
                cb(DlAddrInfo {
                    module_base_address: Some(info.dli_fbase),
                    image_name: if info.dli_fname.is_null() {
                        None
                    } else {
                        CStr::from_ptr(info.dli_fname).to_str().ok()
                    },
                })
            } else {
                cb(Default::default())
            }
        }
    }
    // The backtrace crate only supports module base addresses on Windows, anyway.
    #[cfg(not(unix))]
    cb(Default::default())
}

fn rstrip_until(x: &str, pattern: char) -> &str {
    let Some((_, out)) = x.rsplit_once(pattern) else {
        return x;
    };
    out
}

fn image_base_name(image_name: &str) -> &str {
    rstrip_until(rstrip_until(image_name, '/'), '\\')
}
#[test]
fn test_image_base_name() {
    assert_eq!(image_base_name("/a/b"), "b");
    assert_eq!(image_base_name("/a/foo\\b"), "b");
    assert_eq!(image_base_name("C:\\x\\a/b"), "b");
    assert_eq!(image_base_name("C:\\a\\b"), "b");
}

struct BacktraceDisplay<'a>(&'a Backtrace);
impl<'a> std::fmt::Display for BacktraceDisplay<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let b = self.0;
        for frame in b.frames() {
            let ip = frame.ip();
            dladdr(
                ip,
                |DlAddrInfo {
                     module_base_address,
                     image_name,
                 }|
                 -> std::fmt::Result {
                    let module_base_address = module_base_address
                        .or_else(|| frame.module_base_address())
                        .unwrap_or_default();
                    // On macos and ios, symbol_address() just returns the IP, so we zero this out to
                    // let us know.
                    let symbol_address = if cfg!(any(target_os = "macos", target_os = "ios")) {
                        Default::default()
                    } else {
                        frame.symbol_address()
                    };
                    write!(f, "BACKTRACE: {{\"image_name\": ")?;
                    if let Some(image_name) = image_name {
                        write!(f, "\"{}\"", image_base_name(image_name).escape_default())?;
                    } else {
                        write!(f, "null")?;
                    }
                    writeln!(
                        f,
                        ", \"image_base\": \"{:016X}\", \"symbol\": \"{:016X}\", \"ip\": \"{:016X}\"}}",
                        module_base_address as u64, symbol_address as u64, ip as u64,
                    )
                },
            )?;
        }
        writeln!(f)?;
        Ok(())
    }
}

pub fn set_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let old_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let backtrace = Backtrace::new_unresolved();
            old_hook(info);
            let thread = std::thread::current();
            let thread_name = thread.name().unwrap_or("<unnamed>");
            let thread_id = thread.id();
            log::error!(
                "thread '{thread_name}' ({thread_id:?}) {info}\n{}",
                BacktraceDisplay(&backtrace)
            );
        }));
    });
}

#[cfg(test)]
mod tests {
    use test_case::test_matrix;

    use super::*;

    #[test_matrix([
        "libsignal_foo",
        "signal_foo",
        "attest",
        "device_transfer",
        "poksho",
        "spqr",
        "usernames",
        "zkgroup",
        "zkcredential"
    ])]
    fn accepted(name: &str) {
        assert!(log_enabled_in_apps(
            &log::Metadata::builder()
                .target(name)
                .level(log::Level::Debug)
                .build()
        ));

        assert!(log_enabled_in_apps(
            &log::Metadata::builder()
                .target(&format!("{name}::foo::bar"))
                .level(log::Level::Debug)
                .build()
        ));
    }

    #[test_matrix(
        ["mp4san", "mediasan_common", "webpsan"],
        [log::Level::Error, log::Level::Warn, log::Level::Info]
    )]
    fn warnings_and_errors_only(name: &str, level: log::Level) {
        debug_assert!(
            log::Level::Error < log::Level::Warn,
            "log levels are ordered with 'higher' = 'more verbose'"
        );
        let expected = level <= log::Level::Warn;

        assert_eq!(
            expected,
            log_enabled_in_apps(&log::Metadata::builder().target(name).level(level).build()),
        );

        assert_eq!(
            expected,
            log_enabled_in_apps(
                &log::Metadata::builder()
                    .target(&format!("{name}::foo::bar"))
                    .level(level)
                    .build()
            ),
        );
    }

    #[test_matrix([
        "",
        "dependency",
        "curve25519_dalek",
        "not a usual target"]
    )]
    fn rejected(name: &str) {
        assert!(!log_enabled_in_apps(
            &log::Metadata::builder()
                .target(name)
                .level(log::Level::Error)
                .build()
        ));

        assert!(!log_enabled_in_apps(
            &log::Metadata::builder()
                .target(&format!("{name}::foo::bar"))
                .level(log::Level::Error)
                .build()
        ));
    }

    // `test_matrix` gets unhappy with "" and "::" in the same list, because neither has any
    // identifier characters.
    #[test]
    fn rejected_double_colon() {
        rejected("::")
    }
}
