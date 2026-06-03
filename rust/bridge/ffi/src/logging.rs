//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_bridge::{ffi, ffi_result_type};
use libsignal_bridge_macros::bridge_callbacks;

#[repr(C)]
pub enum LogLevel {
    Error = 1,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<log::Level> for LogLevel {
    fn from(level: log::Level) -> Self {
        use log::Level::*;
        match level {
            Error => Self::Error,
            Warn => Self::Warn,
            Info => Self::Info,
            Debug => Self::Debug,
            Trace => Self::Trace,
        }
    }
}

impl From<LogLevel> for log::Level {
    fn from(level: LogLevel) -> Self {
        use LogLevel::*;
        match level {
            Error => Self::Error,
            Warn => Self::Warn,
            Info => Self::Info,
            Debug => Self::Debug,
            Trace => Self::Trace,
        }
    }
}

impl ffi::ResultTypeInfo for LogLevel {
    type ResultType = Self;
    fn convert_into(self) -> ffi::SignalFfiResult<Self::ResultType> {
        Ok(self)
    }
}

#[bridge_callbacks(jni = false, node = false)]
trait Logger {
    fn log(&self, level: LogLevel, file: Option<&str>, line: u32, message: String);
    fn flush(&self);
}

// It's up to the other side of the bridge to provide a Sync-friendly context.
unsafe impl Send for FfiLoggerStruct {}
unsafe impl Sync for FfiLoggerStruct {}

impl log::Log for FfiLoggerStruct {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        libsignal_bridge::logging::log_enabled_in_apps(metadata)
    }

    fn log(&self, record: &log::Record) {
        if !libsignal_bridge::logging::log_enabled_in_apps(record.metadata()) {
            return;
        }

        let message = record.args().to_string();
        let message = if message.contains('\0') {
            // This should be rare, so we won't especially optimize it. But just in case.
            message.replace('\0', "\\0")
        } else {
            message
        };

        Logger::log(
            self,
            record.level().into(),
            record.file(),
            record.line().unwrap_or(0),
            message,
        );
    }

    fn flush(&self) {
        Logger::flush(self);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn signal_init_logger(max_level: LogLevel, logger: FfiLoggerStruct) -> bool {
    match log::set_logger(Box::leak(Box::new(logger))) {
        Ok(_) => {
            log::set_max_level(log::Level::from(max_level).to_level_filter());
            log::info!(
                "Initializing libsignal version:{}",
                env!("CARGO_PKG_VERSION")
            );
            // These strings are explicitly looked for by build_ffi.sh.
            log::debug!("THIS BUILD HAS DEBUG-LEVEL LOGS ENABLED");
            log::trace!("THIS BUILD HAS TRACE-LEVEL LOGS ENABLED");
            log_panics::Config::new()
                .backtrace_mode(log_panics::BacktraceMode::Unresolved)
                .install_panic_hook();
            true
        }
        Err(_) => {
            log::warn!("logging already initialized for libsignal; ignoring later call");
            false
        }
    }
}
