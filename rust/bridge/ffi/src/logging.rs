//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libc::c_char;
use std::ffi::CString;

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

pub type LogCallback = extern "C" fn(
    target: *const c_char,
    level: LogLevel,
    file: *const c_char,
    line: u32,
    message: *const c_char,
);

pub type LogEnabledCallback = extern "C" fn(target: *const c_char, level: LogLevel) -> bool;

pub type LogFlushCallback = extern "C" fn();

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FfiLogger {
    enabled: LogEnabledCallback,
    log: LogCallback,
    flush: LogFlushCallback,
}

impl log::Log for FfiLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        let target = CString::new(metadata.target()).expect("no 0 bytes in log target");
        (self.enabled)(target.as_ptr(), metadata.level().into())
    }

    fn log(&self, record: &log::Record) {
        let target = CString::new(record.target()).expect("no 0 bytes in log target");
        let file = record
            .file()
            .map(|file| CString::new(file).expect("no 0 bytes in file"));
        let message = CString::new(record.args().to_string()).unwrap_or_else(|_| {
            CString::new(record.args().to_string().replace('\0', "\\0"))
                .expect("We escaped any NULLs")
        });
        (self.log)(
            target.as_ptr(),
            record.level().into(),
            file.as_ref()
                .map(|file| file.as_ptr())
                .unwrap_or(std::ptr::null()),
            record.line().unwrap_or(0),
            message.as_ptr(),
        );
    }

    fn flush(&self) {
        (self.flush)()
    }
}

#[no_mangle]
pub unsafe extern "C" fn signal_init_logger(max_level: LogLevel, logger: FfiLogger) {
    match log::set_logger(Box::leak(Box::new(logger))) {
        Ok(_) => {
            log::set_max_level(log::Level::from(max_level).to_level_filter());
            log::info!(
                "Initializing libsignal version:{}",
                env!("CARGO_PKG_VERSION")
            );
            log_panics::Config::new()
                .backtrace_mode(log_panics::BacktraceMode::Unresolved)
                .install_panic_hook();
        }
        Err(_) => {
            log::warn!("logging already initialized for libsignal; ignoring later call");
        }
    }
}
