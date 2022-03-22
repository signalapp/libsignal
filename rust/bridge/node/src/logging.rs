//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_bridge::node::SimpleArgTypeInfo;
use neon::prelude::*;

/// ts: export const enum LogLevel { Error = 1, Warn, Info, Debug, Trace }
#[derive(Clone, Copy)]
enum LogLevel {
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

impl From<LogLevel> for u32 {
    fn from(level: LogLevel) -> Self {
        level as u32
    }
}

struct NodeLogger {
    channel: Channel,
}

impl NodeLogger {
    fn new(cx: &mut FunctionContext) -> Self {
        let mut channel = cx.channel();
        channel.unref(cx);
        Self { channel }
    }
}

const GLOBAL_LOG_FN_KEY: &str = "__libsignal_log_fn";

impl log::Log for NodeLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let target = record.target().to_string();
        let file = record.file().map(|s| s.to_string());
        let line = record.line();
        let message = record.args().to_string();
        let level = record.level();
        // Drop any error; it's not like we can log it!
        // Most likely the Node event loop has already shut down.
        let _ = self.channel.try_send(move |mut cx| {
            let level_arg: Handle<JsValue> = cx.number(u32::from(LogLevel::from(level))).upcast();
            let target_arg: Handle<JsValue> = cx.string(target).upcast();
            let file_arg: Handle<JsValue> = match file {
                Some(file) => cx.string(file).upcast(),
                None => cx.null().upcast(),
            };
            let line_arg: Handle<JsValue> = match line {
                Some(line) => cx.number(line as f64).upcast(),
                None => cx.null().upcast(),
            };
            let message_arg: Handle<JsValue> = cx.string(message).upcast();

            let global_obj = cx.global();
            let log_fn: Handle<JsFunction> = global_obj.get(&mut cx, GLOBAL_LOG_FN_KEY)?;
            let undef = cx.undefined();
            log_fn.call(
                &mut cx,
                undef,
                [level_arg, target_arg, file_arg, line_arg, message_arg],
            )?;
            Ok(())
        });
    }

    fn flush(&self) {}
}

fn set_max_level_from_js_level(max_level: u32) {
    let level = match max_level {
        1 => LogLevel::Error,
        2 => LogLevel::Warn,
        3 => LogLevel::Info,
        4 => LogLevel::Debug,
        5 => LogLevel::Trace,
        _ => panic!("invalid log level"),
    };
    assert!(u32::from(level) == max_level);

    log::set_max_level(log::Level::from(level).to_level_filter());
}

/// ts: export function initLogger(maxLevel: LogLevel, callback: (level: LogLevel, target: string, file: string | null, line: number | null, message: string) => void): void
pub(crate) fn init_logger(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let max_level_arg = cx.argument::<JsNumber>(0)?;
    let max_level = u32::convert_from(&mut cx, max_level_arg)?;
    let callback = cx.argument::<JsFunction>(1)?;

    let global = cx.global();
    global.set(&mut cx, GLOBAL_LOG_FN_KEY, callback)?;

    let logger = NodeLogger::new(&mut cx);
    match log::set_logger(Box::leak(Box::new(logger))) {
        Ok(_) => {
            set_max_level_from_js_level(max_level);
            log::info!(
                "Initializing libsignal version:{}",
                env!("CARGO_PKG_VERSION")
            );
            log_panics::init();
        }
        Err(_) => {
            log::warn!("logging already initialized for libsignal; ignoring later call");
        }
    }

    Ok(cx.undefined())
}
