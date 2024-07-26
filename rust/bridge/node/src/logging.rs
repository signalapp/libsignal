//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

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
    // Conceptually, we're going to use this like a shared AtomicU32.
    // But Arc already has an atomic reference count, and we're exactly trying to track the amount of sharing.
    // So we don't actually need to store any data.
    throttle_counter: Arc<()>,
    currently_in_log_spike: AtomicBool,
}

impl NodeLogger {
    fn new(cx: &mut FunctionContext) -> Self {
        let mut channel = cx.channel();
        channel.unref(cx);
        Self {
            channel,
            throttle_counter: Arc::new(()),
            currently_in_log_spike: AtomicBool::new(false),
        }
    }
}

const GLOBAL_LOG_FN_KEY: &str = "__libsignal_log_fn";

impl log::Log for NodeLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        libsignal_bridge::logging::log_enabled_in_apps(metadata)
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let throttle_counter = self.throttle_counter.clone();

        const MAX_LOGS_IN_FLIGHT: usize = 100;
        const END_OF_SPIKE: usize = 80;
        // TODO: Use exclusive range patterns when they're stabilized.
        #[allow(overlapping_range_endpoints, clippy::match_overlapping_arm)]
        let should_additionally_log_about_dropped_logs =
            match Arc::strong_count(&self.throttle_counter) {
                0..=END_OF_SPIKE => {
                    // We are not in a spike, or we are no longer in a spike.
                    self.currently_in_log_spike
                        .store(false, std::sync::atomic::Ordering::Release);
                    false
                }
                END_OF_SPIKE..=MAX_LOGS_IN_FLIGHT => {
                    // Either we're not yet in a spike,
                    // or we're coming off of one but not sure we're done with it yet.
                    false
                }
                _ => {
                    // We are in a spike, or we are just beginning a spike.
                    if self
                        .currently_in_log_spike
                        .swap(true, std::sync::atomic::Ordering::AcqRel)
                    {
                        // Drop this log, we are clearly logging too much.
                        return;
                    }
                    true
                }
            };

        let target = record.target().to_string();
        let file = record.file().map(|s| s.to_string());
        let line = record.line();
        let message = record.args().to_string();
        let level = record.level();

        // Drop any error; it's not like we can log it!
        // Most likely the Node event loop has already shut down.
        let _ = self.channel.try_send(move |mut cx| {
            let log_fn: Handle<JsFunction> = cx.global(GLOBAL_LOG_FN_KEY)?;
            let undef = cx.undefined();

            let args =
                convert_log_args_to_js(&mut cx, level, &target, file.as_deref(), line, &message);
            log_fn.call(&mut cx, undef, args)?;

            if should_additionally_log_about_dropped_logs {
                let args = convert_log_args_to_js(
                    &mut cx,
                    log::Level::Warn,
                    "libsignal_node",
                    Some(file!()),
                    Some(line!()),
                    "high log volume; some logs may have been dropped",
                );
                log_fn.call(&mut cx, undef, args)?;
            }

            // Explicitly keep this alive until we're done.
            drop(throttle_counter);

            Ok(())
        });
    }

    fn flush(&self) {}
}

fn convert_log_args_to_js<'a>(
    cx: &mut TaskContext<'a>,
    level: log::Level,
    target: &str,
    file: Option<&str>,
    line: Option<u32>,
    message: &str,
) -> [Handle<'a, JsValue>; 5] {
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
    [level_arg, target_arg, file_arg, line_arg, message_arg]
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

    let global = cx.global_object();
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
