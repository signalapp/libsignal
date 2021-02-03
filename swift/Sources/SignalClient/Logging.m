//
// Copyright 2020-2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

#import "signal_ffi.h"
#import <CocoaLumberjack/CocoaLumberjack.h>

#ifdef DEBUG
static const NSUInteger ddLogLevel = DDLogLevelAll;
#else
static const NSUInteger ddLogLevel = DDLogLevelInfo;
#endif

// Matches the behavior of SignalCoreKit.
static const char *getPrefix(SignalLogLevel level)
{
    switch (level) {
        case SignalLogLevel_Trace:
            return u8"💙";
        case SignalLogLevel_Debug:
            return u8"💚";
        case SignalLogLevel_Info:
            return u8"💛";
        case SignalLogLevel_Warn:
            return u8"🧡";
        case SignalLogLevel_Error:
        default:
            return u8"❤️";
    }
}

static DDLogFlag getDDLogFlag(SignalLogLevel level)
{
    switch (level) {
        case SignalLogLevel_Trace:
            return DDLogFlagVerbose;
        case SignalLogLevel_Debug:
            return DDLogFlagDebug;
        case SignalLogLevel_Info:
            return DDLogFlagInfo;
        case SignalLogLevel_Warn:
            return DDLogFlagWarning;
        case SignalLogLevel_Error:
        default:
            return DDLogFlagError;
    }
}

static bool isEnabled(const char *_Nonnull target, SignalLogLevel level)
{
    return ddLogLevel >= getDDLogFlag(level);
}

static void logMessage(const char *_Nonnull target,
    SignalLogLevel level,
    const char *_Nullable file,
    uint32_t line,
    const char *_Nonnull message)
{
    if (!isEnabled(target, level)) {
        return;
    }

    const char *prefix = getPrefix(level);

    NSString *format;
    if (file) {
        format = @"%1$s [%3$s:%4$u] %2$s";
    } else {
        format = @"%1$s %2$s";
    }

    [DDLog log:(level != SignalLogLevel_Error)
         level:ddLogLevel
          flag:getDDLogFlag(level)
       context:0
          file:file ? file : "<SignalClient>"
      function:NULL
          line:line
           tag:nil
        format:format, prefix, message, file, line];
}

static void flush()
{
    [DDLog flushLog];
}

__attribute__((constructor)) static void initLogging()
{
    SignalLogLevel logLevel = isEnabled("", SignalLogLevel_Trace) ? SignalLogLevel_Trace : SignalLogLevel_Info;
    signal_init_logger(logLevel, (SignalFfiLogger) { .enabled = isEnabled, .log = logMessage, .flush = flush });
}
