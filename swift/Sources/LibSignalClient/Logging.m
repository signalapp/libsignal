//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#import "signal_ffi.h"
#import <SignalCoreKit/OWSLogs.h>

static DDLogFlag flagForLevel(SignalLogLevel level)
{
    switch (level) {
        case SignalLogLevelError:
            return DDLogFlagError;
        case SignalLogLevelWarn:
            return DDLogFlagWarning;
        case SignalLogLevelInfo:
            return DDLogFlagInfo;
        case SignalLogLevelDebug:
            return DDLogFlagDebug;
        case SignalLogLevelTrace:
            return DDLogFlagVerbose;
        default:
            return DDLogFlagError;
    }
}

static bool isEnabled(const char *_Nonnull target, SignalLogLevel level)
{
    return ShouldLogFlag(flagForLevel(level));
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
    OWSLogUnconditionally(flagForLevel(level), file ?: "", NO, line, "", @"%s", message);
}

static void flush()
{
    OWSLogFlush();
}

__attribute__((constructor)) static void initLogging()
{
    @autoreleasepool {
        SignalLogLevel logLevel = ShouldLogDebug() ? SignalLogLevelTrace : SignalLogLevelInfo;
        signal_init_logger(logLevel, (SignalFfiLogger) { .enabled = isEnabled, .log = logMessage, .flush = flush });
    }
}
