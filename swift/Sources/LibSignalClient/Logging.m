//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#import "signal_ffi.h"
#import <SignalCoreKit/OWSLogs.h>

static bool isEnabled(const char *_Nonnull target, SignalLogLevel level)
{
    switch (level) {
        case SignalLogLevel_Error:
            return ShouldLogError();
        case SignalLogLevel_Warn:
            return ShouldLogWarning();
        case SignalLogLevel_Info:
            return ShouldLogInfo();
        case SignalLogLevel_Debug:
            return ShouldLogDebug();
        case SignalLogLevel_Trace:
            return ShouldLogVerbose();
        default:
            return ShouldLogError();
    }
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

    // We're not using OWSLog* directly because we don't want log() to be the source of the log.
    NSString *formattedMessage;
    if (file) {
        formattedMessage = [NSString stringWithFormat:@"[%s:%u] %s", file, line, message];
    } else {
        formattedMessage = [NSString stringWithUTF8String:message];
    }

    switch (level) {
        case SignalLogLevel_Error:
            [OWSLogger error:formattedMessage];
            break;
        case SignalLogLevel_Warn:
            [OWSLogger warn:formattedMessage];
            break;
        case SignalLogLevel_Info:
            [OWSLogger info:formattedMessage];
            break;
        case SignalLogLevel_Debug:
            [OWSLogger debug:formattedMessage];
            break;
        case SignalLogLevel_Trace:
            [OWSLogger verbose:formattedMessage];
            break;
        default:
            [OWSLogger error:formattedMessage];
            break;
    }
}

static void flush()
{
    OWSLogFlush();
}

__attribute__((constructor)) static void initLogging()
{
    @autoreleasepool {
        SignalLogLevel logLevel = ShouldLogDebug() ? SignalLogLevel_Trace : SignalLogLevel_Info;
        signal_init_logger(logLevel, (SignalFfiLogger) { .enabled = isEnabled, .log = logMessage, .flush = flush });
    }
}
