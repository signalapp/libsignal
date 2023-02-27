//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#import "signal_ffi.h"
#import <SignalCoreKit/OWSLogs.h>

static bool isEnabled(const char *_Nonnull target, SignalLogLevel level)
{
    switch (level) {
        case SignalLogLevelError:
            return ShouldLogError();
        case SignalLogLevelWarn:
            return ShouldLogWarning();
        case SignalLogLevelInfo:
            return ShouldLogInfo();
        case SignalLogLevelDebug:
            return ShouldLogDebug();
        case SignalLogLevelTrace:
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
        case SignalLogLevelError:
            [OWSLogger error:formattedMessage];
            break;
        case SignalLogLevelWarn:
            [OWSLogger warn:formattedMessage];
            break;
        case SignalLogLevelInfo:
            [OWSLogger info:formattedMessage];
            break;
        case SignalLogLevelDebug:
            [OWSLogger debug:formattedMessage];
            break;
        case SignalLogLevelTrace:
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
        SignalLogLevel logLevel = ShouldLogDebug() ? SignalLogLevelTrace : SignalLogLevelInfo;
        signal_init_logger(logLevel, (SignalFfiLogger) { .enabled = isEnabled, .log = logMessage, .flush = flush });
    }
}
