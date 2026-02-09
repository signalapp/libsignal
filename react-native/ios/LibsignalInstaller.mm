//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#import <React/RCTBridgeModule.h>
#import <ReactCommon/RCTTurboModule.h>
#import <React/RCTBridge+Private.h>
#import <jsi/jsi.h>
#include "LibsignalTurboModule.h"

@interface LibsignalInstaller : NSObject <RCTBridgeModule>
@end

@implementation LibsignalInstaller

RCT_EXPORT_MODULE(Libsignal)

+ (BOOL)requiresMainQueueSetup {
    return YES;
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(install) {
    RCTBridge *bridge = [RCTBridge currentBridge];
    RCTCxxBridge *cxxBridge = (RCTCxxBridge *)bridge;
    if (cxxBridge == nil) {
        return @(NO);
    }

    auto runtime = (facebook::jsi::Runtime *)cxxBridge.runtime;
    if (runtime == nil) {
        return @(NO);
    }

    libsignal::LibsignalModule::install(*runtime);
    return @(YES);
}

@end
