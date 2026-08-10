//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

public struct CallQualitySurvey: Sendable {
    public init(
        userSatisfied: Bool,
        callQualityIssues: [String],
        additionalIssuesDescription: String?,
        debugLogUrl: String?,
        startTimestamp: Date,
        endTimestamp: Date,
        callType: String,
        success: Bool,
        callEndReason: String,
        connectionRttMedian: Float? = nil,
        audioRttMedian: Float? = nil,
        videoRttMedian: Float? = nil,
        audioRecvJitterMedian: Float? = nil,
        videoRecvJitterMedian: Float? = nil,
        audioSendJitterMedian: Float? = nil,
        videoSendJitterMedian: Float? = nil,
        audioRecvPacketLossFraction: Float? = nil,
        videoRecvPacketLossFraction: Float? = nil,
        audioSendPacketLossFraction: Float? = nil,
        videoSendPacketLossFraction: Float? = nil,
        callTelemetry: Data?,
        callIdHash: Data?
    ) {
        self.userSatisfied = userSatisfied
        self.callQualityIssues = callQualityIssues
        self.additionalIssuesDescription = additionalIssuesDescription
        self.debugLogUrl = debugLogUrl
        self.startTimestamp = startTimestamp
        self.endTimestamp = endTimestamp
        self.callType = callType
        self.success = success
        self.callEndReason = callEndReason
        self.connectionRttMedian = connectionRttMedian
        self.audioRttMedian = audioRttMedian
        self.videoRttMedian = videoRttMedian
        self.audioRecvJitterMedian = audioRecvJitterMedian
        self.videoRecvJitterMedian = videoRecvJitterMedian
        self.audioSendJitterMedian = audioSendJitterMedian
        self.videoSendJitterMedian = videoSendJitterMedian
        self.audioRecvPacketLossFraction = audioRecvPacketLossFraction
        self.videoRecvPacketLossFraction = videoRecvPacketLossFraction
        self.audioSendPacketLossFraction = audioSendPacketLossFraction
        self.videoSendPacketLossFraction = videoSendPacketLossFraction
        self.callTelemetry = callTelemetry
        self.callIdHash = callIdHash
    }

    /// Indicates whether the caller was generally satisfied with the quality of
    /// the call
    var userSatisfied: Bool
    /// A list of call quality issues selected by the caller
    var callQualityIssues: [String]
    /// A free-form description of any additional issues as written by the caller
    var additionalIssuesDescription: String?
    /// A URL for a set of debug logs associated with the call if the caller chose
    /// to submit debug logs
    var debugLogUrl: String?
    /// The time at which the call started
    var startTimestamp: Date
    /// The time at which the call ended
    var endTimestamp: Date
    /// The type of call, note that direct voice calls can become video calls and
    /// vice versa, and this field indicates which mode was selected at call
    /// initiation time. At the time of writing, expected call types are
    /// "direct_voice", "direct_video", "group", and "call_link".
    var callType: String
    /// Indicates whether the call completed without error or if it terminated
    /// abnormally
    var success: Bool
    /// A client-defined, but human-readable reason for call termination
    var callEndReason: String
    /// The median round-trip time, measured in milliseconds, for STUN/ICE packets
    /// (i.e. connection maintenance and establishment)
    var connectionRttMedian: Float?
    /// The median round-trip time, measured in milliseconds, for RTP/RTCP packets
    /// for audio streams
    var audioRttMedian: Float?
    /// The median round-trip time, measured in milliseconds, for RTP/RTCP packets
    /// for video streams
    var videoRttMedian: Float?
    /// The median jitter for audio streams, measured in milliseconds, for the
    /// duration of the call as measured by the client submitting the survey
    var audioRecvJitterMedian: Float?
    /// The median jitter for video streams, measured in milliseconds, for the
    /// duration of the call as measured by the client submitting the survey
    var videoRecvJitterMedian: Float?
    /// The median jitter for audio streams, measured in milliseconds, for the
    /// duration of the call as measured by the remote endpoint in the call (either
    /// the peer of the client submitting the survey in a direct call or the SFU in
    /// a group call)
    var audioSendJitterMedian: Float?
    /// The median jitter for video streams, measured in milliseconds, for the
    /// duration of the call as measured by the remote endpoint in the call (either
    /// the peer of the client submitting the survey in a direct call or the SFU in
    /// a group call)
    var videoSendJitterMedian: Float?
    /// The fraction of audio packets lost over the duration of the call as
    /// measured by the client submitting the survey
    var audioRecvPacketLossFraction: Float?
    /// The fraction of video packets lost over the duration of the call as
    /// measured by the client submitting the survey
    var videoRecvPacketLossFraction: Float?
    /// The fraction of audio packets lost over the duration of the call as
    /// measured by the remote endpoint in the call (either the peer of the client
    /// submitting the survey in a direct call or the SFU in a group call)
    var audioSendPacketLossFraction: Float?
    /// The fraction of video packets lost over the duration of the call as
    /// measured by the remote endpoint in the call (either the peer of the client
    /// submitting the survey in a direct call or the SFU in a group call)
    var videoSendPacketLossFraction: Float?
    /// Machine-generated telemetry from the call, this is a serialized protobuf
    /// entity generated (and, critically, explained to the user!) by the calling
    /// library
    var callTelemetry: Data?
    /// A hash of a call ID (shared between clients and never sent to the calling
    /// server) that can be used to correlate survey responses from multiple
    /// participants in a call.
    var callIdHash: Data?
}

public protocol UnauthCallQualityService: Sendable {
    /// Submit a call quality survey response.
    ///
    /// - Throws:
    ///   - the standard Signal network errors
    func submitCallQualitySurvey(
        survey: CallQualitySurvey,
    ) async throws
}

extension UnauthenticatedChatConnection: UnauthCallQualityService {

    public func submitCallQualitySurvey(survey: CallQualitySurvey) async throws {
        return try await NativeNice.UnauthenticatedChatConnection_submit_call_quality_survey(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            survey: survey,
        )
    }

}

extension UnauthServiceSelector where Self == UnauthServiceSelectorHelper<any UnauthCallQualityService> {
    public static var callQuality: Self { .init() }
}
