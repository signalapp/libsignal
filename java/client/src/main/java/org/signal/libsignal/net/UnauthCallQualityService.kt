//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.net

import org.signal.libsignal.internal.CompletableFuture
import org.signal.libsignal.internal.NativeNice
import org.signal.libsignal.internal.mapWithCancellation

public data class CallQualitySurvey(
  /**
   * Indicates whether the caller was generally satisfied with the quality of
   * the call
   */
  val userSatisfied: Boolean,
  /**
   * A list of call quality issues selected by the caller
   */
  val callQualityIssues: List<String>,
  /**
   * A free-form description of any additional issues as written by the caller
   */
  val additionalIssuesDescription: String?,
  /**
   * A URL for a set of debug logs associated with the call if the caller chose
   * to submit debug logs
   */
  val debugLogUrl: String?,
  /**
   * The time at which the call started
   */
  val startTimestamp: java.time.Instant,
  /**
   * The time at which the call ended
   */
  val endTimestamp: java.time.Instant,
  /**
   * The type of call, note that direct voice calls can become video calls and
   * vice versa, and this field indicates which mode was selected at call
   * initiation time. At the time of writing, expected call types are
   * "direct_voice", "direct_video", "group", and "call_link".
   */
  val callType: String,
  /**
   * Indicates whether the call completed without error or if it terminated
   * abnormally
   */
  val success: Boolean,
  /**
   * A client-defined, but human-readable reason for call termination
   */
  val callEndReason: String,
  /**
   * The median round-trip time, measured in milliseconds, for STUN/ICE packets
   * (i.e. connection maintenance and establishment)
   */
  val connectionRttMedian: Float?,
  /**
   * The median round-trip time, measured in milliseconds, for RTP/RTCP packets
   * for audio streams
   */
  val audioRttMedian: Float?,
  /**
   * The median round-trip time, measured in milliseconds, for RTP/RTCP packets
   * for video streams
   */
  val videoRttMedian: Float?,
  /**
   * The median jitter for audio streams, measured in milliseconds, for the
   * duration of the call as measured by the client submitting the survey
   */
  val audioRecvJitterMedian: Float?,
  /**
   * The median jitter for video streams, measured in milliseconds, for the
   * duration of the call as measured by the client submitting the survey
   */
  val videoRecvJitterMedian: Float?,
  /**
   * The median jitter for audio streams, measured in milliseconds, for the
   * duration of the call as measured by the remote endpoint in the call (either
   * the peer of the client submitting the survey in a direct call or the SFU in
   * a group call)
   */
  val audioSendJitterMedian: Float?,
  /**
   * The median jitter for video streams, measured in milliseconds, for the
   * duration of the call as measured by the remote endpoint in the call (either
   * the peer of the client submitting the survey in a direct call or the SFU in
   * a group call)
   */
  val videoSendJitterMedian: Float?,
  /**
   * The fraction of audio packets lost over the duration of the call as
   * measured by the client submitting the survey
   */
  val audioRecvPacketLossFraction: Float?,
  /**
   * The fraction of video packets lost over the duration of the call as
   * measured by the client submitting the survey
   */
  val videoRecvPacketLossFraction: Float?,
  /**
   * The fraction of audio packets lost over the duration of the call as
   * measured by the remote endpoint in the call (either the peer of the client
   * submitting the survey in a direct call or the SFU in a group call)
   */
  val audioSendPacketLossFraction: Float?,
  /**
   * The fraction of video packets lost over the duration of the call as
   * measured by the remote endpoint in the call (either the peer of the client
   * submitting the survey in a direct call or the SFU in a group call)
   */
  val videoSendPacketLossFraction: Float?,
  /**
   * Machine-generated telemetry from the call, this is a serialized protobuf
   * entity generated (and, critically, explained to the user!) by the calling
   * library
   */
  val callTelemetry: ByteArray?,
  /**
   * Machine-generated telemetry from the call, this is a serialized protobuf
   * entity generated (and, critically, explained to the user!) by the calling
   * library
   */
  val callIdHash: ByteArray?,
)

public class UnauthCallQualityService(
  private val connection: UnauthenticatedChatConnection,
) {
  /**
   * Submit a call quality survey response.
   *
   * All exceptions are mapped into [RequestResult]; unexpected ones will be treated as
   * [RequestResult.ApplicationError].
   */
  public fun submitCallQualitySurvey(survey: CallQualitySurvey): CompletableFuture<RequestResult<Unit, Nothing>> =
    try {
      NativeNice
        .UnauthenticatedChatConnection_submit_call_quality_survey(
          asyncCtx = connection.tokioAsyncContext,
          chat = connection,
          survey = survey,
        ).mapWithCancellation(
          onSuccess = { RequestResult.Success(Unit) },
          onError = { err -> err.toRequestResult() },
        )
    } catch (e: Throwable) {
      CompletableFuture.completedFuture(RequestResult.ApplicationError(e))
    }
}
