//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import { RequestOptions, UnauthenticatedChatConnection } from '../Chat.js';
import * as NativeNice from '../../NativeNice.js';
import { StandardNetworkError } from '../../Errors.js';

declare module '../Chat' {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type
  interface UnauthenticatedChatConnection extends UnauthCallQualityService {}
}

export type CallQualitySurvey = {
  /*
   * Indicates whether the caller was generally satisfied with the quality of
   * the call
   */
  userSatisfied: boolean;
  /*
   * A list of call quality issues selected by the caller
   */
  callQualityIssues: Array<string>;
  /*
   * A free-form description of any additional issues as written by the caller
   */
  additionalIssuesDescription: string | null;
  /*
   * A URL for a set of debug logs associated with the call if the caller chose
   * to submit debug logs
   */
  debugLogUrl: string | null;
  /*
   * The time at which the call started in milliseconds since the epoch
   */
  startTimestamp: number;
  /*
   * The time at which the call ended in milliseconds since the epoch
   */
  endTimestamp: number;
  /*
   * The type of call, note that direct voice calls can become video calls and
   * vice versa, and this field indicates which mode was selected at call
   * initiation time. At the time of writing, expected call types are
   * "direct_voice", "direct_video", "group", and "call_link".
   */
  callType: string;
  /*
   * Indicates whether the call completed without error or if it terminated
   * abnormally
   */
  success: boolean;
  /*
   * A client-defined, but human-readable reason for call termination
   */
  callEndReason: string;
  /*
   * The median round-trip time, measured in milliseconds, for STUN/ICE packets
   * (i.e. connection maintenance and establishment)
   */
  connectionRttMedian: number | null;
  /*
   * The median round-trip time, measured in milliseconds, for RTP/RTCP packets
   * for audio streams
   */
  audioRttMedian: number | null;
  /*
   * The median round-trip time, measured in milliseconds, for RTP/RTCP packets
   * for video streams
   */
  videoRttMedian: number | null;
  /*
   * The median jitter for audio streams, measured in milliseconds, for the
   * duration of the call as measured by the client submitting the survey
   */
  audioRecvJitterMedian: number | null;
  /*
   * The median jitter for video streams, measured in milliseconds, for the
   * duration of the call as measured by the client submitting the survey
   */
  videoRecvJitterMedian: number | null;
  /*
   * The median jitter for audio streams, measured in milliseconds, for the
   * duration of the call as measured by the remote endpoint in the call (either
   * the peer of the client submitting the survey in a direct call or the SFU in
   * a group call)
   */
  audioSendJitterMedian: number | null;
  /*
   * The median jitter for video streams, measured in milliseconds, for the
   * duration of the call as measured by the remote endpoint in the call (either
   * the peer of the client submitting the survey in a direct call or the SFU in
   * a group call)
   */
  videoSendJitterMedian: number | null;
  /*
   * The fraction of audio packets lost over the duration of the call as
   * measured by the client submitting the survey
   */
  audioRecvPacketLossFraction: number | null;
  /*
   * The fraction of video packets lost over the duration of the call as
   * measured by the client submitting the survey
   */
  videoRecvPacketLossFraction: number | null;
  /*
   * The fraction of audio packets lost over the duration of the call as
   * measured by the remote endpoint in the call (either the peer of the client
   * submitting the survey in a direct call or the SFU in a group call)
   */
  audioSendPacketLossFraction: number | null;
  /*
   * The fraction of video packets lost over the duration of the call as
   * measured by the remote endpoint in the call (either the peer of the client
   * submitting the survey in a direct call or the SFU in a group call)
   */
  videoSendPacketLossFraction: number | null;
  /*
   * Machine-generated telemetry from the call, this is a serialized protobuf
   * entity generated (and, critically, explained to the user!) by the calling
   * library
   */
  callTelemetry: Uint8Array<ArrayBuffer> | null;
  /*
   * Machine-generated telemetry from the call, this is a serialized protobuf
   * entity generated (and, critically, explained to the user!) by the calling
   * library
   */
  callIdHash: Uint8Array<ArrayBuffer> | null;
};

export interface UnauthCallQualityService {
  /**
   * Submit a call quality survey response.
   *
   * @throws {StandardNetworkError}
   */
  submitCallQualitySurvey: (
    request: {
      survey: CallQualitySurvey;
    },
    options?: RequestOptions
  ) => Promise<void>;
}
UnauthenticatedChatConnection.prototype.submitCallQualitySurvey =
  async function (
    {
      survey,
    }: {
      survey: CallQualitySurvey;
    },
    options?: RequestOptions
  ): Promise<void> {
    return await NativeNice.UnauthenticatedChatConnection_submit_call_quality_survey(
      {
        asyncContext: this._asyncContext,
        abortSignal: options?.abortSignal,
        chat: this._chatService,
        survey,
      }
    );
  };
