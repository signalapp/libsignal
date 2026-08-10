//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Infallible;

use libsignal_net_grpc::proto::chat::call_quality::call_quality_client::CallQualityClient;
use libsignal_net_grpc::proto::chat::call_quality::{
    SubmitCallQualitySurveyRequest, SubmitCallQualitySurveyResponse,
};
use libsignal_protocol::Timestamp;

use crate::api::{RequestError, Unauth};
use crate::grpc::{GrpcServiceProvider, log_and_send};

#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct CallQualitySurvey {
    /// Indicates whether the caller was generally satisfied with the quality of
    /// the call
    pub user_satisfied: bool,

    /// A list of call quality issues selected by the caller
    pub call_quality_issues: Vec<String>,

    /// A free-form description of any additional issues as written by the caller
    pub additional_issues_description: Option<String>,

    /// A URL for a set of debug logs associated with the call if the caller chose
    /// to submit debug logs
    pub debug_log_url: Option<String>,

    /// The time at which the call started in milliseconds since the epoch
    pub start_timestamp: Timestamp,

    /// The time at which the call ended in milliseconds since the epoch
    pub end_timestamp: Timestamp,

    /// The type of call, note that direct voice calls can become video calls and
    /// vice versa, and this field indicates which mode was selected at call
    /// initiation time. At the time of writing, expected call types are
    /// "direct_voice", "direct_video", "group", and "call_link".
    pub call_type: String,

    /// Indicates whether the call completed without error or if it terminated
    /// abnormally
    pub success: bool,

    /// A client-defined, but human-readable reason for call termination
    pub call_end_reason: String,

    /// The median round-trip time, measured in milliseconds, for STUN/ICE packets
    /// (i.e. connection maintenance and establishment)
    pub connection_rtt_median: Option<f32>,

    /// The median round-trip time, measured in milliseconds, for RTP/RTCP packets
    /// for audio streams
    pub audio_rtt_median: Option<f32>,

    /// The median round-trip time, measured in milliseconds, for RTP/RTCP packets
    /// for video streams
    pub video_rtt_median: Option<f32>,

    /// The median jitter for audio streams, measured in milliseconds, for the
    /// duration of the call as measured by the client submitting the survey
    pub audio_recv_jitter_median: Option<f32>,

    /// The median jitter for video streams, measured in milliseconds, for the
    /// duration of the call as measured by the client submitting the survey
    pub video_recv_jitter_median: Option<f32>,

    /// The median jitter for audio streams, measured in milliseconds, for the
    /// duration of the call as measured by the remote endpoint in the call (either
    /// the peer of the client submitting the survey in a direct call or the SFU in
    /// a group call)
    pub audio_send_jitter_median: Option<f32>,

    /// The median jitter for video streams, measured in milliseconds, for the
    /// duration of the call as measured by the remote endpoint in the call (either
    /// the peer of the client submitting the survey in a direct call or the SFU in
    /// a group call)
    pub video_send_jitter_median: Option<f32>,

    /// The fraction of audio packets lost over the duration of the call as
    /// measured by the client submitting the survey
    pub audio_recv_packet_loss_fraction: Option<f32>,

    /// The fraction of video packets lost over the duration of the call as
    /// measured by the client submitting the survey
    pub video_recv_packet_loss_fraction: Option<f32>,

    /// The fraction of audio packets lost over the duration of the call as
    /// measured by the remote endpoint in the call (either the peer of the client
    /// submitting the survey in a direct call or the SFU in a group call)
    pub audio_send_packet_loss_fraction: Option<f32>,

    /// The fraction of video packets lost over the duration of the call as
    /// measured by the remote endpoint in the call (either the peer of the client
    /// submitting the survey in a direct call or the SFU in a group call)
    pub video_send_packet_loss_fraction: Option<f32>,

    /// Machine-generated telemetry from the call, this is a serialized protobuf
    /// entity generated (and, critically, explained to the user!) by the calling
    /// library
    pub call_telemetry: Option<Vec<u8>>,

    /// A hash of a call ID (shared between clients and never sent to the calling
    /// server) that can be used to correlate survey responses from multiple
    /// participants in a call.
    pub call_id_hash: Option<Vec<u8>>,
}

impl<T: GrpcServiceProvider> Unauth<T> {
    /// Submit a call quality survey response.
    pub async fn submit_call_quality_survey(
        &self,
        survey: CallQualitySurvey,
    ) -> Result<(), RequestError<Infallible>> {
        let mut client = CallQualityClient::new(self.0.service());
        let CallQualitySurvey {
            user_satisfied,
            call_quality_issues,
            additional_issues_description,
            debug_log_url,
            start_timestamp,
            end_timestamp,
            call_type,
            success,
            call_end_reason,
            connection_rtt_median,
            audio_rtt_median,
            video_rtt_median,
            audio_recv_jitter_median,
            video_recv_jitter_median,
            audio_send_jitter_median,
            video_send_jitter_median,
            audio_recv_packet_loss_fraction,
            video_recv_packet_loss_fraction,
            audio_send_packet_loss_fraction,
            video_send_packet_loss_fraction,
            call_telemetry,
            call_id_hash,
        } = survey;
        let SubmitCallQualitySurveyResponse {} =
            log_and_send("unauth", "SubmitCallQualitySurvey", || {
                client.submit_call_quality_survey(SubmitCallQualitySurveyRequest {
                    user_satisfied,
                    call_quality_issues,
                    additional_issues_description,
                    debug_log_url,
                    start_timestamp: start_timestamp
                        .epoch_millis()
                        .try_into()
                        .expect("Fits in i64"),
                    end_timestamp: end_timestamp
                        .epoch_millis()
                        .try_into()
                        .expect("Fits in i64"),
                    call_type,
                    success,
                    call_end_reason,
                    connection_rtt_median,
                    audio_rtt_median,
                    video_rtt_median,
                    audio_recv_jitter_median,
                    video_recv_jitter_median,
                    audio_send_jitter_median,
                    video_send_jitter_median,
                    audio_recv_packet_loss_fraction,
                    video_recv_packet_loss_fraction,
                    audio_send_packet_loss_fraction,
                    video_send_packet_loss_fraction,
                    call_telemetry,
                    call_id_hash,
                })
            })
            .await?
            .into_inner();
        Ok(())
    }
}

// Not cfg(test) so it can be accessed via bridging tests.
// These tests will get pruned via LTO tree shaking.
pub mod test_cases {
    use super::*;
    use crate::grpc::GrpcTestCase;

    pub type SubmitCallQualitySurveyArgs = CallQualitySurvey;
    pub type SubmitCallQualitySurveyOut = ();

    pub fn submit_call_quality_survey_test_cases() -> Vec<
        GrpcTestCase<
            SubmitCallQualitySurveyArgs,
            SubmitCallQualitySurveyRequest,
            SubmitCallQualitySurveyResponse,
            SubmitCallQualitySurveyOut,
        >,
    > {
        let method = "/org.signal.chat.calling.quality.CallQuality/SubmitCallQualitySurvey";
        vec![
            GrpcTestCase {
                name: "success non-empty".to_string(),
                method: method.to_string(),
                request: CallQualitySurvey {
                    user_satisfied: true,
                    call_quality_issues: vec![
                        "dishonest".into(),
                        "untrustworthy".into(),
                        "duplicitous".into(),
                    ],
                    additional_issues_description: Some(
                        "Salamander vocalizations inaudible.".to_owned(),
                    ),
                    debug_log_url: Some("https://www.example.com/".to_owned()),
                    start_timestamp: Timestamp::from_epoch_millis(1785435216229),
                    end_timestamp: Timestamp::from_epoch_millis(1785435216300),
                    call_type: "enigmatic".into(),
                    success: true,
                    call_end_reason: "Eaten by salamanders".into(),
                    connection_rtt_median: Some(1.0),
                    audio_rtt_median: Some(2.0),
                    video_rtt_median: Some(3.0),
                    audio_recv_jitter_median: Some(4.0),
                    video_recv_jitter_median: Some(5.0),
                    audio_send_jitter_median: Some(6.0),
                    video_send_jitter_median: Some(7.0),
                    audio_recv_packet_loss_fraction: Some(8.0),
                    video_recv_packet_loss_fraction: Some(9.0),
                    audio_send_packet_loss_fraction: Some(10.0),
                    video_send_packet_loss_fraction: Some(3.640625),
                    call_telemetry: Some(b"01010101".to_vec()),
                    call_id_hash: Some(b"0xhexadecimal".to_vec()),
                },
                request_grpc: SubmitCallQualitySurveyRequest {
                    user_satisfied: true,
                    call_quality_issues: vec![
                        "dishonest".into(),
                        "untrustworthy".into(),
                        "duplicitous".into(),
                    ],
                    additional_issues_description: Some(
                        "Salamander vocalizations inaudible.".into(),
                    ),
                    debug_log_url: Some("https://www.example.com/".into()),
                    start_timestamp: 1785435216229,
                    end_timestamp: 1785435216300,
                    call_type: "enigmatic".into(),
                    success: true,
                    call_end_reason: "Eaten by salamanders".into(),
                    connection_rtt_median: Some(1.0),
                    audio_rtt_median: Some(2.0),
                    video_rtt_median: Some(3.0),
                    audio_recv_jitter_median: Some(4.0),
                    video_recv_jitter_median: Some(5.0),
                    audio_send_jitter_median: Some(6.0),
                    video_send_jitter_median: Some(7.0),
                    audio_recv_packet_loss_fraction: Some(8.0),
                    video_recv_packet_loss_fraction: Some(9.0),
                    audio_send_packet_loss_fraction: Some(10.0),
                    video_send_packet_loss_fraction: Some(3.640625),
                    call_telemetry: Some(b"01010101".into()),
                    call_id_hash: Some(b"0xhexadecimal".into()),
                },
                response_grpc: SubmitCallQualitySurveyResponse {},
                response: (),
            },
            GrpcTestCase {
                name: "success empty".to_string(),
                method: method.to_string(),
                request: CallQualitySurvey {
                    user_satisfied: false,
                    call_quality_issues: vec![],
                    additional_issues_description: None,
                    debug_log_url: None,
                    start_timestamp: Timestamp::from_epoch_millis(1785435216229),
                    end_timestamp: Timestamp::from_epoch_millis(1785435216300),
                    call_type: "".into(),
                    success: false,
                    call_end_reason: "".into(),
                    connection_rtt_median: None,
                    audio_rtt_median: None,
                    video_rtt_median: None,
                    audio_recv_jitter_median: None,
                    video_recv_jitter_median: None,
                    audio_send_jitter_median: None,
                    video_send_jitter_median: None,
                    audio_recv_packet_loss_fraction: None,
                    video_recv_packet_loss_fraction: None,
                    audio_send_packet_loss_fraction: None,
                    video_send_packet_loss_fraction: None,
                    call_telemetry: None,
                    call_id_hash: None,
                },
                request_grpc: SubmitCallQualitySurveyRequest {
                    user_satisfied: false,
                    call_quality_issues: vec![],
                    additional_issues_description: None,
                    debug_log_url: None,
                    start_timestamp: 1785435216229,
                    end_timestamp: 1785435216300,
                    call_type: "".into(),
                    success: false,
                    call_end_reason: "".into(),
                    connection_rtt_median: None,
                    audio_rtt_median: None,
                    video_rtt_median: None,
                    audio_recv_jitter_median: None,
                    video_recv_jitter_median: None,
                    audio_send_jitter_median: None,
                    video_send_jitter_median: None,
                    audio_recv_packet_loss_fraction: None,
                    video_recv_packet_loss_fraction: None,
                    audio_send_packet_loss_fraction: None,
                    video_send_packet_loss_fraction: None,
                    call_telemetry: None,
                    call_id_hash: None,
                },
                response_grpc: SubmitCallQualitySurveyResponse {},
                response: (),
            },
        ]
    }
}

#[test]
fn test_submit_call_quality_survey() {
    use test_cases::*;
    crate::grpc::testutil::run_tests(
        submit_call_quality_survey_test_cases(),
        |chat: Unauth<_>, survey| async move { chat.submit_call_quality_survey(survey).await },
        |(), result| result.unwrap(),
    );
}
