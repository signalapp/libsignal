//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![warn(clippy::unwrap_used)]

use futures::executor;
use libsignal_bridge::node::ResultTypeInfo;
use libsignal_bridge::node_register;
use libsignal_bridge::support::*;
use libsignal_bridge_macros::bridge_fn;
use libsignal_protocol::SealedSenderV2SentMessage;
use minidump::Minidump;
use minidump_processor::ProcessorOptions;
use minidump_unwind::Symbolizer;
use minidump_unwind::symbols::string_symbol_supplier;
use neon::prelude::*;
use rand::TryRngCore;
use uuid::Uuid;

mod logging;

// Import bridged functions. Without this, the compiler and/or linker are too
// smart and don't include the symbols in the library.
#[allow(unused)]
use libsignal_bridge_testing::*;

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    libsignal_bridge::node::register(&mut cx)?;
    cx.export_function("initLogger", logging::init_logger)?;
    let remote_config_keys = libsignal_bridge::net::RemoteConfigKey::KEYS.convert_into(&mut cx)?;
    cx.export_value("NetRemoteConfigKeys", remote_config_keys)?;
    Ok(())
}

struct ArrayBuilder<'a> {
    array: Handle<'a, JsArray>,
    len: u32,
}

impl<'a> ArrayBuilder<'a> {
    fn new(cx: &mut Cx<'a>) -> Self {
        Self {
            array: cx.empty_array(),
            len: 0,
        }
    }

    fn push(&mut self, value: Handle<'a, impl Value>, cx: &mut Cx<'a>) -> NeonResult<()> {
        self.array.prop(cx, self.len).set(value)?;
        self.len += 1;
        Ok(())
    }
}

impl<'a> From<ArrayBuilder<'a>> for Handle<'a, JsArray> {
    fn from(value: ArrayBuilder<'a>) -> Self {
        value.array
    }
}

struct SealedSenderMultiRecipientMessage<'a>(SealedSenderV2SentMessage<'a>);
impl<'a, 'b> ResultTypeInfo<'a> for SealedSenderMultiRecipientMessage<'b> {
    type ResultType = JsObject;

    fn convert_into(self, cx: &mut Cx<'a>) -> JsResult<'a, Self::ResultType> {
        let messages = self.0;
        let recipient_map = cx.empty_object();
        let mut excluded_recipients_array = ArrayBuilder::new(cx);

        for (service_id, recipient) in &messages.recipients {
            let service_id_string = cx.string(service_id.service_id_string());
            if recipient.devices.is_empty() {
                excluded_recipients_array
                    .push(service_id_string, cx)
                    .expect("failed to construct output array");
                continue;
            }

            let mut device_ids = ArrayBuilder::new(cx);
            let mut registration_ids = ArrayBuilder::new(cx);

            for &(device_id, registration_id) in &recipient.devices {
                device_ids
                    .push(cx.number(u32::from(device_id)), cx)
                    .expect("failed to construct output array");
                registration_ids
                    .push(cx.number(registration_id), cx)
                    .expect("failed to construct output array");
            }

            let range = messages.range_for_recipient_key_material(recipient);
            let range_start = cx.number(u32::try_from(range.start).expect("message too large"));
            let range_len = cx.number(u32::try_from(range.len()).expect("message too large"));

            let recipient_object = cx.empty_object();
            let device_ids: Handle<JsArray> = device_ids.into();
            let registration_ids: Handle<JsArray> = registration_ids.into();
            recipient_object
                .prop(cx, "deviceIds")
                .set(device_ids)
                .expect("failed to construct recipient object");
            recipient_object
                .prop(cx, "registrationIds")
                .set(registration_ids)
                .expect("failed to construct recipient object");
            recipient_object
                .prop(cx, "rangeOffset")
                .set(range_start)
                .expect("failed to construct recipient object");
            recipient_object
                .prop(cx, "rangeLen")
                .set(range_len)
                .expect("failed to construct recipient object");

            recipient_map
                .prop(cx, service_id_string)
                .set(recipient_object)
                .expect("failed to record recipient object");
        }

        let offset_of_shared_bytes =
            cx.number(u32::try_from(messages.offset_of_shared_bytes()).expect("message too large"));

        let result = cx.empty_object();
        result
            .prop(cx, "recipientMap")
            .set(recipient_map)
            .expect("failed to construct result object");
        let excluded_recipients_array: Handle<JsArray> = excluded_recipients_array.into();
        result
            .prop(cx, "excludedRecipients")
            .set(excluded_recipients_array)
            .expect("failed to construct result object");
        result
            .prop(cx, "offsetOfSharedData")
            .set(offset_of_shared_bytes)
            .expect("failed to construct result object");

        Ok(result)
    }

    #[cfg(feature = "metadata")]
    fn register_ts_ffi_type(
        _: &mut libsignal_bridge_types::metadata::node::TsMetadataContext,
    ) -> String {
        "SealedSenderMultiRecipientMessage".into()
    }
}

#[bridge_fn(jni = false, ffi = false)]
fn SealedSenderMultiRecipientMessage_Parse(
    buffer: &[u8],
) -> libsignal_protocol::error::Result<SealedSenderMultiRecipientMessage<'_>> {
    Ok(SealedSenderMultiRecipientMessage(
        SealedSenderV2SentMessage::parse(buffer)?,
    ))
}

#[bridge_fn(ffi = false, jni = false)]
fn MinidumpToJSONString(buffer: &[u8]) -> String {
    let dump = Minidump::read(buffer).expect("Failed to parse minidump");
    let provider = Symbolizer::new(string_symbol_supplier(std::collections::HashMap::new()));
    let options = ProcessorOptions::default();

    let state = executor::block_on(minidump_processor::process_minidump_with_options(
        &dump, &provider, options,
    ))
    .expect("processing to finish");

    let mut json = Vec::new();
    state
        .print_json(&mut json, false)
        .expect("Failed to print json");

    String::from_utf8(json).expect("Failed to convert JSON to utf8")
}

#[bridge_fn(ffi = false, jni = false)]
fn uuid_to_string(uuid: Uuid) -> String {
    uuid.as_hyphenated().to_string()
}

#[bridge_fn(ffi = false, jni = false)]
fn uuid_from_string(string: String) -> Option<Uuid> {
    Uuid::try_parse(&string).ok()
}

#[bridge_fn(ffi = false, jni = false)]
fn uuid_new_v4() -> Uuid {
    let mut bytes = [0; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .expect("system RNG should always be available");
    uuid::Builder::from_random_bytes(bytes).into_uuid()
}
