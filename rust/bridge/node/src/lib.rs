//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![warn(clippy::unwrap_used)]

use futures::executor;
use libsignal_bridge::node::{AssumedImmutableBuffer, ResultTypeInfo, SignalNodeError};
use libsignal_protocol::{IdentityKeyPair, SealedSenderV2SentMessage};
use minidump::Minidump;
use minidump_processor::ProcessorOptions;
use minidump_unwind::symbols::string_symbol_supplier;
use minidump_unwind::Symbolizer;
use neon::prelude::*;
use neon::types::buffer::TypedArray;

mod logging;

// Import bridged functions. Without this, the compiler and/or linker are too
// smart and don't include the symbols in the library.
#[allow(unused)]
use libsignal_bridge_testing::*;

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    libsignal_bridge::node::register(&mut cx)?;
    cx.export_function("initLogger", logging::init_logger)?;
    cx.export_function("IdentityKeyPair_Deserialize", identitykeypair_deserialize)?;
    cx.export_function(
        "SealedSenderMultiRecipientMessage_Parse",
        sealed_sender_multi_recipient_message_parse,
    )?;
    cx.export_function("MinidumpToJSONString", minidump_to_json_string)?;
    Ok(())
}

/// ts: export function IdentityKeyPair_Deserialize(buffer: Buffer): { publicKey: PublicKey, privateKey: PrivateKey }
fn identitykeypair_deserialize(mut cx: FunctionContext) -> JsResult<JsObject> {
    let buffer = cx.argument::<JsBuffer>(0)?;
    let identity_keypair_or_error = IdentityKeyPair::try_from(buffer.as_slice(&cx));
    let identity_keypair = identity_keypair_or_error.or_else(|e| {
        let module = cx.this()?;
        let throwable = e.into_throwable(&mut cx, module, "identitykeypair_deserialize");
        cx.throw(throwable)
    })?;
    let public_key = identity_keypair.public_key().convert_into(&mut cx)?;
    let private_key = identity_keypair.private_key().convert_into(&mut cx)?;
    let result = cx.empty_object();
    result.set(&mut cx, "publicKey", public_key)?;
    result.set(&mut cx, "privateKey", private_key)?;
    Ok(result)
}

struct ArrayBuilder<'a> {
    array: Handle<'a, JsArray>,
    len: u32,
}

impl<'a> ArrayBuilder<'a> {
    fn new(cx: &mut impl Context<'a>) -> Self {
        Self {
            array: cx.empty_array(),
            len: 0,
        }
    }

    fn push(&mut self, value: Handle<'a, impl Value>, cx: &mut impl Context<'a>) -> NeonResult<()> {
        self.array.set(cx, self.len, value)?;
        self.len += 1;
        Ok(())
    }
}

impl<'a> From<ArrayBuilder<'a>> for Handle<'a, JsArray> {
    fn from(value: ArrayBuilder<'a>) -> Self {
        value.array
    }
}

/// ts: export function SealedSenderMultiRecipientMessage_Parse(buffer: Buffer): SealedSenderMultiRecipientMessage
fn sealed_sender_multi_recipient_message_parse(mut cx: FunctionContext) -> JsResult<JsObject> {
    let buffer_arg = cx.argument::<JsBuffer>(0)?;
    let buffer = AssumedImmutableBuffer::new(&cx, buffer_arg);
    let messages = match SealedSenderV2SentMessage::parse(&buffer) {
        Ok(messages) => messages,
        Err(e) => {
            let module = cx.this()?;
            let throwable = e.into_throwable(
                &mut cx,
                module,
                "sealed_sender_multi_recipient_parse_sent_message",
            );
            cx.throw(throwable)?
        }
    };

    let recipient_map = cx.empty_object();
    let mut excluded_recipients_array = ArrayBuilder::new(&mut cx);

    for (service_id, recipient) in &messages.recipients {
        let service_id_string = cx.string(service_id.service_id_string());
        if recipient.devices.is_empty() {
            excluded_recipients_array
                .push(service_id_string, &mut cx)
                .expect("failed to construct output array");
            continue;
        }

        let mut device_ids = ArrayBuilder::new(&mut cx);
        let mut registration_ids = ArrayBuilder::new(&mut cx);

        for &(device_id, registration_id) in &recipient.devices {
            device_ids
                .push(cx.number(u32::from(device_id)), &mut cx)
                .expect("failed to construct output array");
            registration_ids
                .push(cx.number(registration_id), &mut cx)
                .expect("failed to construct output array");
        }

        let range = messages.range_for_recipient_key_material(recipient);
        let range_start = cx.number(u32::try_from(range.start).expect("message too large"));
        let range_len = cx.number(u32::try_from(range.len()).expect("message too large"));

        let recipient_object = cx.empty_object();
        recipient_object
            .set(&mut cx, "deviceIds", device_ids.into())
            .expect("failed to construct recipient object");
        recipient_object
            .set(&mut cx, "registrationIds", registration_ids.into())
            .expect("failed to construct recipient object");
        recipient_object
            .set(&mut cx, "rangeOffset", range_start)
            .expect("failed to construct recipient object");
        recipient_object
            .set(&mut cx, "rangeLen", range_len)
            .expect("failed to construct recipient object");

        recipient_map
            .set(&mut cx, service_id_string, recipient_object)
            .expect("failed to record recipient object");
    }

    let offset_of_shared_bytes =
        cx.number(u32::try_from(messages.offset_of_shared_bytes()).expect("message too large"));

    let result = cx.empty_object();
    result
        .set(&mut cx, "recipientMap", recipient_map)
        .expect("failed to construct result object");
    result
        .set(
            &mut cx,
            "excludedRecipients",
            excluded_recipients_array.into(),
        )
        .expect("failed to construct result object");
    result
        .set(&mut cx, "offsetOfSharedData", offset_of_shared_bytes)
        .expect("failed to construct result object");

    Ok(result)
}

/// ts: export function MinidumpToJSONString(buffer: Buffer): string
fn minidump_to_json_string(mut cx: FunctionContext) -> JsResult<JsString> {
    let buffer_arg = cx.argument::<JsBuffer>(0)?;
    let dump = Minidump::read(buffer_arg.as_slice(&cx)).expect("Failed to parse minidump");
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

    Ok(cx.string(std::str::from_utf8(&json).expect("Failed to convert JSON to utf8")))
}
