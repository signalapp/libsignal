//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::io::{InputStream, InputStreamRead};

use super::*;

use async_trait::async_trait;
use futures_util::TryFutureExt;
use signal_neon_futures::*;
use std::cell::Cell;
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult};
use std::sync::Arc;

pub struct NodeInputStream {
    js_channel: Channel,
    stream_object: Arc<Root<JsObject>>,
    eof_reached: Cell<bool>,
}

impl NodeInputStream {
    pub(crate) fn new(cx: &mut FunctionContext, stream: Handle<JsObject>) -> Self {
        Self {
            js_channel: cx.channel(),
            stream_object: Arc::new(stream.root(cx)),
            eof_reached: Default::default(),
        }
    }

    async fn do_read(&self, amount: u32) -> Result<Vec<u8>, String> {
        let stream_object_shared = self.stream_object.clone();
        let read_data = JsFuture::get_promise(&self.js_channel, move |cx| {
            let stream_object = stream_object_shared.to_inner(cx);
            let amount: Handle<JsNumber> = amount.convert_into(cx)?;
            let result = call_method(cx, stream_object, "_read", [amount.upcast()])?;
            let result = result.downcast_or_throw(cx)?;
            stream_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<JsBuffer, _>(cx) {
                Ok(b) => Ok(b.as_slice(cx).to_vec()),
                Err(_) => Err("unexpected result from _read".into()),
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await?;
        if read_data.is_empty() {
            self.eof_reached.set(true);
        }
        Ok(read_data)
    }

    async fn do_skip(&self, amount: u64) -> Result<(), String> {
        let amount = amount as f64;
        if amount > MAX_SAFE_JS_INTEGER {
            return Err("skipped more than fits in JsInteger".into());
        }

        let stream_object_shared = self.stream_object.clone();
        JsFuture::get_promise(&self.js_channel, move |cx| {
            let stream_object = stream_object_shared.to_inner(cx);
            let amount = cx.number(amount);
            let result = call_method(cx, stream_object, "_skip", [amount.upcast()])?;
            let result = result.downcast_or_throw(cx)?;
            stream_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<JsUndefined, _>(cx) {
                Ok(_) => Ok(()),
                Err(_) => Err("unexpected result from _skip".into()),
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }
}

impl Finalize for NodeInputStream {
    fn finalize<'a, C: neon::prelude::Context<'a>>(self, cx: &mut C) {
        self.stream_object.finalize(cx)
    }
}

#[async_trait(?Send)]
impl InputStream for NodeInputStream {
    fn read<'out, 'a: 'out>(&'a self, buf: &mut [u8]) -> IoResult<InputStreamRead<'out>> {
        let amount = buf.len() as u32;
        if self.eof_reached.get() {
            // If we read again after eof was reached, we can end up hitting an unreachable!() in
            // futures::io::FillBuf due to issue rust-lang/futures#2727.
            Ok(InputStreamRead::Ready { amount_read: 0 })
        } else {
            Ok(InputStreamRead::Pending(Box::pin(
                self.do_read(amount)
                    .map_err(|err| IoError::new(IoErrorKind::Other, err)),
            )))
        }
    }

    async fn skip(&self, amount: u64) -> IoResult<()> {
        self.do_skip(amount)
            .await
            .map_err(|err| IoError::new(IoErrorKind::Other, err))
    }
}
