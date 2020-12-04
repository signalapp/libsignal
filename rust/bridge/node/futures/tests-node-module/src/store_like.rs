//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use futures::try_join;
use neon::prelude::*;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use signal_neon_futures::*;

struct NameStore {
    js_queue: EventQueue,
    store_object: Arc<Root<JsObject>>,
}

impl NameStore {
    fn new<'a>(cx: &mut FunctionContext<'a>, store: Handle<'a, JsObject>) -> Self {
        Self {
            js_queue: cx.queue(),
            store_object: Arc::new(store.root(cx)),
        }
    }

    async fn get_name(&self) -> Result<String, String> {
        let store_object_shared = self.store_object.clone();
        JsFuture::get_promise(&self.js_queue, move |cx| {
            let store_object = store_object_shared.to_inner(cx);
            let op = store_object
                .get(cx, "getName")?
                .downcast_or_throw::<JsFunction, _>(cx)?;
            let result = op
                .call(cx, store_object, std::iter::empty::<Handle<JsValue>>())?
                .downcast_or_throw(cx)?;
            store_object_shared.finalize(cx);
            Ok(result)
        })
        .then(|cx, result| match result {
            Ok(value) => match value.downcast::<JsString, _>(cx) {
                Ok(s) => Ok(s.value(cx)),
                Err(_) => Err("name must be a string".into()),
            },
            Err(error) => Err(error
                .to_string(cx)
                .expect("can convert to string")
                .value(cx)),
        })
        .await
    }
}

impl Finalize for NameStore {
    fn finalize<'a, C: Context<'a>>(self, cx: &mut C) {
        self.store_object.finalize(cx)
    }
}

async fn double_name_from_store_impl(store: &mut NameStore) -> Result<String, String> {
    Ok(format!(
        "{0} {1}",
        store.get_name().await?,
        store.get_name().await?
    ))
}

// function doubleNameFromStore(store: { getName: () => Promise<string> }): Promise<string>
pub fn double_name_from_store(mut cx: FunctionContext) -> JsResult<JsObject> {
    let js_store = cx.argument(0)?;
    let mut store = NameStore::new(&mut cx, js_store);

    promise(&mut cx, async move {
        let future = AssertUnwindSafe(double_name_from_store_impl(&mut store));
        let result = future.await;
        fulfill_promise(move |cx| {
            store.finalize(cx);
            match result {
                Ok(doubled) => Ok(cx.string(doubled)),
                Err(message) => cx.throw_error(format!("rejected: {}", message)),
            }
        })
    })
}

async fn double_name_from_store_using_join_impl(store: &mut NameStore) -> Result<String, String> {
    let names = try_join!(store.get_name(), store.get_name())?;
    Ok(format!("{0} {1}", names.0, names.1))
}

// function doubleNameFromStoreUsingJoin(store: { getName: () => Promise<string> }): Promise<string>
pub fn double_name_from_store_using_join(mut cx: FunctionContext) -> JsResult<JsObject> {
    let js_store = cx.argument(0)?;
    let mut store = NameStore::new(&mut cx, js_store);

    promise(&mut cx, async move {
        let future = AssertUnwindSafe(double_name_from_store_using_join_impl(&mut store));
        let result = future.await;
        fulfill_promise(move |cx| {
            store.finalize(cx);
            match result {
                Ok(doubled) => Ok(cx.string(doubled)),
                Err(message) => cx.throw_error(format!("rejected: {}", message)),
            }
        })
    })
}
